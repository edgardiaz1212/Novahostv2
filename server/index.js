import express from 'express';
import cors from 'cors';
import pg from 'pg';
import https from 'https'; // Needed for custom agent for direct vSphere calls (fallback)
import dotenv from 'dotenv';
import Proxmox, { proxmoxApi } from 'proxmox-api';
import bcrypt from 'bcrypt';
import { constants as cryptoConstants } from 'crypto';
import jwt from 'jsonwebtoken';
// import fetch from 'node-fetch'; // Asegúrate de tener node-fetch si usas Node < 18 o si fetch no está global
import WebSocket, { WebSocketServer } from 'ws';
import http from 'http'; // o https si tu servidor Express ya usa HTTPS
import net from 'net';
import { URL } from 'url';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;
const { Pool } = pg;
const pool = new Pool({
  connectionString: `postgres://${process.env.VITE_POSTGRES_USER}:${process.env.VITE_POSTGRES_PASSWORD}@${process.env.VITE_POSTGRES_HOST}:${process.env.VITE_POSTGRES_PORT}/${process.env.VITE_POSTGRES_DB}`,
});

app.use(cors());
app.use(express.json());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // Para fallback a vSphere REST API directa

// --- URL del Microservicio Python ---
const PYVMOMI_MICROSERVICE_URL = process.env.PYVMOMI_MICROSERVICE_URL || 'http://localhost:5000';

// --- Helper para llamar al microservicio PyVmomi ---
async function callPyvmomiService(method, path, hypervisor, body = null) {
  // Para vSphere, la contraseña ahora está en el campo 'password' del objeto hypervisor.
  // El objeto 'hypervisor' pasado aquí debe tener 'host', 'username', y 'password' (para vSphere).
  const { host: vsphereHost, username: vsphereUser, password: vspherePassword } = hypervisor;

  if (!vsphereHost || !vsphereUser || (hypervisor.type === 'vsphere' && !vspherePassword)) {
    throw new Error('Missing vSphere connection credentials for PyVmomi microservice call.');
  }

  const options = {
    method,
    headers: {},
  };

  let url = `${PYVMOMI_MICROSERVICE_URL}${path}`;

  if (method === 'GET') {
    const queryParams = new URLSearchParams({
      host: vsphereHost.split(':')[0], // Enviar solo el hostname
      user: vsphereUser,
      password: vspherePassword,
    });
    
    // More robust way to add query parameters: parse the URL first
    const parsedUrl = new URL(url); // Parse the URL constructed from PYVMOMI_MICROSERVICE_URL + path
    const combinedQueryParams = new URLSearchParams(parsedUrl.search); // Start with existing query params from 'path'
    // Add connection parameters, overwriting if they somehow already exist
    combinedQueryParams.set('host', vsphereHost.split(':')[0]);
    combinedQueryParams.set('user', vsphereUser);
    combinedQueryParams.set('password', vspherePassword);
    url = `${parsedUrl.origin}${parsedUrl.pathname}?${combinedQueryParams.toString()}`;
  } else if (body || method === 'POST') { // Asegurar que POST siempre tenga Content-Type
    options.headers['Content-Type'] = 'application/json';
    // Para POST, las credenciales van en el body según app.py
    const requestBody = {
      ...body, // Incluir el cuerpo original de la solicitud
      host: vsphereHost.split(':')[0],
      user: vsphereUser,
      password: vspherePassword,
    };
    options.body = JSON.stringify(requestBody);
  }
  //console.log(`[PyVmomi Call] Method: ${method}, URL: ${url}`);
  if (options.body) console.log(`PyVmomi microservice body: ${options.body.substring(0,200)}...`);


  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      let errorText = '';
      //console.log(`[PyVmomi Call] Received non-OK status: ${response.status} ${response.statusText}`);

      let errorJson = null;
      try {
        // Try to read the error response body as text
        errorText = await response.text();
        if (errorText) {
          // If there's text, try to parse it as JSON
          try {
            errorJson = JSON.parse(errorText);
          } catch (parseError) {
            // Not JSON or malformed JSON. errorText will be used.
            console.warn(`PyVmomi error response (status ${response.status}) was not valid JSON:`, errorText.substring(0, 200));
          }
        }
      } catch (readError) {
        // Failed to read the error response body at all
        console.error(`Failed to read error response body from PyVmomi (status ${response.status}):`, readError);
        errorText = response.statusText; // Fallback to status text
      }

      // Determine the most relevant error message
      const errorMessage = errorJson?.error || errorJson?.message || errorText || response.statusText || 'Unknown error';
      console.error(`PyVmomi microservice error: ${response.status}`, errorMessage);
      const err = new Error(`PyVmomi microservice request failed with status ${response.status}: ${errorMessage}`);
      err.status = response.status;
      err.details = errorJson || { error: errorText || "Failed to retrieve error details" };
      throw err;
    }

    // Handle 204 No Content for successful responses
    if (response.status === 204) {
        return null; // No body to parse
    }

    // For other successful responses (2xx), read body as text then parse as JSON
    const successText = await response.text();
    if (!successText && response.status !== 204) { // Handle empty successful response if that's possible and not 204
        console.warn(`PyVmomi successful response (status ${response.status}) had an empty body.`);
        return {}; // Or null, or an empty array, depending on expected successful empty body
    }
    return JSON.parse(successText); // Parse the text as JSON
  } catch (error) {
    console.error('Error calling PyVmomi microservice:', error.message);
    if (!error.status) error.status = 503; // Default to Service Unavailable if no status is set (e.g., network error)
    if (!error.details) error.details = { error: error.message };
    throw error; // Re-throw para que la ruta lo maneje
  }
}


// --- Authentication Middleware ---
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Auth middleware: Invalid token', err.message);
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Unauthorized: Token expired' });
      }
      return res.status(403).json({ error: 'Forbidden: Invalid token' });
    }
    req.user = user;
    next();
  });
};

// --- Role-Based Access Control Middleware ---
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    console.log('RequireAdmin: Access denied for user:', req.user?.userId, 'Role:', req.user?.role);
    return res.status(403).json({ error: 'Forbidden: Admin privileges required' });
  }
  next();
};

// --- Authentication Routes ---
app.post('/api/auth/login', async (req, res) => {
  console.log('--- HIT /api/auth/login ---');
  const { email, password } = req.body;
  console.log(`Login attempt for email: ${email}`);

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const userResult = await pool.query(
      `SELECT u.id, u.username, u.email, u.password_hash, u.is_active, r.name as role_name
       FROM users u
       JOIN roles r ON u.role_id = r.id
       WHERE u.email = $1`,
      [email]
    );

    const user = userResult.rows[0];

    if (!user) {
      console.log(`Login failed: User not found for email ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.is_active) {
      console.log(`Login failed: User ${email} is inactive`);
      return res.status(403).json({ error: 'Account is inactive' });
    }

    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      console.log(`Login failed: Incorrect password for email ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const payload = {
      userId: user.id,
      username: user.username,
      email: user.email,
      role: user.role_name
    };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    console.log(`Login successful for ${email}. Role: ${user.role_name}`);
    res.json({ accessToken, user: { id: user.id, username: user.username, email: user.email, role: user.role_name } });

  } catch (error) {
    console.error('Login process error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// --- User Management Routes (Admin Only) ---
app.post('/api/users', authenticate, requireAdmin, async (req, res) => {
  const { username, email, password, role_name = 'user', is_active = true } = req.body;
  console.log(`--- POST /api/users --- Creating user: ${email}, Role: ${role_name}`);

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  if (!['admin', 'user', 'viewer'].includes(role_name)) {
    return res.status(400).json({ error: 'Invalid role specified. Must be admin, user, or viewer.' });
  }

  try {
    const roleResult = await pool.query('SELECT id FROM roles WHERE name = $1', [role_name]);
    if (roleResult.rows.length === 0) {
      return res.status(400).json({ error: `Role '${role_name}' not found in database.` });
    }
    const roleId = roleResult.rows[0].id;

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const insertResult = await pool.query(
      `INSERT INTO users (username, email, password_hash, role_id, is_active)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, email, role_id, is_active, created_at, updated_at`,
      [username, email, passwordHash, roleId, is_active]
    );

    const newUser = insertResult.rows[0];
    newUser.role_name = role_name;
    delete newUser.role_id;

    console.log('Successfully created user:', newUser);
    res.status(201).json(newUser);

  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Email or username already exists.' });
    }
    res.status(500).json({ error: 'Failed to create user.' });
  }
});

app.put('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, email, role_name, is_active, password } = req.body; // Added password

  console.log(`--- PUT /api/users/${id} --- Updating user. Email: ${email}, Role: ${role_name}, Active: ${is_active}, Password change requested: ${!!password}`);

  if (!username || !email) {
    return res.status(400).json({ error: 'Username and email are required' });
  }
  if (role_name && !['admin', 'user', 'viewer'].includes(role_name)) {
    return res.status(400).json({ error: 'Invalid role specified. Must be admin, user, or viewer.' });
  }
  // Validate password if provided (e.g., minimum length)
  if (password && password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }
  if (typeof is_active !== 'boolean') {
    return res.status(400).json({ error: 'is_active must be a boolean value.' });
  }

  try {
    let roleId = null;
    if (role_name) {
      const roleResult = await pool.query('SELECT id FROM roles WHERE name = $1', [role_name]);
      if (roleResult.rows.length === 0) {
        return res.status(400).json({ error: `Role '${role_name}' not found.` });
      }
      roleId = roleResult.rows[0].id;
    }

    const updates = [];
    const values = [];
    let valueIndex = 1;

    updates.push(`username = $${valueIndex++}`); values.push(username);
    updates.push(`email = $${valueIndex++}`); values.push(email);
    if (roleId) { updates.push(`role_id = $${valueIndex++}`); values.push(roleId); }
    if (password) {
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      updates.push(`password_hash = $${valueIndex++}`); values.push(passwordHash);
    }
    updates.push(`is_active = $${valueIndex++}`); values.push(is_active);
    updates.push(`updated_at = now()`);

    values.push(id);

    const updateQuery = `UPDATE users SET ${updates.join(', ')} WHERE id = $${valueIndex} RETURNING id, username, email, role_id, is_active, created_at, updated_at`;

    const result = await pool.query(updateQuery, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updatedUser = result.rows[0];
    updatedUser.role_name = role_name || (await pool.query('SELECT name FROM roles WHERE id = $1', [updatedUser.role_id])).rows[0]?.name;
    delete updatedUser.role_id;

    console.log('Successfully updated user:', updatedUser);
    res.json(updatedUser);

  } catch (error) {
    console.error(`Error updating user ${id}:`, error);
    if (error.code === '23505') return res.status(409).json({ error: 'Email or username already exists.' });
    res.status(500).json({ error: 'Failed to update user.' });
  }
});

app.get('/api/users', authenticate, requireAdmin, async (req, res) => {
  console.log('--- GET /api/users ---');
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.email, u.is_active, r.name as role_name, u.created_at, u.updated_at
       FROM users u
       JOIN roles r ON u.role_id = r.id
       ORDER BY u.created_at DESC`
    );
    console.log(`Found ${result.rows.length} users`);
    const users = result.rows.map(dbUser => ({
      id: dbUser.id,
      username: dbUser.username,
      email: dbUser.email,
      role: dbUser.role_name,
      is_active: dbUser.is_active,
    }));
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

// DELETE /api/users/:id - Delete a user (Admin Only)
app.delete('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  const { id: userIdToDelete } = req.params;
  const adminUserId = req.user.userId; // From authenticate middleware

  console.log(`--- DELETE /api/users/${userIdToDelete} --- Requested by admin: ${adminUserId}`);

  // Prevent admin from deleting their own account
  // Ensure consistent type for comparison (req.params.id is string, req.user.userId might be number)
  if (userIdToDelete === String(adminUserId)) {
    console.log(`Admin user ${adminUserId} attempted to delete self.`);
    return res.status(403).json({ error: 'Los administradores no pueden eliminar su propia cuenta.' });
  }

  try {
    // Optional: Check if the user exists before attempting to delete.
    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [userIdToDelete]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    // Consider foreign key constraints (e.g., created_by_user_id in virtual_machines)
    // You might need to set related fields to NULL or prevent deletion if dependencies exist.
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [userIdToDelete]);

    if (result.rowCount > 0) {
      console.log(`Successfully deleted user ${userIdToDelete}`);
      res.status(204).send(); // No Content
    } else {
      // This case might be redundant if userCheck is performed, but good as a fallback.
      res.status(404).json({ error: 'Usuario no encontrado o ya eliminado.' });
    }
  } catch (error) {
    console.error(`Error deleting user ${userIdToDelete}:`, error);
    res.status(500).json({ error: 'Error al eliminar el usuario.' });
  }
});


// --- User Profile & Password Management for Logged-in User ---
app.put('/api/auth/profile', authenticate, async (req, res) => {
  const { userId } = req.user; // From authenticate middleware
  const { fullName } = req.body; // Assuming frontend sends 'fullName'

  console.log(`--- PUT /api/auth/profile for user ${userId} --- fullName: ${fullName}`);

  if (!fullName || typeof fullName !== 'string' || fullName.trim() === '') {
    return res.status(400).json({ error: 'Full name is required and must be a non-empty string.' });
  }

  try {
    // Assuming 'username' field stores the display name/full name.
    // If you have a separate 'full_name' column, use that instead.
    const result = await pool.query(
      `UPDATE users SET username = $1, updated_at = now() WHERE id = $2
       RETURNING id, username, email, role_id, is_active`,
      [fullName.trim(), userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const updatedDbUser = result.rows[0];
    const roleResult = await pool.query('SELECT name FROM roles WHERE id = $1', [updatedDbUser.role_id]);
    const roleName = roleResult.rows[0]?.name || 'user';

    const updatedUser = {
      id: updatedDbUser.id,
      username: updatedDbUser.username, // This is the updated 'fullName'
      email: updatedDbUser.email,
      role: roleName,
      name: updatedDbUser.username, // Assuming username is used as name for consistency with User type
    };
    
    console.log(`User ${userId} profile updated successfully. New name: ${updatedUser.username}`);
    res.json({ user: updatedUser, message: 'Perfil actualizado correctamente.' });

  } catch (error) {
    console.error(`Error updating profile for user ${userId}:`, error);
    if (error.code === '23505') { // Unique constraint violation (e.g. if username must be unique)
        return res.status(409).json({ error: 'Este nombre podría ya estar en uso.' });
    }
    res.status(500).json({ error: 'Error al actualizar el perfil.' });
  }
});

app.put('/api/auth/password', authenticate, async (req, res) => {
  const { userId } = req.user;
  const { currentPassword, newPassword } = req.body;

  console.log(`--- PUT /api/auth/password for user ${userId} ---`);

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'La contraseña actual y la nueva contraseña son obligatorias.' });
  }
  if (newPassword.length < 6) { // Example: Basic password policy
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
  }

  try {
    const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });

    const user = userResult.rows[0];
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });

    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2', [newPasswordHash, userId]);

    console.log(`Password updated successfully for user ${userId}.`);
    res.json({ message: 'Contraseña actualizada correctamente.' });

  } catch (error) {
    console.error(`Error changing password for user ${userId}:`, error);
    res.status(500).json({ error: 'Error al cambiar la contraseña.' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// vSphere API routes (Placeholder, to be potentially replaced by PyVmomi calls)
app.get('/api/vsphere/datacenters', authenticate, (req, res) => {
  // TODO: PYVMOMI: Implement with PyVmomi microservice if needed, or remove if not used.
  console.warn("Placeholder endpoint /api/vsphere/datacenters hit. Consider PyVmomi or removal.");
  res.json([
    { id: 'datacenter-1', name: 'Main Datacenter (Placeholder)' }
  ]);
});


// POST /api/vms - Create a new VM
app.post('/api/vms', authenticate, async (req, res) => {
  const params = req.body;
  console.log('--- Received POST /api/vms --- Params:', params);

  if (!params.name || !params.hypervisorId || !params.specs?.cpu || !params.specs?.memory || !params.specs?.disk || !params.templateId) {
    return res.status(400).json({ error: 'Missing required VM parameters (name, hypervisorId, specs, templateId).' });
  }

  try {
    const { rows: [hypervisor] } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, status, name as hypervisor_name, vsphere_subtype
       FROM hypervisors WHERE id = $1`,
      [params.hypervisorId]
    );

    if (!hypervisor) {
      return res.status(404).json({ error: 'Target hypervisor not found' });
    }
    if (hypervisor.status !== 'connected') {
      return res.status(409).json({ error: 'Target hypervisor is not connected' });
    }

    let creationResult = null;
    let newVmId = null; // This will be Proxmox VMID or vSphere UUID/MOID
    let targetNode = null;

    if (hypervisor.type === 'proxmox') {
      // ... (Proxmox VM Creation Logic - Mantenida como estaba)
      const [dbHost, dbPortStr] = hypervisor.host.split(':');
      const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
      const cleanHost = dbHost;
      const isIso = params.templateId.includes(':iso/');

      const proxmoxConfig = {
        host: cleanHost, port: port, username: hypervisor.username,
        tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
        tokenSecret: hypervisor.api_token, timeout: 30000, rejectUnauthorized: false
      };
      const proxmox = proxmoxApi(proxmoxConfig);

      targetNode = params.nodeName;
      if (!targetNode) {
        const nodes = await proxmox.nodes.$get();
        if (!nodes || nodes.length === 0) throw new Error('No nodes found on hypervisor');
        targetNode = nodes[0].node;
        console.log(`No node specified, defaulting to first node: ${targetNode}`);
      }

      const nextIdResult = await proxmox.cluster.nextid.$get();
      newVmId = nextIdResult.toString();

      if (isIso) {
        const sanitizedName = params.name.replace(/\s+/g, '-');
        const createParams = {
          vmid: newVmId, node: targetNode, name: sanitizedName,
          cores: params.specs.cpu, memory: params.specs.memory,
          description: params.description || '', 
          tags: params.tags?.join(';') || '',
          // Usar el datastoreName (storage de Proxmox) proporcionado desde el frontend
          // Fallback a 'local-lvm' si no se proporciona, aunque el frontend debería validarlo.
          scsi0: `${params.datastoreName || 'local-lvm'}:${params.specs.disk}`, 
          ide2: `${params.templateId},media=cdrom`, boot: 'order=ide2;scsi0',
          net0: 'virtio,bridge=vmbr0', scsihw: 'virtio-scsi-pci', ostype: 'l26',
        };
        console.log(`Attempting to create Proxmox VM ${newVmId} from ISO on node ${targetNode} with params:`, createParams);
        creationResult = await proxmox.nodes.$(targetNode).qemu.$post(createParams); // No .$create()
      } else {
        const templateVmIdToClone = params.templateId;
        const sanitizedName = params.name.replace(/\s+/g, '-');
        const cloneParams = {
          newid: newVmId, name: sanitizedName, full: 1,
          cores: params.specs.cpu, memory: params.specs.memory,
          description: params.description || '', tags: params.tags?.join(';') || '',
        };
        // Si se especifica un datastoreName (storage de Proxmox), usarlo para el clon.
        if (params.datastoreName) {
          cloneParams.storage = params.datastoreName;
        }
        console.log(`Attempting to clone Proxmox template VM ${templateVmIdToClone} to new VM ${newVmId} on node ${targetNode} with params:`, cloneParams);
        creationResult = await proxmox.nodes.$(targetNode).qemu.$(templateVmIdToClone).clone.$post(cloneParams);
      }

      if (params.start && creationResult) {
        console.log(`Starting Proxmox VM ${newVmId}...`);
        await proxmox.nodes.$(targetNode).qemu.$(newVmId).status.start.$post();
      }
    } else if (hypervisor.type === 'vsphere') {
      console.log(`Attempting to create VM on vSphere via PyVmomi microservice: ${params.name}`);
      try {
        const pyVmomiCreateParams = {
            name: params.name,
            specs: params.specs, // cpu, memory, disk
            description: params.description,
            tags: params.tags,
            start_vm: params.start || false,
            // vSphere specific params from VMCreateParams if provided by frontend
            datastore_name: params.datastoreName, // Target datastore for VM's disk
            // resource_pool_name: params.resourcePoolName, // Future: if UI supports it
            // folder_name: params.folderName, // Future: if UI supports it
            // Potentially add placement details if known:
            // datastore_name: params.datastoreName,
            // host_name: params.nodeName, // if nodeName is ESXi host for vCenter
            // resource_pool_name: params.resourcePoolName,
        };

        // Check if templateId is an ISO or a VM Template UUID
        // An ISO path from frontend is like "[datastoreNameOrMoid] path/to/iso.iso"
        const isIso = params.templateId && params.templateId.includes(':') && params.templateId.toLowerCase().includes('.iso');

        if (isIso) {
            // Extract the datastore name and the actual ISO path
            // params.templateId is like "datastore-moid:[DatastoreName] path/to/iso.iso"
            // or "[DatastoreName] path/to/iso.iso" if moid wasn't available
            const parts = params.templateId.split(':');
            const isoPathWithinDatastore = parts.length > 1 ? parts[1] : parts[0]; // Get the part after the first colon, or the whole string if no colon
            
            pyVmomiCreateParams.iso_path = isoPathWithinDatastore; // e.g., "[datastore1] isos/ubuntu-20.04.2.0-desktop-amd64.iso"
            // Ensure specs.os (guestId) is provided by the frontend for ISO creation
            if (!params.specs?.os) {
                 console.error('vSphere ISO creation: Missing OS identifier (guestId) in specs.os');
                 return res.status(400).json({ error: 'OS identifier (guestId) is required in specs.os for ISO creation.' });
            }
            // guestId is expected to be in params.specs.os
        } else {
            pyVmomiCreateParams.template_uuid = params.templateId; // It's a VM template UUID
        }

        // Asumimos que el microservicio devuelve el UUID de la nueva VM o un ID de tarea
        const responseFromPyvmomi = await callPyvmomiService('POST', '/vms/create', hypervisor, pyVmomiCreateParams);
        newVmId = responseFromPyvmomi.vm_uuid; // PyVmomi /vms/create now returns vm_uuid
        creationResult = responseFromPyvmomi.task_id || newVmId; // Task ID or new VM ID
        console.log(`vSphere VM creation initiated via PyVmomi, response:`, responseFromPyvmomi);

      } catch (pyVmomiError) {
        console.error('PyVmomi microservice VM creation error:', pyVmomiError);
        return res.status(pyVmomiError.status || 500).json({
          error: 'Failed to create VM on vSphere via PyVmomi microservice.',
          details: pyVmomiError.details || pyVmomiError.message,
        });
      }
    }

    if (newVmId && creationResult) {
      console.log(`Inserting VM record into database for VMID: ${newVmId}`);
      console.log('User ID for DB insert:', req.user?.userId);
      try {
        const insertQuery = `INSERT INTO virtual_machines (name, description, hypervisor_id, hypervisor_vm_id, status, cpu_cores, memory_mb, disk_gb, ticket, final_client_id, created_by_user_id, os)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id`;
        const insertParams = [
            params.name, params.description || null, params.hypervisorId,
            newVmId, 'creating', params.specs.cpu, params.specs.memory, params.specs.disk,
            params.ticket || null, params.finalClientId || null, req.user.userId,
            params.specs.os || null,
        ];
        const insertResult = await pool.query(insertQuery, insertParams);
        console.log(`Successfully inserted VM record with DB ID: ${insertResult.rows[0].id}`);
      } catch (dbError) {
        console.error('Error inserting VM record into database after creation:', dbError);
      }
    }

    res.status(202).json({
      id: newVmId, status: 'creating',
      message: `VM creation initiated for ${params.name} (ID: ${newVmId}). Task ID: ${creationResult}`,
      taskId: creationResult
    });

  } catch (error) {
    console.error('Error creating VM:', error);
    const errorDetails = getProxmoxError(error); // getProxmoxError might need adjustment for generic errors
    res.status(errorDetails.code || 500).json({
      error: 'Failed to create VM.',
      details: errorDetails.message,
      suggestion: errorDetails.suggestion
    });
  }
});

// POST /api/vms/:id/action - Implement real actions
app.post('/api/vms/:id/action', authenticate, async (req, res) => {
  const { id: vmExternalId } = req.params; // This is Proxmox vmid or vSphere UUID
  const { action } = req.body;

  console.log(`--- Received POST /api/vms/${vmExternalId}/action --- Action: ${action}`);

  if (!['start', 'stop', 'restart', 'suspend', 'resume', 'shutdown'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action specified.' });
  }

  let targetHypervisor = null;
  let targetNode = null; // For Proxmox
  let proxmoxClientInstance = null;
  // No vsphereClientInstance needed here, PyVmomi microservice handles its own client

  try {
    // --- Step 1: Find the VM's Hypervisor (from DB, assuming vmExternalId is hypervisor_vm_id) ---
    // This logic assumes vmExternalId is unique enough across hypervisors or we fetch the VM from DB first
    // For simplicity, we'll iterate through connected hypervisors and try to find the VM.
    // A more robust way is to query `virtual_machines` table by `hypervisor_vm_id` to directly get its hypervisor.
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, name as hypervisor_name, vsphere_subtype
       FROM hypervisors WHERE status = 'connected'`
    );

    let vmFoundOnHypervisor = false;

    for (const hypervisor of connectedHypervisors) {
      if (hypervisor.type === 'proxmox') {
        // ... (Proxmox VM finding logic - Mantenida como estaba)
        const [dbHost, dbPortStr] = hypervisor.host.split(':');
        const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
        const cleanHost = dbHost;
        const proxmoxConfig = {
          host: cleanHost, port: port, username: hypervisor.username,
          tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
          tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false
        };
        proxmoxClientInstance = proxmoxApi(proxmoxConfig);
        try {
          const vmResources = await proxmoxClientInstance.cluster.resources.$get({ type: 'vm' });
          const foundVm = vmResources.find(vm => vm.vmid.toString() === vmExternalId);
          if (foundVm) {
            targetHypervisor = hypervisor;
            targetNode = foundVm.node;
            vmFoundOnHypervisor = true;
            console.log(`Found Proxmox VM ${vmExternalId} on node ${targetNode} of hypervisor ${hypervisor.id} for action`);
            break;
          }
        } catch (findError) {
          console.warn(`Could not check Proxmox hypervisor ${hypervisor.id} for VM ${vmExternalId} action:`, findError.message);
        }
      } else if (hypervisor.type === 'vsphere') {
        // For vSphere, we assume vmExternalId is the UUID.
        // The PyVmomi microservice will confirm if the VM exists.
        // We just need to identify that this is the target hypervisor.
        // A better approach: query DB for the VM by hypervisor_vm_id to get its hypervisor_id directly.
        // For now, if we *think* it's vSphere, we'll try.
        // This part is tricky without a DB lookup for the VM first.
        // Let's assume for now the frontend somehow knows which hypervisor the vSphere VM belongs to,
        // or we modify this to first query the DB for the VM.
        // For this example, we'll assume if a vSphere hypervisor is iterated, we try with it.
        // This needs refinement for a multi-hypervisor vSphere setup.
        // A simple check: if vmExternalId looks like a UUID (common for vSphere VMs from PyVmomi)
        if (vmExternalId.length === 36 && vmExternalId.includes('-')) { // Basic UUID check
          console.log(`Action route: Assuming VM ${vmExternalId} is vSphere. Attempting with hypervisor ${hypervisor.id} (${hypervisor.hypervisor_name || 'Name N/A'})`);
          targetHypervisor = hypervisor;
            vmFoundOnHypervisor = true; // Assume we'll try with this hypervisor
            break;
        }
      }
    }

    if (!vmFoundOnHypervisor || !targetHypervisor) {
      console.log(`Action route: VM ${vmExternalId} not found on any suitable connected hypervisor or targetHypervisor is null.`);
      return res.status(404).json({ error: `VM ${vmExternalId} not found on any suitable connected hypervisor.` });
    }

    // --- Step 2: Perform the action ---
    let resultMessage = `Action '${action}' initiated for VM ${vmExternalId}.`;
    let taskId = null;

    if (targetHypervisor.type === 'proxmox') {
      // ... (Proxmox action logic - Mantenida como estaba)
      const vmPath = proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status;
      console.log(`Performing Proxmox action '${action}' on VM ${vmExternalId} at ${targetNode}...`);
      let proxmoxResult;
      switch (action) {
        case 'start': proxmoxResult = await vmPath.start.$post(); break;
        case 'stop': // Changed to hard stop for Proxmox to avoid timeout issues
          console.log(`Proxmox action 'stop': Performing hard stop for VM ${vmExternalId}`);
          proxmoxResult = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.stop.$post();
          break;
        case 'restart': // Changed to hard restart for Proxmox
          console.log(`Proxmox action 'restart': Performing hard restart (stop then start) for VM ${vmExternalId}`);
          await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.stop.$post();
          // Esperar un momento para asegurar que la VM se detenga antes de intentar iniciarla.
          // Considera que esto es un delay fijo y podría no ser ideal para todos los casos.
          // Monitorear el estado de la tarea de detención sería más robusto pero más complejo aquí.
          await new Promise(resolve => setTimeout(resolve, 5000)); // 5 segundos de espera
          proxmoxResult = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.start.$post();
          break;
        case 'suspend': proxmoxResult = await vmPath.suspend.$post(); break;
        case 'resume': proxmoxResult = await vmPath.resume.$post(); break;
        case 'shutdown': proxmoxResult = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.stop.$post(); break; // Hard power off (Force Off) - Explicit client instance
        default: throw new Error('Invalid action');
      }
      taskId = proxmoxResult;
      resultMessage = `Proxmox action '${action}' initiated for VM ${vmExternalId}. Task ID: ${taskId}`;
      console.log(`Proxmox action '${action}' result for VM ${vmExternalId}:`, taskId);
    } else if (targetHypervisor.type === 'vsphere') {
      console.log(`Performing vSphere action '${action}' on VM ${vmExternalId} via PyVmomi microservice...`);
      let pyvmomiAction = action; // Default to sending the action name directly

      // Map frontend actions to PyVmomi actions
      switch (action) {
        case 'start':
        case 'resume': // vSphere uses 'on' for both start and resume
          pyvmomiAction = 'on';
          break;
        case 'stop': // Graceful stop
          pyvmomiAction = 'shutdown_guest';
          break;
        case 'restart': // Graceful restart
          pyvmomiAction = 'reboot_guest';
          break;
        case 'shutdown': // Force off
          pyvmomiAction = 'off';
          break;
        case 'suspend':
          pyvmomiAction = 'suspend';
          break;
        // 'suspend' is already correct
        default:
          // pyvmomiAction remains as action
          break;
      }

      if (action === 'restart') {
            console.log(`Simulating restart for vSphere VM ${vmExternalId}: power off then power on.`);
            
            try {
              console.log(`Action route: Calling PyVmomi for 'off' for VM ${vmExternalId} on hypervisor ${targetHypervisor.id}`);

              await callPyvmomiService('POST', `/vm/${vmExternalId}/power`, targetHypervisor, { action: 'reboot_guest' }); // Or 'off' then 'on' if reboot_guest is not robust
              console.log(`Action route: Calling PyVmomi for 'on' for VM ${vmExternalId} on hypervisor ${targetHypervisor.id}`);
              // await callPyvmomiService('POST', `/vm/${vmExternalId}/power`, targetHypervisor, { action: 'on' }); // if doing off then on
              resultMessage = `vSphere VM ${vmExternalId} restart (off/on) action initiated via PyVmomi.`;
            } catch (pyError) {
              console.error(`Action route: Error during vSphere restart sequence for ${vmExternalId}:`, pyError.message, "Status:", pyError.status, "Details:", pyError.details);
              throw pyError;
            }
          } else { // This covers 'start' (mapped to 'on') or 'stop' (mapped to 'off')
            // This will be 'on' or 'off'
            console.log(`Action route: Calling PyVmomi for action '${pyvmomiAction}' (mapped from '${action}') for VM ${vmExternalId} on hypervisor ${targetHypervisor.id}`);
             try {
              await callPyvmomiService('POST', `/vm/${vmExternalId}/power`, targetHypervisor, { action: pyvmomiAction });
              resultMessage = `vSphere VM ${vmExternalId} ${action} action initiated via PyVmomi.`;
            } catch (pyError) {
              // Log the specific error from callPyvmomiService here
              console.error(`Action route: Error calling PyVmomi for power action '${pyvmomiAction}' on ${vmExternalId}:`, pyError.message, "Status:", pyError.status, "Details:", pyError.details);
              throw pyError; // Re-throw to be caught by the outer catch block of the route
            }
          }
        // PyVmomi microservice currently returns {status: 'success'} or error, not a task ID.
        console.log(`vSphere action '${action}' for VM ${vmExternalId} completed via PyVmomi.`);
      }
    

    res.json({
      id: vmExternalId, status: 'pending',
      message: resultMessage, taskId: taskId
    });

  } catch (error) {
    console.error(`Error performing action '${action}' on VM ${vmExternalId}:`, error);
    let errorDetails;
    if (targetHypervisor?.type === 'proxmox') {
        errorDetails = getProxmoxError(error);
    } else if (targetHypervisor?.type === 'vsphere') {
        errorDetails = {
            code: error.status || 500,
            message: error.details?.error || error.message || `Failed to perform vSphere action '${action}' on VM ${vmExternalId} via PyVmomi.`
        };
    } else {
        errorDetails = { code: 500, message: error.message || `Failed to perform action '${action}' on VM ${vmExternalId}` };
    }
    res.status(errorDetails.code || 500).json({
      error: `Failed to perform action '${action}' on VM ${vmExternalId}.`,
      details: errorDetails.message,
      suggestion: errorDetails.suggestion
    });
  }
});

// POST /api/vms/:id/console - Get console access details
app.post('/api/vms/:id/console', authenticate, async (req, res) => {
  const { id: vmExternalId } = req.params; // Proxmox vmid or vSphere UUID
  console.log(`--- Received POST /api/vms/${vmExternalId}/console ---`);

  let targetHypervisor = null;
  let targetNode = null; // For Proxmox
  let proxmoxClientInstance = null;
  let vmNameForConsole = vmExternalId; // Default name

  try {
    // Step 1: Find the VM's Hypervisor and basic info
    // Similar logic to /action or /details route to find the VM
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, api_token, password, token_name, name as hypervisor_name 
       FROM hypervisors WHERE status = 'connected'`
    );

    let vmFoundOnHypervisor = false;

    for (const hypervisor of connectedHypervisors) {
      if (hypervisor.type === 'proxmox') {
        const [dbHost, dbPortStr] = hypervisor.host.split(':');
        const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
        const cleanHost = dbHost; // This is the Proxmox API host
        const proxmoxConfig = {
          host: cleanHost, port: port, username: hypervisor.username,
          tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
          tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false
        };
        
console.log("proxmoxConfig",proxmoxConfig)
        proxmoxClientInstance = proxmoxApi(proxmoxConfig);
        try {
          const vmResources = await proxmoxClientInstance.cluster.resources.$get({ type: 'vm' });
          const foundVm = vmResources.find(vm => vm.vmid.toString() === vmExternalId);
          if (foundVm) {
            targetHypervisor = hypervisor;
            targetNode = foundVm.node;
            vmNameForConsole = foundVm.name || vmExternalId;
            vmFoundOnHypervisor = true;
            console.log(`Console: Found Proxmox VM ${vmExternalId} on node ${targetNode} of hypervisor ${hypervisor.id}`);
            break;
          }
        } catch (findError) {
          console.warn(`Console: Could not check Proxmox hypervisor ${hypervisor.id} for VM ${vmExternalId}:`, findError.message);
        }
      } else if (hypervisor.type === 'vsphere') {
        // For vSphere, we assume vmExternalId is the UUID. The PyVmomi service will confirm.
        // We need to fetch the VM name if possible for a better console title.
        // A quick DB lookup:
        const { rows: [dbVm] } = await pool.query('SELECT name FROM virtual_machines WHERE hypervisor_vm_id = $1 AND hypervisor_id = $2', [vmExternalId, hypervisor.id]);
        if (dbVm) {
            vmNameForConsole = dbVm.name;
        }
        // Basic UUID check to ensure it's likely a vSphere VM before trying
        if (vmExternalId.length === 36 && vmExternalId.includes('-')) {
          targetHypervisor = hypervisor;
          vmFoundOnHypervisor = true; // Assume we'll try with this hypervisor
          console.log(`Console: Assuming VM ${vmExternalId} is vSphere on hypervisor ${hypervisor.id}. Name: ${vmNameForConsole}`);
          break;
        }
      }
    }

    if (!vmFoundOnHypervisor || !targetHypervisor) {
      return res.status(404).json({ error: `VM ${vmExternalId} not found on any suitable connected hypervisor for console access.` });
    }

    // Step 2: Get console details based on hypervisor type
    if (targetHypervisor.type === 'proxmox') {
      console.log(`Console: Requesting VNC proxy for Proxmox VM ${vmExternalId} on node ${targetNode}`);
      const vncProxyResponse = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).vncproxy.$post({});
      // targetHypervisor.host from DB is like "10.70.255.84:8006"
      const [apiHost, apiPortStr] = targetHypervisor.host.split(':');
      const proxmoxApiPort = apiPortStr ? parseInt(apiPortStr, 10) : 8006;

      // vncProxyResponse.port is the actual VNC port (e.g., 5900)
      // vncProxyResponse.ticket is the VNC ticket
      console.log(`Proxmox vncproxy obtained: vncPort=${vncProxyResponse.port}, ticket=${vncProxyResponse.ticket ? 'present' : 'missing'}. Proxmox API for connection: ${apiHost}:${proxmoxApiPort}, Node: ${targetNode}`);

      if (!vncProxyResponse.port || !vncProxyResponse.ticket) {
        console.error(`Proxmox vncproxy response for VM ${vmExternalId} on node ${targetNode} is missing port or ticket.`);
        throw new Error('Proxmox vncproxy response was incomplete (missing port or ticket).');
      }
 

      res.json({
        type: 'proxmox',
        connectionDetails: {
          host: apiHost, // Proxmox API host (e.g., 10.70.255.84)
          port: proxmoxApiPort, // Proxmox API port (e.g., 8006)
          ticket: vncProxyResponse.ticket, // This is the password for VNC
          vmid: vmExternalId,
          node: targetNode,
          vmName: vmNameForConsole,
          vncPort: vncProxyResponse.port // Actual VNC port from vncproxy (e.g., 5900)


        }
      });
    } else if (targetHypervisor.type === 'vsphere') {
      console.log(`Console: Requesting WebMKS ticket for vSphere VM ${vmExternalId} via PyVmomi`);
      const mksTicketDetails = await callPyvmomiService('POST', `/vm/${vmExternalId}/console`, targetHypervisor, { vm_name: vmNameForConsole });
         // PyVmomi service now returns ticket_type ('mks' or 'webmks') and corresponding details.
      // The frontend will use ticket_type to determine how to connect.
      res.json({
        type: `vsphere_${mksTicketDetails.ticket_type}`, // e.g., vsphere_mks or vsphere_webmks
        connectionDetails: { 
          ...mksTicketDetails, // Pass all details from PyVmomi
          vmName: vmNameForConsole 
        }
      });
    }
  } catch (error) {
    console.error(`Error getting console for VM ${vmExternalId}:`, error);
    const errorDetails = getProxmoxError(error); // Adapt if error is from PyVmomi
    res.status(errorDetails.code || 500).json({ error: 'Failed to get console access.', details: errorDetails.message });
  }
});

// Helper function to extract IP addresses from Proxmox QEMU agent response
function extractIpAddressesFromAgent(agentInterfaces) {
  const ips = [];
  if (Array.isArray(agentInterfaces)) {
    for (const iface of agentInterfaces) {
      if (iface.name === 'lo' || !iface['ip-addresses']) continue; // Skip loopback or interfaces without IPs
      for (const ipAddr of iface['ip-addresses']) {
        // Prefer IPv4, non-link-local
        if (ipAddr['ip-address-type'] === 'ipv4' && ipAddr['ip-address'] && !ipAddr['ip-address'].startsWith('169.254.')) {
          ips.push(ipAddr['ip-address']);
        }
        // Optionally, add IPv6 later if needed: else if (ipAddr['ip-address-type'] === 'ipv6' && ipAddr['ip-address'] && !ipAddr['ip-address'].startsWith('fe80:'))
      }
    }
  }
  return ips;
}

// GET /api/vms - List VMs from all connected hypervisors
app.get('/api/vms', authenticate, async (req, res) => {
 // console.log('--- Received GET /api/vms ---');
  let allVms = [];

  try {
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, name as hypervisor_name, vsphere_subtype
       FROM hypervisors WHERE status = 'connected'`
    );
    console.log(`Found ${connectedHypervisors.length} connected hypervisors.`);

    for (const hypervisor of connectedHypervisors) {
      console.log(`Fetching VMs from ${hypervisor.type} hypervisor: ${hypervisor.host} (ID: ${hypervisor.id})`);
      try {
        if (hypervisor.type === 'proxmox') {
          // ... (Proxmox VM listing logic - Mantenida como estaba)
          const [dbHost, dbPortStr] = hypervisor.host.split(':');
          const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
          const cleanHost = dbHost;
          const proxmoxConfig = {
            host: cleanHost, port: port, username: hypervisor.username,
            tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
            tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false
          };
          const proxmox = proxmoxApi(proxmoxConfig);
          const vmResources = await proxmox.cluster.resources.$get({ type: 'vm' }).catch(e => {
            console.error(`Error fetching Proxmox VM resources for ${hypervisor.host}: ${e.message}`);
            return [];
          });

          for (const vm of vmResources) {
            let ipAddress = null;
            if (vm.status === 'running' && vm.agent === 1) { // Check if agent is enabled and VM is running
              try {
                const agentNetInfo = await proxmox.nodes.$(vm.node).qemu.$(vm.vmid).agent('network-get-interfaces').$get({timeout: 2000});
                const ips = extractIpAddressesFromAgent(agentNetInfo?.result);
                if (ips.length > 0) ipAddress = ips[0];
              } catch (agentError) {
                // console.warn(`Could not get IP for Proxmox VM ${vm.vmid} via agent: ${agentError.message}`);
              }
            }
            allVms.push({
              id: vm.vmid.toString(), name: vm.name, status: vm.status, nodeName: vm.node,
              specs: {
                cpu: vm.maxcpu, memory: Math.round(vm.maxmem / (1024 * 1024)),
                disk: Math.round(vm.maxdisk / (1024 * 1024 * 1024)),
              },
              hypervisorType: 'proxmox', hypervisorId: hypervisor.id, createdAt: new Date(vm.uptime ? Date.now() - (vm.uptime * 1000) : Date.now()), // Approximate createdAt from uptime
              ipAddress: ipAddress,
            });
          }
        } else if (hypervisor.type === 'vsphere') {
          console.log(`Fetching VMs from vSphere hypervisor ${hypervisor.id} via PyVmomi microservice`);
          try {
            const pyvmomiVmsRaw = await callPyvmomiService('GET', '/vms', hypervisor);
            if (Array.isArray(pyvmomiVmsRaw)) {
              const vsphereVms = pyvmomiVmsRaw.map(vm => ({
                id: vm.uuid, // Use UUID from PyVmomi as the primary ID
                name: vm.name,
                status: vm.power_state === 'poweredOn' ? 'running' : (vm.power_state === 'poweredOff' ? 'stopped' : vm.power_state.toLowerCase()),
                nodeName: hypervisor.hypervisor_name, // Simplified, actual ESXi host per VM needs more detail from PyVmomi
                specs: {
                  cpu: vm.cpu_count || 0,
                  memory: vm.memory_mb || 0,
                  disk: vm.disk_gb || 0,
                  os: vm.guest_os,
                },
                hypervisorType: 'vsphere',
                hypervisorId: hypervisor.id,
                createdAt: new Date(), // Placeholder, PyVmomi might provide creation date
                // Nuevos campos para vSphere
                hostname: vm.hostname,
                vmware_tools_status: vm.vmware_tools_status,
                ipAddress: vm.ip_address, // Asegurarse que el listado también lo devuelva si es necesario para la card
              }));
              allVms = allVms.concat(vsphereVms);
              console.log(`Fetched ${vsphereVms.length} VMs from vSphere ${hypervisor.host} via PyVmomi`);
            } else {
              console.warn(`Unexpected response for vSphere VMs from PyVmomi microservice for ${hypervisor.host}:`, pyvmomiVmsRaw);
            }
          } catch (pyVmomiError) {
            console.error(`Error fetching VMs from vSphere ${hypervisor.id} via PyVmomi:`, pyVmomiError.details?.error || pyVmomiError.message);
          }
        }
      } catch (hypervisorError) {
        console.error(`Error fetching VMs from hypervisor ${hypervisor.id} (${hypervisor.host}):`, hypervisorError.message);
      }
    }
    console.log(`Total VMs fetched: ${allVms.length}`);
    res.json(allVms);
  } catch (dbError) {
    console.error('Error retrieving connected hypervisors from DB:', dbError);
    res.status(500).json({ error: 'Failed to retrieve hypervisor list' });
  }
});

// GET /api/vms/:id - Get details for a single VM
app.get('/api/vms/:id', authenticate, async (req, res) => {
  const { id: vmExternalId } = req.params; // Proxmox vmid or vSphere UUID
 // console.log(`--- Received GET /api/vms/${vmExternalId} ---`);

  let targetHypervisor = null;
  let targetNode = null; // For Proxmox
  let proxmoxClientInstance = null;

  try {
    // --- Step 1: Fetch VM record from local database (if it exists) ---
    // This is to get DB-specific fields like ticket, client, description, and the hypervisor_id
    // We assume vmExternalId is the hypervisor_vm_id (Proxmox VMID or vSphere UUID)
    console.log(`VMDetails: Attempting to find VM record in DB for hypervisor_vm_id = ${vmExternalId}`);
    const { rows: [dbVmRecord] } = await pool.query(
      `SELECT vm.*, fc.name as final_client_name 
       FROM virtual_machines vm 
       LEFT JOIN final_clients fc ON vm.final_client_id = fc.id 
       WHERE vm.hypervisor_vm_id = $1`, [vmExternalId]);

    if (!dbVmRecord) {
      console.log(`VMDetails: No record found in DB for hypervisor_vm_id = ${vmExternalId}. Will attempt to find on connected hypervisors.`);
    }

    // --- Step 2: Find the VM on a connected hypervisor and get live data ---
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, name as hypervisor_name, vsphere_subtype, status
       FROM hypervisors WHERE status = 'connected'`
    );

    let vmFoundOnHypervisor = false;
    let hypervisorData = {}; // To store data fetched from hypervisor


    // Iterate through connected hypervisors to find the VM
    for (const hypervisor of connectedHypervisors) {
      console.log(`VMDetails: Checking hypervisor ${hypervisor.id} (${hypervisor.name}) of type ${hypervisor.type} for VM ${vmExternalId}`);
      try {
      if (hypervisor.type === 'proxmox') {
        const [dbHost, dbPortStr] = hypervisor.host.split(':');
        const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
        const cleanHost = dbHost;
        proxmoxClientInstance = proxmoxApi({ host: cleanHost, port: port, username: hypervisor.username, tokenID: `${hypervisor.username}!${hypervisor.token_name}`, tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false });

      // Find the node for the VM first
      const vmResources = await proxmoxClientInstance.cluster.resources.$get({ type: 'vm' });
      const foundVmResource = vmResources.find(vm => vm.vmid.toString() === vmExternalId);
      if (!foundVmResource) {
        // Not on this Proxmox hypervisor's cluster resources, continue to next hypervisor
        console.log(`VMDetails: Proxmox VM ${vmExternalId} not found on cluster resources of hypervisor ${hypervisor.id}.`);
        continue;
      }
        targetNode = foundVmResource.node;
        targetHypervisor = hypervisor; // Found it!
        console.log(`VMDetails: Found Proxmox VM ${vmExternalId} on node ${targetNode} of hypervisor ${targetHypervisor.id}`);

      const vmConfig = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).config.$get();
      const vmStatus = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.current.$get();
      
      let ipAddress = null;
      let ipAddresses = [];
      if (vmStatus.status === 'running' && vmStatus.agent === 1) { // Check if agent is enabled and VM is running
        try {
          const agentNetInfo = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).agent.$post({ command: 'network-get-interfaces' }, { timeout: 3000 });
          ipAddresses = extractIpAddressesFromAgent(agentNetInfo?.result);
          if (ipAddresses.length > 0) ipAddress = ipAddresses[0];
        } catch (agentError) {
          console.warn(`Could not get IP for Proxmox VM ${vmExternalId} details via agent: ${agentError.message}`);
        }
      }
      hypervisorData = {
        name: vmConfig.name, // Name from hypervisor
        status: vmStatus.status,
        nodeName: targetNode, // Node where it runs
        ipAddress: ipAddress,
        ipAddresses: ipAddresses,
        specs: { // Specs from Proxmox
          cpu: (vmConfig.cores || 0) * (vmConfig.sockets || 1), // Ensure cores is a number, sockets defaults to 1
          memory: vmConfig.memory || 0, // memory is already in MB from Proxmox API, ensure it's a number
          disk: Math.round((vmConfig.maxdisk || 0) / (1024 * 1024 * 1024)), // GB, ensure maxdisk is a number
           // Additional Proxmox Config Details
           nameserver: vmConfig.nameserver || null,
           agent: vmConfig.agent || 0, // 0 or 1
           arch: vmConfig.arch || null,
           args: vmConfig.args || null,
           autostart: vmConfig.autostart || 0, // 0 or 1
           keyboard: vmConfig.keyboard || null,
           kvm: vmConfig.kvm || 0, // 0 or 1
           machine: vmConfig.machine || null,
           onboot: vmConfig.onboot || 0, // 0 or 1
           startdate: vmConfig.startdate || null, // Configured start date for autostart
          
          os: vmConfig.ostype,
          },
        tags: vmConfig.tags ? vmConfig.tags.split(';') : [],
      };
      console.log('detalles',hypervisorData)

        vmFoundOnHypervisor = true; // Found on this hypervisor
        break; // Stop searching
      } else if (hypervisor.type === 'vsphere') {
      // This endpoint should return comprehensive details: name, power_state, guest_os, ip, uuid,
      // cpu_count, memory_mb, disk details (capacity, datastore), network details, host, etc.
      try {
        const pyvmomiVmDetails = await callPyvmomiService('GET', `/vm/${vmExternalId}/details`, hypervisor);
        // If callPyvmomiService returns a 404 (VM not found on this vSphere), it will throw an error
        // and we'll catch it below, then continue to the next hypervisor.
        
        const vsphereIps = [];
        if (pyvmomiVmDetails.ip_address && !vsphereIps.includes(pyvmomiVmDetails.ip_address)) {
            vsphereIps.push(pyvmomiVmDetails.ip_address);
        }
        targetHypervisor = hypervisor; // Found it!
        console.log(`VMDetails: Found vSphere VM ${vmExternalId} on hypervisor ${targetHypervisor.id}`);
        hypervisorData = {
          name: pyvmomiVmDetails.name,
          nodeName: pyvmomiVmDetails.host_name || targetHypervisor.hypervisor_name,
          description: pyvmomiVmDetails.annotation || '', // Mapear anotación de vSphere a descripción
          status: pyvmomiVmDetails.power_state === 'poweredOn' ? 'running' : (pyvmomiVmDetails.power_state === 'poweredOff' ? 'stopped' : pyvmomiVmDetails.power_state.toLowerCase()),
          ipAddress: pyvmomiVmDetails.ip_address || null,
          ipAddresses: vsphereIps, 
          specs: {
            cpu: pyvmomiVmDetails.cpu_count || 0,
            memory: pyvmomiVmDetails.memory_mb || 0,
            disk: pyvmomiVmDetails.disk_gb || 0, 
            os: pyvmomiVmDetails.guest_os || 'Unknown',
          },
          moid: pyvmomiVmDetails.moid,
          hostname: pyvmomiVmDetails.hostname,
          vmwareToolsStatus: pyvmomiVmDetails.vmware_tools_status, 
          tags: [], 
        };
        vmFoundOnHypervisor = true; // Found on this hypervisor
        break; // Stop searching
      } catch (pyVmomiError) {
        if (pyVmomiError.status === 404) {
          console.log(`VMDetails: vSphere VM ${vmExternalId} not found on hypervisor ${hypervisor.id}.`);
        } else {
          console.warn(`VMDetails: Error fetching vSphere VM ${vmExternalId} details from hypervisor ${hypervisor.id}:`, pyVmomiError.message);
        }
        // Do NOT re-throw here if it's a 404, let the loop continue to check other hypervisors
        // If it's another error (e.g., 500 from Python service), we might also want to continue or handle differently.
        // For now, we continue.
      }
    }
    } catch (hypervisorCheckError) {
        console.warn(`VMDetails: Error checking hypervisor ${hypervisor.id} (${hypervisor.name}) for VM ${vmExternalId}:`, hypervisorCheckError.message);
        // Continue to the next hypervisor if checking this one fails
    }
    } // End of hypervisor loop

    if (!vmFoundOnHypervisor) {
      // If not found in DB and not found on any connected hypervisor
      if (!dbVmRecord) {
        return res.status(404).json({ error: `VM with external ID ${vmExternalId} not found in database or on any connected hypervisor.` });
      }
      // If it was in DB, but not found live (e.g., hypervisor disconnected or VM deleted from hypervisor)
      // Return DB data with a warning.
      console.warn(`VMDetails: VM ${vmExternalId} found in DB but not on any connected hypervisor. Returning DB data.`);
      const dbOnlyVmDetails = {
        id: dbVmRecord.hypervisor_vm_id,
        databaseId: dbVmRecord.id,
        name: dbVmRecord.name,
        description: dbVmRecord.description,
        hypervisorId: dbVmRecord.hypervisor_id,
        hypervisorType: (await pool.query('SELECT type FROM hypervisors WHERE id = $1', [dbVmRecord.hypervisor_id])).rows[0]?.type || 'unknown',
        nodeName: null,
        status: dbVmRecord.status, // Could be stale
        specs: { cpu: dbVmRecord.cpu_cores, memory: dbVmRecord.memory_mb, disk: dbVmRecord.disk_gb, os: dbVmRecord.os },
        createdAt: dbVmRecord.created_at,
        ticket: dbVmRecord.ticket,
        finalClientId: dbVmRecord.final_client_id,
        finalClientName: dbVmRecord.final_client_name,
        tags: dbVmRecord.tags || [],
        ipAddress: null,
        ipAddresses: [],
        warning: "VM not found on connected hypervisors; live data unavailable. Displaying stored data."
      };
      return res.json(dbOnlyVmDetails);
    }


    // --- Step 3: Merge DB data with Hypervisor data ---
    if (!dbVmRecord) {
      // VM found on hypervisor but not in local DB (unmanaged VM)
      console.warn(`VM ${vmExternalId} found on hypervisor ${targetHypervisor.id} but not in local DB. Returning live data only.`);
      return res.json({
        id: vmExternalId, // hypervisor_vm_id
        name: hypervisorData.name || vmExternalId,
        description: hypervisorData.description || '',
        hypervisorId: targetHypervisor.id,
        hypervisorType: targetHypervisor.type,
        nodeName: hypervisorData.nodeName || null,
        status: hypervisorData.status || 'unknown',
        specs: hypervisorData.specs || { cpu: 0, memory: 0, disk: 0, os: 'Unknown' },
        createdAt: hypervisorData.created_at ? new Date(hypervisorData.created_at) : new Date(0),
        ipAddress: hypervisorData.ipAddress || null,
        ipAddresses: hypervisorData.ipAddresses || [],
        moid: hypervisorData.moid,
         // Include new Proxmox config fields if they exist in hypervisorData
      nameserver: hypervisorData.nameserver,
      agent: hypervisorData.agent,
      arch: hypervisorData.arch,
      args: hypervisorData.args,
      autostart: hypervisorData.autostart,
      keyboard: hypervisorData.keyboard,
      kvm: hypervisorData.kvm,
      machine: hypervisorData.machine,
      onboot: hypervisorData.onboot,
      startdate: hypervisorData.startdate,
        hostname: hypervisorData.hostname,
        vmwareToolsStatus: hypervisorData.vmwareToolsStatus,
        tags: hypervisorData.tags || [],
        // No ticket, finalClient info as it's not in DB
      });
    }

    // VM found in DB and on a connected hypervisor: Merge data
    // DB data is primary for some fields, hypervisor data updates/complements it
    const finalVmDetails = {
      id: dbVmRecord.hypervisor_vm_id,
      databaseId: dbVmRecord.id,
      name: hypervisorData.name || dbVmRecord.name, // Prefer live name
      description: dbVmRecord.description || hypervisorData.description, // Prefer DB, fallback to live (e.g. vSphere annotation)
      hypervisorId: dbVmRecord.hypervisor_id,
      hypervisorType: targetHypervisor.type,
      nodeName: hypervisorData.nodeName || null,
      status: hypervisorData.status || dbVmRecord.status, // Prefer live status
      specs: {
        cpu: hypervisorData.specs?.cpu || dbVmRecord.cpu_cores || 0, // Prefer live specs
        memory: hypervisorData.specs?.memory || dbVmRecord.memory_mb || 0,
        disk: hypervisorData.specs?.disk || dbVmRecord.disk_gb,
        os: hypervisorData.specs?.os || dbVmRecord.os,
      },
      createdAt: dbVmRecord.created_at, // DB creation time is authoritative
      ticket: dbVmRecord.ticket,
      finalClientId: dbVmRecord.final_client_id,
      finalClientName: dbVmRecord.final_client_name,
      tags: dbVmRecord.tags || hypervisorData.tags || [], // Prefer DB tags, merge or fallback
      ipAddress: hypervisorData.ipAddress || null,
      ipAddresses: hypervisorData.ipAddresses || [],
      moid: hypervisorData.moid,
      // Include new Proxmox config fields from hypervisorData
      nameserver: hypervisorData.nameserver,
      agent: hypervisorData.agent,
      arch: hypervisorData.arch,
      args: hypervisorData.args,
      autostart: hypervisorData.autostart,
      keyboard: hypervisorData.keyboard,
      kvm: hypervisorData.kvm,
      machine: hypervisorData.machine,
      onboot: hypervisorData.onboot,
      startdate: hypervisorData.startdate,
      hostname: hypervisorData.hostname,
      vmwareToolsStatus: hypervisorData.vmwareToolsStatus,
    };

    res.json(finalVmDetails);
  } catch (error) {
    console.error(`Error fetching details for VM ${vmExternalId}:`, error);
    let errorDetails;
    if (targetHypervisor?.type === 'proxmox') {
        errorDetails = getProxmoxError(error);
    } else if (targetHypervisor?.type === 'vsphere') {
        errorDetails = { code: error.status || 500, message: error.details?.error || error.message || `Failed to retrieve vSphere VM details for ${vmExternalId}` };
    } else {
        errorDetails = { code: 500, message: error.message || `Failed to retrieve VM details for ${vmExternalId}` };
    }
    res.status(errorDetails.code || 500).json({
      error: `Failed to retrieve details for VM ${vmExternalId}.`,
      details: errorDetails.message,
      suggestion: errorDetails.suggestion
    });
  }
});


// GET /api/vms/:id/metrics - Get current performance metrics for a single VM
app.get('/api/vms/:id/metrics', authenticate, async (req, res) => {
  const { id: vmExternalId } = req.params; // Proxmox vmid or vSphere UUID
 // console.log(`--- Received GET /api/vms/${vmExternalId}/metrics ---`);

  let targetHypervisor = null;
  let targetNode = null; // For Proxmox
  let proxmoxClientInstance = null;

  try {
    // --- Step 1: Find the VM's Hypervisor (Iterate or DB lookup) ---
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, name as hypervisor_name, vsphere_subtype
       FROM hypervisors WHERE status = 'connected'`
    );
    let vmFoundOnHypervisor = false;
    for (const hypervisor of connectedHypervisors) {
      if (hypervisor.type === 'proxmox') {
        // ... (Proxmox VM finding logic)
        const [dbHost, dbPortStr] = hypervisor.host.split(':');
        const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
        const cleanHost = dbHost;
        const proxmoxConfig = {
          host: cleanHost, port: port, username: hypervisor.username,
          tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
          tokenSecret: hypervisor.api_token, timeout: 5000, rejectUnauthorized: false
        };
        proxmoxClientInstance = proxmoxApi(proxmoxConfig);
        try {
          const vmResources = await proxmoxClientInstance.cluster.resources.$get({ type: 'vm' });
          const foundVm = vmResources.find(vm => vm.vmid.toString() === vmExternalId);
          if (foundVm) {
            targetHypervisor = hypervisor;
            targetNode = foundVm.node;
            vmFoundOnHypervisor = true;
            break;
          }
        } catch (findError) { /* ignore */ }
      } else if (hypervisor.type === 'vsphere') {
        if (vmExternalId.length === 36 && vmExternalId.includes('-')) { // Basic UUID check
            targetHypervisor = hypervisor;
            vmFoundOnHypervisor = true;
            break;
        }
      }
    }

    if (!vmFoundOnHypervisor || !targetHypervisor) {
      return res.status(404).json({ error: `VM ${vmExternalId} not found for metrics.` });
    }

    // --- Step 2: Get VM Metrics ---
    let metrics;
    if (targetHypervisor.type === 'proxmox') {
      // ... (Proxmox metrics logic - Mantenida como estaba)
      const vmStatus = await proxmoxClientInstance.nodes.$(targetNode).qemu.$(vmExternalId).status.current.$get();
      metrics = {
        cpu: (vmStatus.cpu || 0) * 100,
        memory: vmStatus.maxmem > 0 ? (vmStatus.mem / vmStatus.maxmem) * 100 : 0,
        disk: 0, // Placeholder
        network: { in: vmStatus.netin || 0, out: vmStatus.netout || 0, },
        uptime: vmStatus.uptime || 0,
        raw: { /* ... */ }
      };
    } else if (targetHypervisor.type === 'vsphere') {
      //console.log(`Fetching metrics for vSphere VM ${vmExternalId} via PyVmomi microservice`);
      // TODO: PYVMOMI: Implement '/vm/<vm_uuid>/metrics' endpoint in app.py
      // This endpoint should use pyVmomi's PerformanceManager to get CPU, memory, disk, network usage.
      try {
        const pyvmomiMetrics = await callPyvmomiService('GET', `/vm/${vmExternalId}/metrics`, targetHypervisor);
        // Map pyvmomiMetrics to the structure expected by the frontend
        metrics = {
          cpu: pyvmomiMetrics.cpu_usage_percent || 0,
          memory: pyvmomiMetrics.memory_usage_percent || 0,
          disk: pyvmomiMetrics.disk_usage_percent || 0, // Placeholder if not available
          network: {
            in: pyvmomiMetrics.network_rx_bytes || 0, // Or rate if available
            out: pyvmomiMetrics.network_tx_bytes || 0, // Or rate if available
          },
          uptime: pyvmomiMetrics.uptime_seconds || 0,
          raw: pyvmomiMetrics.raw_stats || {}, // Pass through any raw stats
        };
      } catch (pyVmomiError) {
        console.error(`Error fetching vSphere VM metrics for ${vmExternalId} via PyVmomi:`, pyVmomiError.details?.error || pyVmomiError.message);
        // Return placeholder metrics on error or re-throw
        metrics = { cpu: 0, memory: 0, disk: 0, network: { in: 0, out: 0 }, uptime: 0, error: "Failed to load metrics via PyVmomi" };
      }
    } else {
      return res.status(500).json({ error: 'Inconsistent state for metrics.' });
    }
    res.json(metrics);
  } catch (error) {
    console.error(`Error fetching metrics for VM ${vmExternalId}:`, error);
    // Generic error handling
    res.status(500).json({ error: `Failed to retrieve metrics for VM ${vmExternalId}.`, details: error.message });
  }
});

// GET /api/vms/:id/historical-metrics - Get historical performance metrics
app.get('/api/vms/:id/historical-metrics', authenticate, async (req, res) => {
  const { id: vmExternalId } = req.params;
  const timeframe = req.query.timeframe || 'hour'; // Default to 'hour'
  const validTimeframes = ['hour', 'day', 'week', 'month', 'year'];

  if (typeof timeframe !== 'string' || !validTimeframes.includes(timeframe)) {
    return res.status(400).json({ error: 'Invalid timeframe. Must be one of: ' + validTimeframes.join(', ') });
  }

 // console.log(`--- Received GET /api/vms/${vmExternalId}/historical-metrics?timeframe=${timeframe} ---`);

  let targetHypervisor = null;
  let targetNode = null; // For Proxmox

  try {
    // Step 1: Find the VM's Hypervisor (Iterate or DB lookup)
    // This logic is simplified; a direct DB lookup for the VM to get its hypervisor_id would be more efficient.
    const { rows: connectedHypervisors } = await pool.query( // Ensure password is included for vSphere
      `SELECT id, type, host, username, password, api_token, token_name 
       FROM hypervisors WHERE status = 'connected'`
    );

    let vmFoundOnHypervisor = false;
    for (const hypervisor of connectedHypervisors) {
      if (hypervisor.type === 'proxmox') {
        const [dbHost, dbPortStr] = hypervisor.host.split(':');
        const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
        const cleanHost = dbHost;
        const proxmoxConfig = {
          host: cleanHost, port: port, username: hypervisor.username,
          tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
          tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false
        };
        const proxmox = proxmoxApi(proxmoxConfig);
        try {
          const vmResources = await proxmox.cluster.resources.$get({ type: 'vm' });
          const foundVm = vmResources.find(vm => vm.vmid.toString() === vmExternalId);
          if (foundVm) {
            targetHypervisor = hypervisor;
            targetNode = foundVm.node;
            vmFoundOnHypervisor = true;
            break;
          }
        } catch (findError) { console.warn(`Historical Metrics: Error finding Proxmox VM ${vmExternalId} on ${hypervisor.host}: ${findError.message}`); }
      } else if (hypervisor.type === 'vsphere') {
        // For vSphere, assume vmExternalId is the UUID. The PyVmomi service will confirm.
        // A more robust way is to query `virtual_machines` table by `hypervisor_vm_id` to directly get its hypervisor.
        if (vmExternalId.length === 36 && vmExternalId.includes('-')) { // Basic UUID check
            targetHypervisor = hypervisor;
            vmFoundOnHypervisor = true;
            break;
        }
      }
    }

    if (!vmFoundOnHypervisor || !targetHypervisor) {
      return res.status(404).json({ error: `VM ${vmExternalId} not found on any connected hypervisor for historical metrics.` });
    }

    if (targetHypervisor.type === 'proxmox' && targetNode) {
      const proxmox = await getProxmoxClient(targetHypervisor.id); // Use helper to get client
      const rrdData = await proxmox.nodes.$(targetNode).qemu.$(vmExternalId).rrddata.$get({ timeframe });

      // Transform data for easier consumption by charts
      const formattedMetrics = rrdData.map((dataPoint) => ({
        time: dataPoint.time * 1000, // Convert seconds to milliseconds for JS Date
        cpuUsagePercent: (dataPoint.cpu || 0) * 100, // CPU usage as percentage
        memoryUsageBytes: dataPoint.mem || 0,
        maxMemoryBytes: dataPoint.maxmem || 0,
        memoryUsagePercent: dataPoint.maxmem > 0 ? (dataPoint.mem / dataPoint.maxmem) * 100 : 0,
        diskReadBps: dataPoint.diskread || 0,
        diskWriteBps: dataPoint.diskwrite || 0,
        netInBps: dataPoint.netin || 0,
        netOutBps: dataPoint.netout || 0,
      })).filter(dp => dp.time > 0); // Filter out potential zero/invalid timestamps

      res.json(formattedMetrics);
    } else if (targetHypervisor.type === 'vsphere') { // Logic for vSphere historical metrics via PyVmomi
      //console.log(`Historical Metrics: Fetching for vSphere VM ${vmExternalId} with timeframe ${timeframe}`);
      // Assuming PyVmomi microservice has an endpoint like /vm/<uuid>/historical_metrics?timeframe=...
      const pyvmomiHistoricalData = await callPyvmomiService(
        'GET', 
        `/vm/${vmExternalId}/historical_metrics?timeframe=${timeframe}`, 
        targetHypervisor // Pass the full hypervisor object which includes credentials
      );

      // The Python service now returns data in the expected format (milliseconds timestamp, correct keys)
      // No complex mapping needed here, just ensure it's an array and timestamps are valid.
      const formattedMetrics = Array.isArray(pyvmomiHistoricalData) ? pyvmomiHistoricalData.filter(dp => dp.time > 0) : [];
      res.json(formattedMetrics); // Return the data directly
    
    } else {
      res.status(400).json({ error: `Historical metrics not implemented for hypervisor type ${targetHypervisor?.type} or required details missing.` });
    }
  } catch (error) {
    console.error(`Error fetching historical metrics for VM ${vmExternalId}:`, error);
    let errorDetails;
    // Check if the error is likely from callPyvmomiService (it adds a 'status' property)
    if (error.status) {
        errorDetails = { code: error.status, message: error.details?.error || error.message || `Failed to retrieve historical metrics via PyVmomi for ${vmExternalId}` };
    } else if (targetHypervisor?.type === 'proxmox') {
        errorDetails = getProxmoxError(error); // Use existing Proxmox error handler
    } else {
        errorDetails = { code: 500, message: error.message || `Failed to retrieve historical metrics for VM ${vmExternalId}` }; // Generic fallback
    }
    res.status(errorDetails.code || 500).json({ error: 'Failed to retrieve historical metrics.', details: errorDetails.message, suggestion: errorDetails.suggestion });
   }
});

// Helper function to get authenticated proxmox client (kept for Proxmox logic)
async function getProxmoxClient(hypervisorId) {
  const { rows: [hypervisor] } = await pool.query(
    `SELECT id, type, host, username, api_token, token_name, status
     FROM hypervisors WHERE id = $1`,
    [hypervisorId]
  );

  if (!hypervisor) throw new Error('Hypervisor not found');
  if (hypervisor.status !== 'connected') throw new Error('Hypervisor not connected');
  if (hypervisor.type !== 'proxmox') throw new Error('Not a Proxmox hypervisor');

  const [dbHost, dbPortStr] = hypervisor.host.split(':');
  const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
  const cleanHost = dbHost;

  const proxmoxConfig = {
    host: cleanHost, port: port, username: hypervisor.username,
    tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
    tokenSecret: hypervisor.api_token, timeout: 10000, rejectUnauthorized: false
  };
  return proxmoxApi(proxmoxConfig);
}

// GET /api/hypervisors/:id/nodes
app.get('/api/hypervisors/:id/nodes', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: [hypervisorInfo] } = await pool.query(
      'SELECT id, type, name, status, host, username, password, api_token, token_name, vsphere_subtype FROM hypervisors WHERE id = $1',
      [id]
    );

    if (!hypervisorInfo) return res.status(404).json({ error: 'Hypervisor not found.' });
    if (hypervisorInfo.status !== 'connected') return res.status(409).json({ error: `Hypervisor ${hypervisorInfo.name} not connected.` });

    let formattedNodes = [];

    if (hypervisorInfo.type === 'proxmox') {
      // ... (Proxmox nodes logic - Mantenida como estaba)
      const proxmox = await getProxmoxClient(id);
      const nodes = await proxmox.nodes.$get();
      formattedNodes = await Promise.all(nodes.map(async (node) => {
        const nodeStatus = await proxmox.nodes.$(node.node).status.$get();
        const totalLogicalCpus = (nodeStatus.cpuinfo?.cores || 0) * (nodeStatus.cpuinfo?.sockets || 1);
        return {
          id: node.node, name: node.node, status: node.status,
          cpu: { cores: totalLogicalCpus, usage: nodeStatus.cpu || 0 },
          memory: { total: nodeStatus.memory?.total || 0, used: nodeStatus.memory?.used || 0, free: nodeStatus.memory?.free || 0, },
          rootfs: nodeStatus.rootfs ? { total: nodeStatus.rootfs.total || 0, used: nodeStatus.rootfs.used || 0, } : undefined,
        };
      }));
    } else if (hypervisorInfo.type === 'vsphere') {
     // console.log(`Fetching vSphere nodes for hypervisor ${id} via PyVmomi microservice`);
      // TODO: PYVMOMI: Implement '/hosts' endpoint in app.py
      // This endpoint should list ESXi hosts (if vCenter) or the single ESXi host.
      // It should return details like name, status, CPU (cores, usage), memory (total, used).
      try {
        const pyvmomiHosts = await callPyvmomiService('GET', '/hosts', hypervisorInfo);
        if (Array.isArray(pyvmomiHosts)) {
          formattedNodes = pyvmomiHosts.map(host => ({
            id: host.moid || host.name, // Use MOID if available, else name
            name: host.name,
            // Determine status based on connection, power, and overall health
            status: (host.connection_state === 'connected' && host.power_state === 'poweredOn')
                      ? (host.overall_status === 'green' ? 'online' : (host.overall_status === 'yellow' || host.overall_status === 'red' ? 'warning' : 'unknown'))
                      : 'offline',
            cpu: {
              cores: host.cpu_cores || 0,
              usage: (host.cpu_usage_percent || 0) / 100, // Convert percentage from Python (0-100) to fraction (0-1)
            },
            memory: {
              total: host.memory_total_bytes || 0,
              used: host.memory_used_bytes || 0,
              free: (host.memory_total_bytes || 0) - (host.memory_used_bytes || 0),
            },
            vmCount: host.vm_count, // Added from Python microservice
            powerState: host.power_state, // Added from Python microservice
            connectionState: host.connection_state, // Added from Python microservice
            // storage: PyVmomi microservice would need to aggregate datastore info per host if desired here
          }));
        } else {
          console.warn("PyVmomi /hosts did not return an array:", pyvmomiHosts);
        }
      } catch (pyVmomiError) {
        console.error(`Error fetching vSphere nodes via PyVmomi for ${id}:`, pyVmomiError.details?.error || pyVmomiError.message);
        // Fallback or error response
        return res.status(pyVmomiError.status || 500).json({ error: 'Failed to retrieve vSphere nodes via PyVmomi', details: pyVmomiError.details?.error || pyVmomiError.message });
      }
    } else {
      return res.status(400).json({ error: `Unsupported hypervisor type: ${hypervisorInfo.type}` });
    }
    res.json(formattedNodes);
  } catch (error) {
    console.error(`Error fetching nodes for hypervisor ${id}:`, error.message);
    res.status(500).json({ error: 'Failed to retrieve nodes', details: error.message });
  }
});

//Get the hypervisor info from the request body
app.get('/api/hypervisors/:id/storage', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: [hypervisorInfo] } = await pool.query(
      'SELECT id, name, type, status, host, username, password, api_token, token_name, vsphere_subtype FROM hypervisors WHERE id = $1',
      [id]
    );

    if (!hypervisorInfo) return res.status(404).json({ error: 'Hypervisor not found.' });
    if (hypervisorInfo.status !== 'connected') return res.status(409).json({ error: `Hypervisor ${hypervisorInfo.name} not connected.` });

    let formattedStorage = [];

    if (hypervisorInfo.type === 'proxmox') {
      const proxmox = await getProxmoxClient(id);
      const nodes = await proxmox.nodes.$get().catch(e => {
        console.error(`Proxmox nodes fetch error for storage list on hypervisor ${id}: ${e.message}`);
        return [];
      });

      const primaryNodeName = nodes.length > 0 ? nodes[0].node : null;

      if (!primaryNodeName) {
        console.warn(`Hypervisor ${id} (Proxmox) - No nodes found for storage details. Storage list will be basic.`);
        // Fallback to basic storage list if no node is available
        const basicStorageList = await proxmox.storage.$get().catch(() => []);
        formattedStorage = basicStorageList.map(s => ({
          id: s.storage, name: s.storage, type: s.type,
          size: 0, used: 0, available: 0, // No detailed info
          path: s.path, content: s.content,
        }));
      } else {
        const storageListFromApi = await proxmox.storage.$get().catch(() => []);
        formattedStorage = await Promise.all(storageListFromApi.map(async (s) => {
          try {
            const storageStatus = await proxmox.nodes.$(primaryNodeName).storage.$(s.storage).status.$get();
            return {
              id: s.storage, name: s.storage, type: s.type,
              size: storageStatus.total || 0, used: storageStatus.used || 0, available: storageStatus.avail || 0,
              path: s.path, content: s.content,
            };
          } catch (statusError) {
            console.warn(`Error fetching status for storage ${s.storage} on node ${primaryNodeName} (for /storage endpoint): ${statusError.message}`);
            return { id: s.storage, name: s.storage, type: s.type, size: 0, used: 0, available: 0, path: s.path, content: s.content, error: "Failed to get status" };
          }
        }));
      }
    } else if (hypervisorInfo.type === 'vsphere') {
     // console.log(`Fetching vSphere storage (datastores) for ${id} via PyVmomi microservice`);
      // TODO: PYVMOMI: Implement '/datastores' endpoint in app.py
      // This endpoint should list all datastores with name, type, capacity, free_space.
      try {
        const pyvmomiDatastores = await callPyvmomiService('GET', '/datastores', hypervisorInfo);
        if (Array.isArray(pyvmomiDatastores)) {
          formattedStorage = pyvmomiDatastores.map(ds => ({
            id: ds.moid || ds.name, // Use MOID if available
            name: ds.name,
            type: ds.type, // e.g., "VMFS", "NFS"
            size: ds.capacity_bytes || 0,
            used: (ds.capacity_bytes || 0) - (ds.free_space_bytes || 0),
            available: ds.free_space_bytes || 0,
            path: null, // Not typically relevant for vSphere datastores
          }));
        } else {
            console.warn("PyVmomi /datastores did not return an array:", pyvmomiDatastores);
        }
      } catch (pyVmomiError) {
        console.error(`Error fetching vSphere datastores via PyVmomi for ${id}:`, pyVmomiError.details?.error || pyVmomiError.message);
        return res.status(pyVmomiError.status || 500).json({ error: 'Failed to retrieve vSphere datastores via PyVmomi', details: pyVmomiError.details?.error || pyVmomiError.message });
      }
    } else {
      return res.status(400).json({ error: `Unsupported hypervisor type: ${hypervisorInfo.type}` });
    }
    res.json(formattedStorage);
  } catch (error) {
    console.error(`Error fetching storage for hypervisor ${id}:`, error);
    res.status(500).json({ error: 'Failed to retrieve storage', details: error.message });
  }
});

// Helper function to fetch VM Templates from vSphere (now via PyVmomi)
async function fetchVSphereVMTemplates(hypervisor) { // Pass full hypervisor object
  //console.log(`vSphere Templates: Fetching VM templates for ${hypervisor.id} via PyVmomi`);
  // TODO: PYVMOMI: Implement '/templates' endpoint in app.py
  // This endpoint should list VMs marked as templates, returning name, uuid, disk size, etc.
  try {
    const pyvmomiTemplates = await callPyvmomiService('GET', '/templates', hypervisor);
    if (Array.isArray(pyvmomiTemplates)) {
      return pyvmomiTemplates.map(tmpl => ({
        id: tmpl.uuid, // PyVmomi should return UUID
        name: tmpl.name,
        description: `vSphere VM Template: ${tmpl.name}`,
        size: tmpl.disk_capacity_bytes || 0, // Example, adapt to actual PyVmomi response
        path: tmpl.uuid, // Use UUID as path identifier
        type: 'template',
        storage: tmpl.datastore_name || 'vSphere Managed',
      }));
    }
    console.warn("PyVmomi /templates did not return an array:", pyvmomiTemplates);
    return [];
  } catch (error) {
    console.error(`vSphere Templates: Error fetching VM templates via PyVmomi for ${hypervisor.id}:`, error.details?.error || error.message);
    return [];
  }
}

// Helper function to fetch ISO files from vSphere datastores (now via PyVmomi)
async function fetchVSphereIsoFiles(hypervisor) { // Pass full hypervisor object
  //console.log(`vSphere ISOs: Fetching ISO files for ${hypervisor.id} via PyVmomi`);
  // TODO: PYVMOMI: Implement '/isos' endpoint in app.py
  // This endpoint should browse datastores for .iso files, returning name, path, size, datastore.
  try {
    const pyvmomiIsos = await callPyvmomiService('GET', '/isos', hypervisor);
    if (Array.isArray(pyvmomiIsos)) {
      return pyvmomiIsos.map(iso => {
        const sizeInGb = iso.size_bytes ? parseFloat((iso.size_bytes / (1024 * 1024 * 1024)).toFixed(2)) : 0;
        return {
        id: `${iso.datastore_moid || iso.datastore_name}:${iso.path}`, // Unique ID
        name: iso.name,
        description: `ISO file from datastore ${iso.datastore_name}`,
        size: sizeInGb, // Converted to GB
        // path: iso.path, // 'path' is not in VMTemplate, id now contains full path info
        // type: 'iso', // 'type' is not in VMTemplate
        // storage: iso.datastore_name, // 'storage' is not in VMTemplate

        // Fields required by VMTemplate:
        hypervisorType: 'vsphere',
        os: 'otherGuest64', // Ensure this is a string literal
        specs: { // Default specs for an ISO "template"
          cpu: 1,
          memory: 1024, // MB
          disk: 20, // GB (default disk size for a new VM using this ISO)
        },
        osVersion: undefined, // Or try to infer from iso.name if possible
        };
      });
    }
    console.warn("PyVmomi /isos did not return an array:", pyvmomiIsos);
    return [];
  } catch (error) {
    // More detailed error logging to help pinpoint future issues
    console.error(`[DEBUG] Caught error in fetchVSphereIsoFiles for ${hypervisor.id}:`);
    console.error("[DEBUG] error.message:", error.message);
    console.error("[DEBUG] error.details:", error.details);
    console.error("[DEBUG] error.stack:", error.stack);
    return [];
  }
}

// GET /api/hypervisors/:id/templates
app.get('/api/hypervisors/:id/templates', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: [hypervisorInfo] } = await pool.query(
      'SELECT id, name, type, status, host, username, password, api_token, token_name, vsphere_subtype FROM hypervisors WHERE id = $1',
      [id]
    );

    if (!hypervisorInfo) return res.status(404).json({ error: 'Hypervisor not found.' });
    if (hypervisorInfo.status !== 'connected') return res.status(409).json({ error: `Hypervisor ${hypervisorInfo.name} not connected.` });

    let allTemplates = [];

    if (hypervisorInfo.type === 'proxmox') {
      // ... (Proxmox templates logic - Mantenida como estaba)
      const proxmox = await getProxmoxClient(id);
      allTemplates = await fetchProxmoxTemplates(proxmox); // Uses original Proxmox helper
    } else if (hypervisorInfo.type === 'vsphere') {
      //console.log(`Fetching vSphere templates and ISOs for ${id} via PyVmomi microservice`);
      const vmTemplates = await fetchVSphereVMTemplates(hypervisorInfo); // Pass full hypervisor object
      const isoFiles = await fetchVSphereIsoFiles(hypervisorInfo); // Pass full hypervisor object
      allTemplates = vmTemplates.concat(isoFiles);
      //console.log(`Fetched ${allTemplates.length} vSphere templates/ISOs for ${id} via PyVmomi`);
    } else {
      return res.status(400).json({ error: `Unsupported hypervisor type: ${hypervisorInfo.type}` });
    }
    res.json(allTemplates);
  } catch (error) {
    console.error(`Error fetching templates for hypervisor ${id}:`, error);
    res.status(500).json({ error: 'Failed to retrieve templates', details: error.message });
  }
});


// GET /api/hypervisors - List all hypervisors
app.get('/api/hypervisors', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, type, host, username, status, last_sync, vsphere_subtype, created_at, updated_at FROM hypervisors ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching hypervisors from DB:', err);
    res.status(500).json({ error: 'Failed to retrieve hypervisors' });
  }
});

// POST /api/hypervisors - Create new hypervisor
app.post('/api/hypervisors', authenticate, requireAdmin, async (req, res) => {
  const { host, username, password, apiToken, tokenName, type, vsphere_subtype: clientVsphereSubtype } = req.body; // clientVsphereSubtype for explicit setting

  const validationErrors = [];
  if (!type) validationErrors.push('Type is required');
  if (!host) validationErrors.push('Host is required');
  if (!username) validationErrors.push('Username is required');

  if (type === 'proxmox') {
      const hasToken = apiToken && tokenName;
      const hasPassword = !!password;
      if (!hasToken && !hasPassword) validationErrors.push('Proxmox requires either password or API token + token name');
      if (apiToken && !tokenName) validationErrors.push('Token name is required when using API token');
      if (tokenName && !apiToken) validationErrors.push('API token secret is required when using token name');
      // Updated Proxmox host validation to allow hostname without protocol, https will be prepended by default.
      if (!/^[\w.-]+(:\d+)?$/.test(host) && !/^https?:\/\/[\w.-]+(:\d+)?$/.test(host)) {
        validationErrors.push('Invalid Proxmox host format. Use hostname[:port] or http(s)://hostname[:port]');
      }
  } else if (type === 'vsphere') {
      if (!password) validationErrors.push('Password is required for vSphere connection');
      if (!/^[\w.-]+(:\d+)?$/.test(host) && !/^https?:\/\/[\w.-]+(:\d+)?$/.test(host)) {
          validationErrors.push('Invalid vSphere host format. Use hostname or https://hostname[:port]');
      }
  }

  if (validationErrors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: validationErrors });
  }

  let status = 'disconnected';
  let last_sync = null;
  let cleanHost = host;
  const name = host.replace(/^https?:\/\//, '').split(/[/:]/)[0].replace(/[^\w-]/g, '-').substring(0, 50);
  let determinedVsphereSubtype = clientVsphereSubtype || null; // Use provided subtype or determine later

  try {
    if (type === 'proxmox') {
      // ... (Proxmox connection logic - Mantenida como estaba)
      const urlParts = new URL(host.includes('://') ? host : `https://${host}`);
      cleanHost = urlParts.hostname;
      const port = urlParts.port || 8006;
      const proxmoxConfig = {
          host: cleanHost, port: port, username: username,
          timeout: 15000, rejectUnauthorized: false,
      };
      if (apiToken && tokenName) {
          proxmoxConfig.tokenID = `${username}!${tokenName}`;
          proxmoxConfig.tokenSecret = apiToken;
      } else {
          proxmoxConfig.password = password;
      }
      const proxmox = proxmoxApi(proxmoxConfig);
      const nodesResponse = await proxmox.nodes.$get();
      if (!nodesResponse?.length) throw new Error('No nodes found in Proxmox cluster');
      const nodeName = nodesResponse[0].node;
      const versionResponse = await proxmox.nodes.$(nodeName).version.$get();
      if (!versionResponse?.version) throw new Error('Invalid Proxmox version response');
      status = 'connected';
      last_sync = new Date();
      console.log(`Connected to Proxmox ${versionResponse.version} at ${cleanHost}:${port}`);
    } else if (type === 'vsphere') {
      //console.log(`Attempting vSphere connection to: ${host} with user: ${username} via PyVmomi microservice`);
      // For vSphere, we now use the PyVmomi microservice to test connection.
      // The microservice's /connect endpoint should attempt SmartConnect.
      // It should also try to determine if it's vCenter or ESXi if possible.
      const hypervisorDataForPyvmomi = { host, username, password: password, type, vsphere_subtype: clientVsphereSubtype }; // Usar campo 'password'
      
            try {
        const connectResponse = await callPyvmomiService('POST', '/connect', hypervisorDataForPyvmomi, {
            // Pass any specific parameters needed by the /connect endpoint if any, besides credentials
        });
        
        status = 'connected'; // If callPyvmomiService doesn't throw, connection is successful
        last_sync = new Date();
        determinedVsphereSubtype = connectResponse.vsphere_subtype || clientVsphereSubtype || 'esxi'; // Prefer subtype from microservice
       // console.log(`Successfully connected to vSphere via PyVmomi. Response:`, connectResponse);
        cleanHost = host.split(':')[0]; // Store clean host
      } catch (pyVmomiConnectError) {
        console.error(`vSphere connection via PyVmomi failed for ${host}:`, pyVmomiConnectError.details?.error || pyVmomiConnectError.message);
        status = 'error';
        // Re-throw to be caught by the main error handler for this route
        throw new Error(`vSphere connection via PyVmomi microservice failed: ${pyVmomiConnectError.details?.error || pyVmomiConnectError.message}`);
      }
    }

    const dbResult = await pool.query(
        `INSERT INTO hypervisors (name, type, host, username, password, api_token, token_name, vsphere_subtype, status, last_sync)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, name, type, host, username, vsphere_subtype, status, last_sync, created_at`,
        [
            name, type,
            type === 'proxmox' ? `${cleanHost}:${(new URL(host.includes('://') ? host : `https://${host}`)).port || 8006}` : cleanHost, // Store Proxmox with port
            username,
            password || null, // Store password (for Proxmox or vSphere if provided)
            (type === 'proxmox' ? (apiToken || null) : null), // api_token specifically for Proxmox
            (type === 'proxmox' ? (tokenName || null) : null),
            determinedVsphereSubtype,
            status, last_sync
        ]
    );
    const responseData = dbResult.rows[0];

    // Password is now directly inserted for both Proxmox and vSphere if provided.
     res.status(201).json(responseData);

  } catch (error) {
    console.error('Error creating hypervisor:', error);
    const errorInfo = { code: 500, message: error.message || 'Hypervisor connection error', suggestion: 'Check connection details and credentials' };
    if (error.status) errorInfo.code = error.status; // Use status from PyVmomi error if available
    if (type === 'proxmox' && error.response) { /* Proxmox specific error handling */ }
    
    res.status(errorInfo.code).json(errorInfo);
  }
});


// GET /api/hypervisors/:id - Get a single hypervisor by ID
app.get('/api/hypervisors/:id', authenticate, async (req, res) => {
  const { id } = req.params;
 // console.log(`GET /api/hypervisors/${id} called`);
  try {
    const { rows: [hypervisor] } = await pool.query(
      'SELECT id, name, type, host, username, password, token_name, api_token, status, last_sync, vsphere_subtype, created_at, updated_at FROM hypervisors WHERE id = $1',
      [id]
    );

    if (!hypervisor) return res.status(404).json({ error: 'Hypervisor not found' });

    if (hypervisor.status === 'connected') {
      if (hypervisor.type === 'proxmox') {
        //console.log(`Hypervisor ${id} (Proxmox) is connected, fetching details...`);
        try {
          const proxmox = await getProxmoxClient(hypervisor.id); // Ensure this gets a client with correct credentials
          const nodesData = await proxmox.nodes.$get().catch(e => {
            console.error(`Proxmox nodes fetch error for ${id}: ${e.message}`);
            return [];
          });
          
          if (!nodesData || nodesData.length === 0) {
            console.warn(`Hypervisor ${id} (Proxmox) - No nodes found. Storage details will be incomplete.`);
            hypervisor.nodes = [];
            hypervisor.storage = [];
          }

          const primaryNodeName = nodesData.length > 0 ? nodesData[0].node : null;

          // Fetch storage list, templates, and VM plans concurrently
          const [actualStorageList, templatesData, vmPlansDataResult] = await Promise.all([
            proxmox.storage.$get().catch(e => { // This fetches the list of storages
              console.error(`Proxmox storage list fetch error for ${id}: ${e.message}`);
              return [];
            }),
            fetchProxmoxTemplates(proxmox).catch(e => { console.error(`Proxmox templates fetch error for ${id}: ${e.message}`); return []; }),
            pool.query('SELECT id, name, specs FROM vm_plans WHERE is_active = true').catch(e => { console.error(`DB vm_plans fetch error: ${e.message}`); return { rows: [] }; })
          ]);

          //console.log(`Hypervisor ${id} (Proxmox) - Raw Storage List from API:`, JSON.stringify(actualStorageList, null, 2));

          // Mapear y enriquecer los datos de almacenamiento con detalles de estado por nodo
          hypervisor.storage = [];
          if (primaryNodeName && Array.isArray(actualStorageList)) {
            hypervisor.storage = await Promise.all(actualStorageList.map(async (s) => {
              try {
                // s.storage should be the ID of the storage
                const storageStatus = await proxmox.nodes.$(primaryNodeName).storage.$(s.storage).status.$get();
                return {
                  id: s.storage, name: s.storage, type: s.type,
                  size: storageStatus.total || 0, used: storageStatus.used || 0, available: storageStatus.avail || 0,
                  path: s.path, // path comes from the general storage list
                  content: s.content, // content also comes from the general list
                };
              } catch (statusError) {
                console.warn(`Error fetching status for storage ${s.storage} on node ${primaryNodeName}: ${statusError.message}`);
                return { id: s.storage, name: s.storage, type: s.type, size: 0, used: 0, available: 0, path: s.path, content: s.content, error: "Failed to get status" };
              }
            }));
          }

          // Calcular el espacio total disponible en disco para VMs en Proxmox (en GB)
          let totalAvailableDiskSpaceForVmsGB_Proxmox = 0;
          hypervisor.storage.forEach(s => {
            // Asegurarse que 's.content' exista y sea un string antes de llamar a 'includes'
            if (s.content && typeof s.content === 'string' && s.content.includes('images') && s.available) {
              totalAvailableDiskSpaceForVmsGB_Proxmox += (s.available / (1024 * 1024 * 1024)); // Convertir bytes a GB
            }
          });
        //  console.log(`Hypervisor ${id} (Proxmox) - Total available disk space for VMs (GB): ${totalAvailableDiskSpaceForVmsGB_Proxmox.toFixed(2)}`);

          hypervisor.templates = templatesData; // Already formatted by fetchProxmoxTemplates

          // Fetch detailed status for each node for Proxmox
          hypervisor.nodes = await Promise.all(nodesData.map(async (node) => {
            try {
              const nodeStatus = await proxmox.nodes.$(node.node).status.$get();
              const totalLogicalCpus = (nodeStatus.cpuinfo?.cores || 1) * (nodeStatus.cpuinfo?.sockets || 1); // Ensure cores/sockets are at least 1 to avoid 0
              
              // Plan capacity estimation for this node
              // Ensure vmPlansDataResult and vmPlansDataResult.rows are valid
              const planRows = vmPlansDataResult && Array.isArray(vmPlansDataResult.rows) ? vmPlansDataResult.rows : [];
              const planCapacityEstimates = planRows.map(plan => {
                const planSpecs = typeof plan.specs === 'string' ? JSON.parse(plan.specs) : plan.specs;
                let estimatedCount = 0;
                
                // Check if nodeStatus.memory is defined before accessing its properties
                if (planSpecs && planSpecs.cpu > 0 && planSpecs.memory > 0 && nodeStatus.memory && nodeStatus.memory.free > 0 && totalLogicalCpus > 0) {
                  const cpuAvailableForEstimation = totalLogicalCpus * (1 - (nodeStatus.cpu || 0)); // Available CPU capacity (fraction * cores)
                  const memoryAvailableForEstimationMB = (nodeStatus.memory.free / (1024 * 1024)); // Available memory in MB

                  const vmsByCpu = Math.floor(cpuAvailableForEstimation / planSpecs.cpu);
                  const vmsByMemory = Math.floor(memoryAvailableForEstimationMB / planSpecs.memory);

                  let vmsByDisk = Infinity;
                  if (planSpecs.disk && planSpecs.disk > 0) {
                    if (totalAvailableDiskSpaceForVmsGB_Proxmox > 0) {
                      vmsByDisk = Math.floor(totalAvailableDiskSpaceForVmsGB_Proxmox / planSpecs.disk);
                    } else {
                      vmsByDisk = 0; // No hay espacio en disco, no se pueden crear VMs que requieran disco
                    }
                  }
                  estimatedCount = Math.min(vmsByCpu, vmsByMemory, vmsByDisk);
                }
                return {
                  planId: plan.id,
                  planName: plan.name,
                  estimatedCount: Math.max(0, estimatedCount), // Ensure non-negative
                  specs: planSpecs,
                };
              });

              return {
                id: node.node, name: node.node, status: node.status === 'online' ? 'online' : 'offline',
                cpu: { cores: totalLogicalCpus, usage: nodeStatus.cpu || 0 },
                memory: nodeStatus.memory ? { // Check if nodeStatus.memory is defined
                  total: nodeStatus.memory?.total || 0,
                  used: nodeStatus.memory?.used || 0,
                  free: nodeStatus.memory?.free || 0,
                } : undefined, // Set to undefined if nodeStatus.memory is not available
                rootfs: nodeStatus.rootfs ? {
                  total: nodeStatus.rootfs.total || 0,
                  used: nodeStatus.rootfs.used || 0,
                } : undefined,
                planCapacityEstimates,
                // physicalDisks would require additional calls, e.g., smartctl or lshw on node if API exposed it
              };
            } catch (nodeDetailError) {
              console.error(`Error fetching details for Proxmox node ${node.node}: ${nodeDetailError.message}`);
              return { id: node.node, name: node.node, status: 'unknown', cpu: undefined, memory: undefined, planCapacityEstimates: [] };
            }
          }));

          // Calculate AggregatedStats for Proxmox
          let totalCores = 0;
          let totalCpuUsageSum = 0; // Sum of (usage * cores)
          let totalMemoryBytes = 0;
          let usedMemoryBytes = 0;

          hypervisor.nodes.forEach(node => {
            if (node.cpu && node.cpu.cores) { // Ensure node.cpu and node.cpu.cores exist
              totalCores += node.cpu.cores;
              totalCpuUsageSum += (node.cpu.usage * node.cpu.cores);
            }
            if (node.memory && node.memory.total) { // Ensure node.memory and node.memory.total exist
              totalMemoryBytes += node.memory.total;
              usedMemoryBytes += node.memory.used;
            }
          });
          const avgCpuUsagePercent = totalCores > 0 ? (totalCpuUsageSum / totalCores) * 100 : 0;

          let totalDiskBytesAgg = 0;
          let usedDiskBytesAgg = 0;
          hypervisor.storage.forEach(s => {
            totalDiskBytesAgg += s.size;
            usedDiskBytesAgg += s.used;
          });

          hypervisor.aggregatedStats = {
            totalCores, avgCpuUsagePercent, totalMemoryBytes, usedMemoryBytes,
            totalDiskBytes: totalDiskBytesAgg, usedDiskBytes: usedDiskBytesAgg,
            storagePoolCount: hypervisor.storage?.length || 0,
          };

        } catch (detailError) {
            console.error(`Failed to fetch Proxmox details for connected hypervisor ${id}:`, detailError);
            hypervisor.detailsError = detailError.message || 'Failed to load Proxmox details';
        }
      } else if (hypervisor.type === 'vsphere') {
       // console.log(`Hypervisor ${id} (vSphere) is connected, fetching details via PyVmomi...`);
        try {

          // Fetch Nodes, Storage, Templates, ISOs, and VM Plans in parallel
          const [pyvmomiNodes, pyvmomiStorage, vmTemplatesPy, isoFilesPy, vmPlansData] = await Promise.all([
            callPyvmomiService('GET', '/hosts', hypervisor).catch(e => { console.error(`PyVmomi /hosts error: ${e.message}`); return []; }), // vmPlansData was incorrectly named here
            callPyvmomiService('GET', '/datastores', hypervisor).catch(e => { console.error(`PyVmomi /datastores error: ${e.message}`); return []; }),
            fetchVSphereVMTemplates(hypervisor).catch(e => { console.error(`PyVmomi /templates error: ${e.message}`); return []; }),
            fetchVSphereIsoFiles(hypervisor).catch(e => { console.error(`PyVmomi /isos error: ${e.message}`); return []; }),
            pool.query('SELECT id, name, specs FROM vm_plans WHERE is_active = true').catch(e => { console.error(`DB vm_plans fetch error: ${e.message}`); return { rows: [] }; })
          ]);

          // Calcular el espacio total disponible en disco para VMs en vSphere (en GB)
          let totalAvailableDiskSpaceForVmsGB_vSphere = 0;
          if (Array.isArray(pyvmomiStorage)) {
            pyvmomiStorage.forEach(ds => {
              const availableSpaceBytes = ds.free_space_bytes || ds.available || 0;
              if (availableSpaceBytes > 0) {
                totalAvailableDiskSpaceForVmsGB_vSphere += (availableSpaceBytes / (1024 * 1024 * 1024)); // Convertir bytes a GB
              }
            });
           // console.log(`Hypervisor ${id} (vSphere) - Total available disk space for VMs (GB): ${totalAvailableDiskSpaceForVmsGB_vSphere.toFixed(2)}`);
          }

          if (Array.isArray(pyvmomiNodes)) {
            hypervisor.nodes = pyvmomiNodes.map(host => {
              const planRows = vmPlansData && Array.isArray(vmPlansData.rows) ? vmPlansData.rows : [];
              const planCapacityEstimates = planRows.map(plan => {
                const planSpecs = typeof plan.specs === 'string' ? JSON.parse(plan.specs) : plan.specs;
                let estimatedCount = 0;

                const hostCpuCores = host.cpu_cores || 0;
                const hostCpuUsageFraction = (host.cpu_usage_percent || 0) / 100;
                const hostMemoryTotalBytes = host.memory_total_bytes || 0;
                const hostMemoryUsedBytes = host.memory_used_bytes || 0;
                const hostMemoryFreeBytes = hostMemoryTotalBytes - hostMemoryUsedBytes;
                
                
                if (planSpecs && planSpecs.cpu > 0 && planSpecs.memory > 0 && hostMemoryFreeBytes > 0 && hostCpuCores > 0) {
                  const cpuAvailableForEstimation = hostCpuCores * (1 - hostCpuUsageFraction);
                  const memoryAvailableForEstimationMB = hostMemoryFreeBytes / (1024 * 1024);

                  const vmsByCpu = Math.floor(cpuAvailableForEstimation / planSpecs.cpu);
                  const vmsByMemory = Math.floor(memoryAvailableForEstimationMB / planSpecs.memory);

                  let vmsByDisk = Infinity;
                  if (planSpecs.disk && planSpecs.disk > 0) {
                    if (totalAvailableDiskSpaceForVmsGB_vSphere > 0) {
                      vmsByDisk = Math.floor(totalAvailableDiskSpaceForVmsGB_vSphere / planSpecs.disk);
                    } else {
                      vmsByDisk = 0; // No hay espacio en disco
                    }
                  }
                  estimatedCount = Math.min(vmsByCpu, vmsByMemory, vmsByDisk);
                }
                return {
                  planId: plan.id,
                  planName: plan.name,
                  estimatedCount: Math.max(0, estimatedCount),
                  specs: planSpecs,
                };
              });

              return {
                id: host.moid || host.name,
                name: host.name,
                status: (host.connection_state === 'connected' && host.power_state === 'poweredOn')
                          ? (host.overall_status === 'green' ? 'online' : (host.overall_status === 'yellow' || host.overall_status === 'red' ? 'warning' : 'unknown'))
                          : 'offline',
                cpu: { cores: host.cpu_cores || 1, usage: (host.cpu_usage_percent || 0) / 100 }, // Ensure cores is at least 1
                memory: { 
                    total: host.memory_total_bytes || 0, 
                    used: host.memory_used_bytes || 0, 
                    free: (host.memory_total_bytes || 0) - (host.memory_used_bytes || 0) 
                },
                vmCount: host.vm_count,
                powerState: host.power_state,
                connectionState: host.connection_state,
                planCapacityEstimates, // Add calculated estimates
              };
            });
          } else {
            hypervisor.nodes = [];
          }
          hypervisor.storage = Array.isArray(pyvmomiStorage) ? pyvmomiStorage.map(ds => ({
            id: ds.moid || ds.name,
            name: ds.name,
            type: ds.type,
            size: ds.capacity_bytes || 0,
            used: (ds.capacity_bytes || 0) - (ds.free_space_bytes || 0),
            available: ds.free_space_bytes || 0,
            path: null, // Not typically relevant for vSphere datastores
          })) : [];

          hypervisor.templates = vmTemplatesPy.concat(isoFilesPy);

         // console.log(`Fetched vSphere details for ${id} via PyVmomi: ${hypervisor.nodes?.length || 0} nodes, ${hypervisor.storage?.length || 0} storage, ${hypervisor.templates?.length || 0} templates/ISOs`);
          
          // Calculate AggregatedStats for vSphere
          if (hypervisor.nodes && hypervisor.nodes.length > 0) {
            let totalCores = 0;
            let totalCpuUsageSum = 0; // Sum of (usage * cores) to average later
            let totalMemoryBytes = 0;
            let usedMemoryBytes = 0;

            hypervisor.nodes.forEach(node => {
              if (node.cpu && node.cpu.cores) { // Ensure node.cpu and node.cpu.cores exist
                totalCores += node.cpu.cores;
                totalCpuUsageSum += (node.cpu.usage * node.cpu.cores); // Weighted sum for accurate averaging
              }
              if (node.memory && node.memory.total) { // Ensure node.memory and node.memory.total exist
                totalMemoryBytes += node.memory.total;
                usedMemoryBytes += node.memory.used;
              }
            });
            
            const avgCpuUsagePercent = totalCores > 0 ? (totalCpuUsageSum / totalCores) * 100 : 0;

            let totalDiskBytesAgg = 0;
            let usedDiskBytesAgg = 0;
            if (hypervisor.storage && hypervisor.storage.length > 0) {
              hypervisor.storage.forEach(s => {
                totalDiskBytesAgg += s.size;
                usedDiskBytesAgg += s.used;
              });
            }

            hypervisor.aggregatedStats = {
              totalCores, avgCpuUsagePercent, totalMemoryBytes, usedMemoryBytes,
              totalDiskBytes: totalDiskBytesAgg, usedDiskBytes: usedDiskBytesAgg,
              storagePoolCount: hypervisor.storage?.length || 0,
            };
          }
        } catch (detailError) {
          console.error(`Failed to fetch vSphere details via PyVmomi for ${id}:`, detailError);
          hypervisor.detailsError = detailError.message || 'Failed to load vSphere details via PyVmomi';
        }
      }
    }

    delete hypervisor.api_token;
    res.json(hypervisor);

  } catch (err) {
    console.error(`Error fetching hypervisor ${id}:`, err);
    res.status(500).json({ error: 'Failed to retrieve hypervisor' });
  }
});

// Helper function to fetch Proxmox templates (Mantenida como estaba)
async function fetchProxmoxTemplates(proxmox) {
  let allTemplatesMap = new Map();
  const nodes = await proxmox.nodes.$get();
  for (const node of nodes) {
    try {
      const storageList = await proxmox.nodes.$(node.node).storage.$get();
      for (const storage of storageList) {
        if (storage.content.includes('iso') || storage.content.includes('vztmpl') || storage.content.includes('template')) {
          const content = await proxmox.nodes.$(node.node).storage.$(storage.storage).content.$get();
          content
            .filter(item => item.content === 'iso' || item.content === 'vztmpl' || item.template === 1)
            .forEach(item => {
              const templateId = item.volid;
              if (!allTemplatesMap.has(templateId)) {
                allTemplatesMap.set(templateId, {
                  id: templateId, name: item.volid.split('/')[1] || item.volid,
                  description: item.volid, size: item.size, path: item.volid,
                  type: item.content === 'iso' ? 'iso' : (item.template === 1 ? 'template' : 'vztmpl'),
                  version: item.format, storage: storage.storage,
                });
              }
            });
        }
      }
    } catch (nodeError) {
        console.error(`Error fetching storage/content for Proxmox node ${node.node}: ${nodeError.message}`);
    }
  }
  return Array.from(allTemplatesMap.values());
}

// Función de manejo de errores de Proxmox (Mantenida como estaba)
function getProxmoxError(error) {
  const response = { message: 'Proxmox API Error', code: 500, suggestion: 'Check network connection and credentials' };
  if (error.response) {
      response.code = error.response.status;
      if (error.response.data?.errors) response.message = error.response.data.errors.map(err => err.message || err).join(', ');
      if (response.code === 401) { response.message = 'Authentication failed'; response.suggestion = 'Verify credentials/token permissions'; }
      if (response.code === 403) { response.message = 'Permission denied'; response.suggestion = 'Check user role privileges'; }
      if (response.code === 595) { response.message = 'SSL certificate verification failed'; response.suggestion = process.env.NODE_ENV === 'production' ? 'Use valid SSL certificate' : 'Set NODE_ENV=development to allow self-signed certs'; }
  } else if (error.code === 'ECONNREFUSED') {
      response.message = 'Connection refused'; response.code = 503; response.suggestion = 'Check if Proxmox is running and port is accessible';
  } else if (error.message) {
      response.message = error.message;
  }
  return response;
}

// PUT /api/hypervisors/:id - Update an existing hypervisor
app.put('/api/hypervisors/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  console.log(`PUT /api/hypervisors/${id} called with body:`, req.body);
  const {
    name, host, username, // Campos existentes
    new_password, new_api_token, new_token_name // Nuevos campos para credenciales
  } = req.body;

  if (!name && !host && !username && !new_password && !new_api_token && !new_token_name) {
    return res.status(400).json({ error: 'No fields provided for update.' });
  }

  try {
    const { rows: [currentHypervisor] } = await pool.query(
      'SELECT id, type, host as current_host, username as current_username, password as current_password, api_token as current_api_token, token_name as current_token_name, name as current_name, status as current_status, last_sync as current_last_sync FROM hypervisors WHERE id = $1',
      [id]
    );

    if (!currentHypervisor) {
      return res.status(404).json({ error: 'Hypervisor not found' });
    }

    // Determinar los valores finales para la actualización
    const finalName = name || currentHypervisor.current_name;
    const finalHost = host || currentHypervisor.current_host;
    const finalUsername = username || currentHypervisor.current_username;

    let passwordToUpdate = currentHypervisor.current_password;
    let apiTokenToUpdate = currentHypervisor.current_api_token;
    let tokenNameToUpdate = currentHypervisor.current_token_name;
    let status = currentHypervisor.current_status; 
    let last_sync = currentHypervisor.current_last_sync;

    let credsChanged = false;
    if (new_password !== undefined) { // Check for undefined to allow sending empty string to clear password
        passwordToUpdate = new_password;
        credsChanged = true;
    }
    if (currentHypervisor.type === 'proxmox') {
        if (new_api_token !== undefined) {
            apiTokenToUpdate = new_api_token;
            credsChanged = true;
        }
        if (new_token_name !== undefined) {
            tokenNameToUpdate = new_token_name;
            credsChanged = true;
        }
    }

    // Si se proporcionan nuevas credenciales, probarlas
    if (credsChanged) {
     // console.log(`Attempting to verify new credentials for hypervisor ${id}`);

      try {
        if (currentHypervisor.type === 'proxmox') {
          const [dbHost, dbPortStr] = testHypervisorData.host.split(':');
          const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
          const cleanHost = dbHost;
          const proxmoxConfig = {
            host: cleanHost, port: port, username: finalUsername, // Use finalUsername for test
            timeout: 15000, rejectUnauthorized: false
          };
          // Prioritize new token for test if both parts are provided
          if (new_api_token !== undefined && new_token_name !== undefined) {
            proxmoxConfig.tokenID = `${finalUsername}!${new_token_name}`;
            proxmoxConfig.tokenSecret = new_api_token;
          } else if (new_password !== undefined) { // Else, use new password if provided
            proxmoxConfig.password = new_password;
          }
          const proxmox = proxmoxApi(proxmoxConfig);
          await proxmox.version.$get(); // Prueba de conexión
          // finalApiToken y finalTokenName se actualizan en la lógica de passwordToUpdate, apiTokenToUpdate
        } else if (currentHypervisor.type === 'vsphere') {
           // For vSphere, test with new_password if provided
           if (new_password !== undefined) {
             const vsphereTestData = {
               host: finalHost, // Usar el host que se va a guardar
               username: finalUsername, // Usar el username que se va a guardar
               password: new_password, // La nueva contraseña a probar
               type: 'vsphere' // Pass type for PyVmomi service context
             };
             await callPyvmomiService('POST', '/connect', vsphereTestData, {});
           } else {
             // If credsChanged is true for vSphere but new_password is not defined,
             // it implies an attempt to clear the password, which might need specific handling or be disallowed.
             // For now, this branch would mean no specific vSphere connection test if only password is cleared.
           }
           // passwordToUpdate ya se habrá establecido a new_password si new_password está definido.
        }
        status = 'connected';
        last_sync = new Date();
//console.log(`New credentials for hypervisor ${id} verified successfully.`);
      } catch (connectionError) {
        console.error(`Failed to verify new credentials for hypervisor ${id}:`, connectionError.message);
        return res.status(400).json({ error: 'Failed to connect with new credentials.', details: connectionError.message });
      }
    }

    // Actualizar la base de datos
      const result = await pool.query(
          `UPDATE hypervisors SET name = $1, host = $2, username = $3, password = $4, api_token = $5, token_name = $6, status = $7, last_sync = $8, updated_at = now()
           WHERE id = $9
           RETURNING id, name, type, host, username, status, last_sync, vsphere_subtype, created_at, updated_at`,
          [finalName, finalHost, finalUsername, passwordToUpdate, apiTokenToUpdate, tokenNameToUpdate, status, last_sync, id]
      );

      if (result.rows.length > 0) res.json(result.rows[0]);
      else res.status(404).json({ error: 'Hypervisor not found' });
  } catch (err) {
      console.error(`Error updating hypervisor ${id} in DB:`, err);
      res.status(500).json({ error: 'Failed to update hypervisor' });
  }
});

// DELETE /api/hypervisors/:id - Delete a hypervisor
app.delete('/api/hypervisors/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
 // console.log(`DELETE /api/hypervisors/${id} called`);
  try {
    const result = await pool.query('DELETE FROM hypervisors WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount > 0) res.status(204).send();
    else res.status(404).json({ error: 'Hypervisor not found' });
  } catch (err) {
    console.error(`Error deleting hypervisor ${id} from DB:`, err);
    res.status(500).json({ error: 'Failed to delete hypervisor' });
  }
});

// POST /api/hypervisors/:id/connect
app.post('/api/hypervisors/:id/connect', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  //console.log(`POST /api/hypervisors/${id}/connect called`);

  try {
    const { rows: [hypervisor] } = await pool.query(
      `SELECT id, type, host, username, password, api_token, token_name, vsphere_subtype
       FROM hypervisors WHERE id = $1`,
      [id]
    );
    if (!hypervisor) return res.status(404).json({ error: 'Hypervisor not found' });

    let newStatus = 'error';
    let last_sync = null;
    let connectionMessage = `Connection attempt for hypervisor ${id} (${hypervisor.type}).`;
    let determinedVsphereSubtype = hypervisor.vsphere_subtype; // Keep existing if not redetermined

    if (hypervisor.type === 'proxmox') {
      // ... (Proxmox connection logic - Mantenida como estaba)
      const [dbHost, dbPortStr] = hypervisor.host.split(':');
      const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
      const cleanHost = dbHost;
      const proxmoxConfig = {
        host: cleanHost, port: port, username: hypervisor.username,
        tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
        tokenSecret: hypervisor.api_token, timeout: 15000, rejectUnauthorized: false
      };
      const proxmox = proxmoxApi(proxmoxConfig);
      const versionResponse = await proxmox.version.$get();
      if (!versionResponse?.version) throw new Error('Failed to retrieve Proxmox version.');
      // const permissionsInfo = await proxmox.access.permissions.$get(); // Optional: permission check
      newStatus = 'connected';
      last_sync = new Date();
      connectionMessage = `Successfully connected to Proxmox user ${hypervisor.username} on ${cleanHost}:${port}`;
    } else if (hypervisor.type === 'vsphere') {
    //  console.log(`Attempting vSphere connection for hypervisor ${id} (${hypervisor.host}) via PyVmomi`);
      try {
        // Pass the full hypervisor object from DB to callPyvmomiService
        const connectResponse = await callPyvmomiService('POST', '/connect', hypervisor, {});
        newStatus = 'connected';
        last_sync = new Date();
        determinedVsphereSubtype = connectResponse.vsphere_subtype || hypervisor.vsphere_subtype || 'esxi';
        connectionMessage = `Successfully connected to vSphere via PyVmomi. Subtype: ${determinedVsphereSubtype}.`;
       
      } catch (pyVmomiConnectError) {
        connectionMessage = `vSphere connection via PyVmomi failed: ${pyVmomiConnectError.details?.error || pyVmomiConnectError.message}`;
        console.error(connectionMessage);
        throw pyVmomiConnectError; // Re-throw
      }
    } else {
      connectionMessage = `Unsupported hypervisor type: ${hypervisor.type}`;
      console.warn(connectionMessage);
    }

    const { rows: [updatedHypervisor] } = await pool.query(
      `UPDATE hypervisors SET status = $1, last_sync = $2, vsphere_subtype = $3, updated_at = NOW()
       WHERE id = $4 RETURNING id, name, status, last_sync, vsphere_subtype`,
      [newStatus, last_sync, determinedVsphereSubtype, id]
    );
    res.json({ ...updatedHypervisor, message: connectionMessage });
    //console.log(`Updated hypervisor ${id} status to ${newStatus}.`);

  } catch (err) {
    const { rows: [hypervisorAttempted] } = await pool.query('SELECT type FROM hypervisors WHERE id = $1', [id]);
    let errorDetails;
    if (hypervisorAttempted?.type === 'proxmox') errorDetails = getProxmoxError(err);
    else if (hypervisorAttempted?.type === 'vsphere') {
      errorDetails = {
        code: err.status || 500,
        message: err.details?.error || err.message || 'vSphere connection error via PyVmomi.',
        suggestion: 'Check PyVmomi microservice logs and vSphere connectivity.'
      };
    } else {
      errorDetails = { code: 500, message: err.message || 'Unknown connection error.', suggestion: 'Review server logs.' };
    }
    console.error(`Connection attempt failed for hypervisor ${id}: ${errorDetails.message}`, { stack: err.stack });
    await pool.query(
      `UPDATE hypervisors SET status = 'error', last_sync = NULL, updated_at = NOW() WHERE id = $1`, [id]
    ).catch(dbUpdateError => console.error(`Failed to update hypervisor ${id} status to 'error' in DB:`, dbUpdateError));
    res.status(errorDetails.code || 500).json(errorDetails);
  }
});


// --- VM Plan CRUD API Routes --- (Mantenidas como estaban)
app.get('/api/vm-plans', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, description, specs, icon, is_active, created_at, updated_at FROM vm_plans ORDER BY created_at ASC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to retrieve VM plans' }); }
});
app.post('/api/vm-plans', authenticate, requireAdmin, async (req, res) => {
  const { name, description, specs, icon, is_active = true } = req.body;
  if (!name || !description || !specs || !specs.cpu || !specs.memory || !specs.disk) {
    return res.status(400).json({ error: 'Missing required plan fields' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO vm_plans (name, description, specs, icon, is_active) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, description, JSON.stringify(specs), icon || null, is_active]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to create VM plan' }); }
});
app.put('/api/vm-plans/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, description, specs, is_active } = req.body;

  // Validación: al menos un campo actualizable debe estar presente
  if (name === undefined && description === undefined && specs === undefined && is_active === undefined) {
    return res.status(400).json({ error: 'No se proporcionaron campos para actualizar.' });
  }
  // Validación más específica si es necesario (ej., estructura de specs)
  if (specs && (specs.cpu === undefined || specs.memory === undefined || specs.disk === undefined)) {
    return res.status(400).json({ error: 'Estructura de especificaciones inválida. Se requieren CPU, memoria y disco dentro de las especificaciones.' });
  }
  if (is_active !== undefined && typeof is_active !== 'boolean') {
    return res.status(400).json({ error: 'is_active debe ser un valor booleano.' });
  }

  try {
    const currentPlanResult = await pool.query('SELECT * FROM vm_plans WHERE id = $1', [id]);
    if (currentPlanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Plan de VM no encontrado' });
    }

    // Construir la consulta de actualización dinámicamente
    const updateFields = [];
    const values = [];
    let valueIndex = 1;

    if (name !== undefined) { updateFields.push(`name = $${valueIndex++}`); values.push(name); }
    if (description !== undefined) { updateFields.push(`description = $${valueIndex++}`); values.push(description); }
    if (specs !== undefined) { updateFields.push(`specs = $${valueIndex++}`); values.push(JSON.stringify(specs)); }
    if (is_active !== undefined) { updateFields.push(`is_active = $${valueIndex++}`); values.push(is_active); }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No se proporcionaron campos válidos para actualizar.' });
    }

    updateFields.push(`updated_at = now()`);
    values.push(id); // Para la cláusula WHERE

    const queryText = `UPDATE vm_plans SET ${updateFields.join(', ')} WHERE id = $${valueIndex} RETURNING *`;
    
    const result = await pool.query(queryText, values);

    if (result.rows.length > 0) res.json(result.rows[0]);
    else res.status(404).json({ error: 'Plan de VM no encontrado (inesperado durante la actualización).' });
  } catch (err) {
    console.error(`Error al actualizar el plan de VM ${id}:`, err);
    res.status(500).json({ error: 'Error al actualizar el plan de VM' });
  }
});

app.delete('/api/vm-plans/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM vm_plans WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount > 0) res.status(204).send();
    else res.status(404).json({ error: 'VM Plan not found' });
  } catch (err) { res.status(500).json({ error: 'Failed to delete VM plan' }); }
});

// --- Final Client CRUD API Routes --- (Mantenidas como estaban)
app.get('/api/final-clients', authenticate, async (req, res) => {
  const page = parseInt(req.query.page || '1', 10);
  const limit = parseInt(req.query.limit || '10', 10);
  const search = req.query.search || '';
  const offset = (page - 1) * limit;
  try {
    let query = 'SELECT * FROM final_clients';
    let countQuery = 'SELECT COUNT(*) FROM final_clients';
    const queryParams = [], countQueryParams = [];
    if (search) {
      const searchTerm = `%${search}%`;
      query += ' WHERE name ILIKE $1 OR rif ILIKE $1';
      countQuery += ' WHERE name ILIKE $1 OR rif ILIKE $1';
      queryParams.push(searchTerm); countQueryParams.push(searchTerm);
    }
    query += ` ORDER BY name ASC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    const [dataResult, countResult] = await Promise.all([pool.query(query, queryParams), pool.query(countQuery, countQueryParams)]);
    const totalItems = parseInt(countResult.rows[0].count, 10);
    const totalPages = Math.ceil(totalItems / limit);
    res.json({ items: dataResult.rows, pagination: { currentPage: page, totalPages, totalItems, limit } });
  } catch (err) { res.status(500).json({ error: 'Failed to retrieve final clients' }); }
});
app.post('/api/final-clients', authenticate, requireAdmin, async (req, res) => {
  const { name, rif, contact_info, additional_info } = req.body;
  const created_by_user_id = req.user.userId;
  if (!name || !rif) return res.status(400).json({ error: 'Name and RIF are required' });
  try {
    const result = await pool.query(
      `INSERT INTO final_clients (name, rif, contact_info, additional_info, created_by_user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, rif, contact_info || null, additional_info || null, created_by_user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A client with this RIF already exists.' });
    res.status(500).json({ error: 'Failed to create final client' });
  }
});
app.put('/api/final-clients/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, rif, contact_info, additional_info } = req.body;
  if (!name || !rif) return res.status(400).json({ error: 'Name and RIF are required' });
  try {
    const result = await pool.query(
      `UPDATE final_clients SET name = $1, rif = $2, contact_info = $3, additional_info = $4, updated_at = now() WHERE id = $5 RETURNING *`,
      [name, rif, contact_info || null, additional_info || null, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Final client not found' });
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Another client with this RIF already exists.' });
    res.status(500).json({ error: 'Failed to update final client' });
  }
});
app.delete('/api/final-clients/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM final_clients WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Final client not found' });
    res.status(204).send();
  } catch (err) { res.status(500).json({ error: 'Failed to delete final client' }); }
});

// --- Statistics Routes ---
app.get('/api/stats/vm-creation-count', authenticate, async (req, res) => {
  const { startDate, endDate } = req.query;
  const MAX_DAYS_FOR_DAILY_COUNTS = 366; // Allow up to a year for daily counts
  if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate are required.' });
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(startDate) || !dateRegex.test(endDate)) return res.status(400).json({ error: 'Dates must be YYYY-MM-DD.' });
  
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  if (isNaN(start.getTime()) || isNaN(end.getTime())) return res.status(400).json({ error: 'Invalid date format.' });
  if (start > end) return res.status(400).json({ error: 'startDate cannot be after endDate.' });
  
  const endOfDay = new Date(end); endOfDay.setDate(endOfDay.getDate() + 1); // Exclusive end for query

  try {
    const uniqueVms = new Map(); // Key: hypervisorId:hypervisorVmId, Value: { createdAt: Date }

    // 1. Fetch VMs from Database, including hypervisor_type
    const dbVmsResult = await pool.query(
      `SELECT id, hypervisor_id, hypervisor_vm_id, created_at 
       FROM virtual_machines 
       WHERE created_at IS NOT NULL`
    );
    for (const dbVm of dbVmsResult.rows) {
      if (dbVm.hypervisor_id && dbVm.hypervisor_vm_id && dbVm.created_at) {
        const key = `${dbVm.hypervisor_id}:${dbVm.hypervisor_vm_id}`;
        // We need hypervisor_type here. Let's fetch it with the hypervisor details.
        // For now, we'll add it when iterating through connectedHypervisors.
        // A more optimized way would be to JOIN hypervisors table here.
        uniqueVms.set(key, { createdAt: new Date(dbVm.created_at), type: null }); // type will be filled later
      }
    }
    //console.log(`Stats: Found ${uniqueVms.size} VMs from database with creation dates.`);

    // 2. Fetch VMs from Connected Hypervisors
    const { rows: connectedHypervisors } = await pool.query(
      `SELECT id, type, host, username, api_token, token_name, name as hypervisor_name 
       FROM hypervisors WHERE status = 'connected'`
    );

    for (const hypervisor of connectedHypervisors) {
      try {
        if (hypervisor.type === 'proxmox') {
          const proxmox = await getProxmoxClient(hypervisor.id);
          const vmResources = await proxmox.cluster.resources.$get({ type: 'vm' });
          for (const vm of vmResources) {
            const vmIdStr = vm.vmid.toString();
            const key = `${hypervisor.id}:${vmIdStr}`;
            if (uniqueVms.has(key)) {
              const existingVm = uniqueVms.get(key);
              if (!existingVm.type) existingVm.type = 'proxmox'; // Fill type if from DB
            } else if (vm.uptime) { // New VM not in DB
              const estimatedCreationDate = new Date(Date.now() - (vm.uptime * 1000));
              uniqueVms.set(key, { createdAt: estimatedCreationDate, type: 'proxmox' });
            } else {
                console.warn(`Stats: Proxmox VM ${vmIdStr} from ${hypervisor.name} missing uptime for creation date estimation.`);
            }
          }
        } else if (hypervisor.type === 'vsphere') {
          const pyvmomiVmsRaw = await callPyvmomiService('GET', '/vms', hypervisor);
          if (Array.isArray(pyvmomiVmsRaw)) {
            for (const vm of pyvmomiVmsRaw) {
              const key = `${hypervisor.id}:${vm.uuid}`;
              if (uniqueVms.has(key)) {
                const existingVm = uniqueVms.get(key);
                if (!existingVm.type) existingVm.type = 'vsphere'; // Fill type if from DB
              } else if (vm.boot_time) { // New VM not in DB
                const estimatedCreationDate = new Date(vm.boot_time);
                uniqueVms.set(key, { createdAt: estimatedCreationDate, type: 'vsphere' });
              } else if (!uniqueVms.has(key)) {
                // Fallback if boot_time is not available, maybe log or skip
                console.warn(`Stats: vSphere VM ${vm.uuid} from ${hypervisor.name} missing boot_time for creation date estimation.`);
                // uniqueVms.set(key, { createdAt: new Date(0), type: 'vsphere' }); // Or handle as unknown creation date
              }
            }
          }
        }
      } catch (hypervisorError) {
        console.error(`Stats: Error fetching VMs from hypervisor ${hypervisor.name} (ID: ${hypervisor.id}):`, hypervisorError.message);
      }
    }
    //console.log(`Stats: Total unique VMs (DB + Hypervisors) before date filtering: ${uniqueVms.size}`);

    // 3. Filter by Date Range and Count
    const filteredVmCreationDates = [];
    uniqueVms.forEach(vmData => {
      if (vmData.type && vmData.createdAt >= start && vmData.createdAt < endOfDay) { // Ensure type is set
        filteredVmCreationDates.push({ date: vmData.createdAt, type: vmData.type });
      }
    });

    const count = filteredVmCreationDates.length;
    let dailyCounts = null;

    const diffTime = Math.abs(end.getTime() - start.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;

    if (diffDays <= MAX_DAYS_FOR_DAILY_COUNTS) {
      const countsByDate = {};
      filteredVmCreationDates.forEach(vm => {
        const dateString = vm.date.toISOString().split('T')[0]; // YYYY-MM-DD
        if (!countsByDate[dateString]) {
          countsByDate[dateString] = { date: dateString, proxmox: 0, vsphere: 0, total: 0 };
        }
        if (vm.type === 'proxmox') {
          countsByDate[dateString].proxmox += 1;
        } else if (vm.type === 'vsphere') {
          countsByDate[dateString].vsphere += 1;
        }
        countsByDate[dateString].total +=1;
      });
      dailyCounts = Object.values(countsByDate)
        .sort((a, b) => new Date(a.date) - new Date(b.date));
    }

    //console.log(`Stats: VMs created between ${startDate} and ${endDate}: ${count}. Daily counts generated: ${!!dailyCounts}`);
    res.json({ count, startDate, endDate, dailyCounts });
  } catch (err) {
    console.error('Error in /api/stats/vm-creation-count:', err);
    res.status(500).json({ error: 'Failed to retrieve VM creation statistics' });
  }
});


app.get('/api/stats/client-vms/:clientId', authenticate, async (req, res) => {
  const { clientId } = req.params;
  const page = parseInt(req.query.page || '1', 10);
  const limit = parseInt(req.query.limit || '5', 10);
  const offset = (page - 1) * limit;
  if (!clientId) return res.status(400).json({ error: 'Client ID is required.' });
  try {
    const vmsQuery = `
      SELECT vm.id as database_id, vm.hypervisor_vm_id as id, vm.name, vm.status, vm.created_at,
             vm.cpu_cores, vm.memory_mb, vm.disk_gb, vm.os, vm.hypervisor_id, h.type as hypervisor_type
      FROM virtual_machines vm JOIN hypervisors h ON vm.hypervisor_id = h.id
      WHERE vm.final_client_id = $1 ORDER BY vm.created_at DESC LIMIT $2 OFFSET $3`;
    const vmsResult = await pool.query(vmsQuery, [clientId, limit, offset]);
    const countQuery = 'SELECT COUNT(*) FROM virtual_machines WHERE final_client_id = $1';
    const countResult = await pool.query(countQuery, [clientId]);
    const totalItems = parseInt(countResult.rows[0].count, 10);
    const totalPages = Math.ceil(totalItems / limit);
    const formattedVms = vmsResult.rows.map(dbVm => ({
      id: dbVm.id, databaseId: dbVm.database_id, name: dbVm.name, status: dbVm.status,
      createdAt: dbVm.created_at, hypervisorId: dbVm.hypervisor_id, hypervisorType: dbVm.hypervisor_type,
      specs: { cpu: dbVm.cpu_cores, memory: dbVm.memory_mb, disk: dbVm.disk_gb, os: dbVm.os, }
    }));
    res.json({ items: formattedVms, pagination: { currentPage: page, totalPages, totalItems, limit } });
  } catch (err) { res.status(500).json({ error: 'Failed to retrieve VMs for the client.' }); }
});

// --- Servidor HTTP para Express y WebSocket ---
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

// --- WebSocket Proxy para noVNC ---
server.on('upgrade', (request, socket, head) => {
  const parsedUrl = new URL(request.url, `http://${request.headers.host}`);
  const pathname = parsedUrl.pathname;
  const token = parsedUrl.searchParams.get('token');

  console.log(`WebSocket Upgrade Request: Path=${pathname}, Token=${token ? 'present' : 'missing'}`);

  // Validar el token aquí si es necesario para la seguridad del proxy
  // Por ejemplo, podrías tener un sistema de tokens de un solo uso generados por la API

  if (pathname.startsWith('/websockify')) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else if (pathname.startsWith('/api/ws/proxmox-console')) {
    console.log(`[WebSocket Upgrade] Path matches '/api/ws/proxmox-console'. Attempting to handle upgrade.`);
    // Authentication layer can be added here if needed
    wss.handleUpgrade(request, socket, head, (wsClient) => {
      console.log('[WebSocket Upgrade] wss.handleUpgrade successful. Emitting "connection" event to wss.');
      wss.emit('connection', wsClient, request);
    });
  } else {
    console.log('WebSocket upgrade request for unknown path, destroying socket.');
    socket.destroy();
  }
});

server.listen(port, () => {
  console.log(`Server (con WebSocket proxy) corriendo en el puerto ${port}`);
});

wss.on('connection', (clientWs, request) => {
  try {
    const parsedUrl = new URL(request.url, `http://${request.headers.host}`);
    console.log("parsedurl", parsedUrl);
    // Extract vmid, node, ticket, vncPort from query params
    const vmid = parsedUrl.searchParams.get('vmid');
    const node = parsedUrl.searchParams.get('node');
    const vncPort = parsedUrl.searchParams.get('vncPort');
    const vncTicket = parsedUrl.searchParams.get('ticket');

    // Resolve Proxmox host IP from DB using vmid and node
    if (!vmid || !node) {
      console.error('WebSocket connection rejected: Missing vmid or node.');
      clientWs.close(1011, 'Missing vmid or node');
      return;
    }

    // Query DB to get Proxmox host for the VM
    pool.query(
      `SELECT h.host FROM hypervisors h
       JOIN virtual_machines vm ON vm.hypervisor_id = h.id
       WHERE vm.hypervisor_vm_id = $1 AND h.type = 'proxmox' AND h.status = 'connected'`,
      [vmid]
    ).then(result => {
      if (result.rows.length === 0) {
        console.log(`No Proxmox host found for VM ${vmid} in DB, attempting to find via Proxmox API scan...`);
        // Fallback scanning logic to find Proxmox host by checking each connected hypervisor
        (async () => {
          try {
            const { rows: connectedProxmoxHypervisors } = await pool.query(
              `SELECT id, host, username, api_token, token_name 
               FROM hypervisors WHERE status = 'connected' AND type = 'proxmox'`
            );
            let foundHost = null;
            for (const hypervisor of connectedProxmoxHypervisors) {
              const [dbHost, dbPortStr] = hypervisor.host.split(':');
              const port = dbPortStr ? parseInt(dbPortStr, 10) : 8006;
              const cleanHost = dbHost;
              const proxmoxConfigScan = {
                host: cleanHost, port: port, username: hypervisor.username,
                tokenID: `${hypervisor.username}!${hypervisor.token_name}`,
                tokenSecret: hypervisor.api_token, timeout: 5000, rejectUnauthorized: false
              };
              const proxmoxClientScan = proxmoxApi(proxmoxConfigScan);
              try {
                // Check if VM exists on the given node via Proxmox API
                await proxmoxClientScan.nodes.$(node).qemu.$(vmid).status.current.$get();
                foundHost = cleanHost;
                console.log(`Found VM ${vmid} on node ${node} via hypervisor ${hypervisor.id} (${cleanHost})`);
                break;
              } catch {
                // VM not found on this hypervisor, continue
              }
            }
            if (!foundHost) {
              console.error(`Could not determine Proxmox host for VM ${vmid} on node ${node} via DB or API scan.`);
              clientWs.close(1011, 'Proxmox host not found for VM');
              return;
            }
            // Proceed with found host
            const proxmoxHost = foundHost;
            const proxmoxPort = 8006; // Default Proxmox API port
            if (!vncPort || !vncTicket) {
              console.error('WebSocket connection rejected: Missing vncPort or ticket.');
              clientWs.close(1011, 'Missing vncPort or ticket');
              return;
            }
            console.log(`WebSocket Connection: Target=${proxmoxHost}:${vncPort}, Ticket=${vncTicket ? 'present' : 'missing'}`);
            const targetSocket = net.createConnection({ host: proxmoxHost, port: parseInt(vncPort, 10) }, () => {
              console.log(`Successfully connected to target VNC server: ${proxmoxHost}:${vncPort}`);
              targetSocket.write(`${vncTicket}\n`);
              console.log('VNC ticket sent to target.');
            });
            // Pipe data between client and target socket
            clientWs.on('message', (data) => {
              targetSocket.write(data);
            });
            targetSocket.on('data', (data) => {
              clientWs.send(data);
            });
            // Handle errors and close events
            clientWs.on('close', (code, reason) => {
              console.log(`Client WebSocket closed: ${code} ${reason}`);
              targetSocket.end();
              targetSocket.destroy();
            });
            clientWs.on('error', (error) => {
              console.error('Client WebSocket error:', error);
              targetSocket.end();
              targetSocket.destroy();
            });
            targetSocket.on('close', () => {
              console.log('Target VNC socket closed.');
              clientWs.close();
            });
            targetSocket.on('error', (error) => {
              console.error(`Target VNC socket error (connecting to ${proxmoxHost}:${vncPort}):`, error.message);
              clientWs.close(1011, `Upstream VNC server connection error: ${error.message}`);
            });
          } catch (err) {
            console.error('Error during Proxmox host scan for VM:', err);
            clientWs.close(1011, 'Internal server error during WebSocket setup.');
          }
        })();
        return;
      }
      const proxmoxHost = result.rows[0].host.split(':')[0];
      const proxmoxPort = 8006; // Default Proxmox API port

      if (!vncPort || !vncTicket) {
        console.error('WebSocket connection rejected: Missing vncPort or ticket.');
        clientWs.close(1011, 'Missing vncPort or ticket');
        return;
      }

      console.log(`WebSocket Connection: Target=${proxmoxHost}:${vncPort}, Ticket=${vncTicket ? 'present' : 'missing'}`);

      const targetSocket = net.createConnection({ host: proxmoxHost, port: parseInt(vncPort, 10) }, () => {
        console.log(`[${new Date().toISOString()}] Successfully connected to target VNC server: ${proxmoxHost}:${vncPort}`);
        targetSocket.write(`${vncTicket}\n`);
        console.log(`[${new Date().toISOString()}] VNC ticket sent to target.`);
      });

      // --- Pipe data between client and target socket ---
      clientWs.on('message', (data) => {
        console.log(`[${new Date().toISOString()}] Client WebSocket sent data: ${data.length} bytes`);
        targetSocket.write(data);
      });
      targetSocket.on('data', (data) => {
        console.log(`[${new Date().toISOString()}] Target socket sent data: ${data.length} bytes`);
        clientWs.send(data);
      });

      // --- Handle errors and close events ---
      clientWs.on('open', () => {
        console.log(`[${new Date().toISOString()}] Client WebSocket connection opened.`);
      });
      clientWs.on('close', (code, reason) => {
        console.log(`[${new Date().toISOString()}] Client WebSocket closed: code=${code}, reason=${reason ? reason.toString() : 'N/A'}`);
        targetSocket.end();
        targetSocket.destroy();
      });
      clientWs.on('error', (error) => {
        console.error(`[${new Date().toISOString()}] Client WebSocket error:`, error);
        targetSocket.end();
        targetSocket.destroy();
      });
      targetSocket.on('close', (hadError) => {
        console.log(`[${new Date().toISOString()}] Target VNC socket closed. Had error: ${hadError}`);
        clientWs.close();
      });
      targetSocket.on('error', (error) => {
        console.error(`[${new Date().toISOString()}] Target VNC socket error (connecting to ${proxmoxHost}:${vncPort}):`, error.message);
        // Enhanced diagnostic logging
        console.error('Diagnostic Info:');
        console.error(`- Proxmox Host: ${proxmoxHost}`);
        console.error(`- VNC Port: ${vncPort}`);
        console.error(`- VNC Ticket Length: ${vncTicket ? vncTicket.length : 0}`);

        // Retry logic: attempt to reconnect up to 3 times with delay
        if (!targetSocket.retryCount) targetSocket.retryCount = 0;
        if (targetSocket.retryCount < 3) {
          targetSocket.retryCount++;
          const retryDelay = 2000 * targetSocket.retryCount; // Exponential backoff
          console.log(`[${new Date().toISOString()}] Retrying connection attempt ${targetSocket.retryCount} in ${retryDelay}ms...`);
          setTimeout(() => {
            const newSocket = net.createConnection({ host: proxmoxHost, port: parseInt(vncPort, 10) }, () => {
              console.log(`[${new Date().toISOString()}] Retry ${targetSocket.retryCount}: Connected to target VNC server: ${proxmoxHost}:${vncPort}`);
              newSocket.write(`${vncTicket}\n`);
              console.log(`[${new Date().toISOString()}] Retry ${targetSocket.retryCount}: VNC ticket sent to target.`);
            });

            // Re-attach event handlers to new socket
            newSocket.on('data', (data) => {
              console.log(`[${new Date().toISOString()}] Retry ${targetSocket.retryCount}: Target socket sent data: ${data.length} bytes`);
              clientWs.send(data);
            });
            newSocket.on('close', (hadError) => {
              console.log(`[${new Date().toISOString()}] Retry ${targetSocket.retryCount}: Target VNC socket closed. Had error: ${hadError}`);
              clientWs.close();
            });
            newSocket.on('error', (err) => {
              console.error(`[${new Date().toISOString()}] Retry ${targetSocket.retryCount}: Target VNC socket error: ${err.message}`);
            });

            // Replace old socket with new socket
            targetSocket.destroy();
            targetSocket = newSocket;
          }, retryDelay);
        } else {
          console.error(`[${new Date().toISOString()}] Max retry attempts reached. Closing client WebSocket.`);
          clientWs.close(1011, `Upstream VNC server connection error: ${error.message}`);
        }
      });
    }).catch(err => {
      console.error('Error querying Proxmox host for VM:', err);
      clientWs.close(1011, 'Internal server error during WebSocket setup.');
    });

  } catch (error) {
    console.error('Error in WebSocket connection handler:', error);
    clientWs.close(1011, 'Internal server error during WebSocket setup.');
  }
});
