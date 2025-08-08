import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Loader2, ArrowLeft } from 'lucide-react';
import RFB from '@novnc/novnc/core/rfb';
import { useAuth } from '../hooks/useAuth';
import { toast } from 'react-hot-toast';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

export default function VMConsole() {
  const { id: vmId } = useParams();
  const navigate = useNavigate();
  const { token: authToken, isAuthenticated, isLoading: authLoading } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const screenRef = useRef<HTMLDivElement>(null);
  const rfbRef = useRef<RFB | null>(null);


  console.log(authToken)
  useEffect(() => {
    // 1. Esperar a que el hook de autenticación termine de cargar.
    if (authLoading) {
      return;
    }

    // 2. Verificar autenticación - si no está autenticado, el ProtectedRoute ya manejará la redirección
    if (!isAuthenticated) {
      console.error('User not authenticated, ProtectedRoute will handle redirect');
      setError('No estás autenticado. Por favor inicia sesión.');
      setLoading(false);
      return;
    }

    // 3. Si no hay token pero está autenticado, intentar obtenerlo del contexto
    const tokenToUse = authToken || localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    
    if (!tokenToUse) {
      console.error('No authentication token available');
      setError('No estás autenticado. Por favor inicia sesión.');
      setLoading(false);
      return;
    }
    
    const fetchConsoleDetails = async () => {
      if (!vmId) return;
      
      try {
        const response = await fetch(`${API_BASE_URL}/vms/${vmId}/console`, {
          headers: {
            Authorization: `Bearer ${tokenToUse}`,
          },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'Failed to load console details');
        }

        const consoleData = await response.json();
        initVNC(consoleData);
      } catch (err) {
        console.error('Console connection error:', err);
        const message = err instanceof Error ? err.message : 'Failed to connect to console';
        setError(message);
        toast.error('Failed to connect to VM console');
      } finally {
        setLoading(false);
      }
    };

    fetchConsoleDetails();

    // Cleanup on unmount
    return () => {
      if (rfbRef.current) {
        rfbRef.current.disconnect();
        rfbRef.current = null;
      }
    };
  }, [vmId, authToken, isAuthenticated, authLoading]);

  const initVNC = (consoleData: any) => {
    if (!screenRef.current) return;
    
    try {
      // Construir URL de WebSocket
 // La conexión WebSocket debe ser PROXYDA a través de nuestro backend,
      // ya que el navegador del cliente no puede acceder a la IP privada de Proxmox.
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const host = window.location.host; // Usa el host de tu aplicación

      // Pasamos los detalles de la consola de Proxmox como parámetros para que el backend sepa a dónde conectarse.
      const proxmoxConsoleUrl = `/api2/json/nodes/${consoleData.node}/qemu/${consoleData.vmid}/vncwebsocket?port=${consoleData.port}&vncticket=${encodeURIComponent(consoleData.ticket)}`;
      const websocketUrl = `${proto}//${host}/api/vms/${vmId}/console-ws?proxmox_host=${consoleData.host}&proxmox_port=${consoleData.port}&proxmox_path=${encodeURIComponent(proxmoxConsoleUrl)}`;
        //EDD!! revisar esta direccion si es correcta   
      
      
      
      
      
      
      
        // Configurar cliente RFB (VNC)
      rfbRef.current = new RFB(screenRef.current, websocketUrl, {
        credentials: {
          password: consoleData.ticket,
        },
        shared: true,
        repeaterID: '',
      });

      rfbRef.current.addEventListener("connect", () => {
        console.log("VNC connected successfully");
      });

      rfbRef.current.addEventListener("disconnect", (e: any) => {
        if (!e.detail.clean) {
          toast.error('Console connection lost');
        }
      });

      rfbRef.current.addEventListener("credentialsrequired", () => {
        toast.error('Authentication failed for console');
      });

      rfbRef.current.scaleViewport = true;
      rfbRef.current.resizeSession = true;

    } catch (err) {
      console.error('VNC initialization error:', err);
      setError('Failed to initialize VNC client');
    }
  };

  const handleDisconnect = () => {
    if (rfbRef.current) {
      rfbRef.current.disconnect();
      rfbRef.current = null;
    }
    navigate(-1); // Volver a la página anterior
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-gray-900">
        <Loader2 className="animate-spin h-12 w-12 text-blue-500 mb-4" />
        <p className="text-gray-300">Conectando a la consola...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-gray-900">
        <div className="bg-red-500 text-white p-4 rounded-lg max-w-md">
          <h2 className="text-xl font-bold mb-2">Error de conexión</h2>
          <p className="mb-4">{error}</p>
          <button 
            onClick={() => navigate(-1)}
            className="bg-white text-red-500 px-4 py-2 rounded hover:bg-gray-100"
          >
            Volver
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-gray-900">
      {/* Barra de control */}
      <div className="bg-gray-800 p-3 flex justify-between items-center">
        <button 
          onClick={handleDisconnect}
          className="text-white hover:text-gray-300 flex items-center"
        >
          <ArrowLeft className="mr-2" /> Salir de la consola
        </button>
        <div className="text-white">
          Consola de VM: {vmId}
        </div>
        <div className="flex space-x-2">
          <button 
            className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
            onClick={() => rfbRef.current?.sendKey('Ctrl', 'Alt', 'Delete')}
          >
            Ctrl+Alt+Supr
          </button>
        </div>
      </div>

      {/* Área de la consola */}
      <div 
        ref={screenRef} 
        className="flex-grow w-full overflow-hidden"
      />
    </div>
  );
}