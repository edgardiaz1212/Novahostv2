import React, { useEffect, useState, useRef } from 'react';
import VNC from '@novnc/novnc/core/rfb.js'; // Correct import for the VNC client

// Define types here as they are imported from this file by StandaloneConsolePage.tsx
// and potentially VMDetails.tsx.

export interface ProxmoxConnectionDetails {
  host: string;
  port: number | string;
  node: string;
  vmid: number | string;
  ticket: string;
  vncPort?: number | string;
  // ssl?: boolean; // Optional: to determine http vs https, though Proxmox typically uses https
}

export interface VSphereHtml5ConnectionDetails {
  url: string; // Typically a full URL for the HTML5 console
}

export interface VSphereWebMKSConnectionDetails {
  host: string;
  port?: number; // Port might be implicit in host or ticket for some SDKs
  ticket: string;
  thumbprint?: string; // SSL thumbprint
  vmId?: string; // VM MoRef ID or similar identifier
  // Add other fields required by the WMKS library
}

// Add other specific connection detail types as needed (e.g., for MKS)

export type ConsoleType = 'proxmox' | 'vsphere_html5' | 'vsphere_webmks' | 'vsphere_mks' | string; // Allow string for future/custom types

export interface ConsoleOption {
  type: ConsoleType;
  name?: string; // e.g., "noVNC (Proxmox)", "HTML5 Console (vSphere)"
  connectionDetails:
    | ProxmoxConnectionDetails
    | VSphereHtml5ConnectionDetails
    | VSphereWebMKSConnectionDetails
    | Record<string, any>; // Fallback for other/unknown structures
  vmName?: string; // Optional: if the option itself carries a specific VM name
}

export interface ConsoleDetailsData {
  vmName: string;
  consoleOptions: ConsoleOption[];
}

interface VMConsoleViewProps {
  consoleDetails: ConsoleDetailsData;
  onClose: () => void;
  onError: (message: string) => void;
}

const VMConsoleView: React.FC<VMConsoleViewProps> = ({ consoleDetails, onClose, onError }) => {
  const [selectedOption, setSelectedOption] = useState<ConsoleOption | null>(null);
  const screenRef = useRef<HTMLDivElement>(null);
  const vncRef = useRef<VNC | null>(null);

  useEffect(() => {
    // Find the best console option to use
    if (consoleDetails && consoleDetails.consoleOptions && consoleDetails.consoleOptions.length > 0) {
      const proxmoxOption = consoleDetails.consoleOptions.find(opt => opt.type === 'proxmox');
      // Add logic for other types if needed
      setSelectedOption(proxmoxOption || consoleDetails.consoleOptions[0]);
      console.log("Selected console option:", proxmoxOption || consoleDetails.consoleOptions[0]);
    } else {
      onError("No console options available in consoleDetails.");
    }

    // Cleanup on unmount
    return () => {
      if (vncRef.current) {
        vncRef.current.disconnect();
        vncRef.current = null;
      }
    };
  }, [consoleDetails, onError]);

  useEffect(() => {
    if (selectedOption && selectedOption.type === 'proxmox' && screenRef.current) {
      // Disconnect previous instance if any
      if (vncRef.current) {
        vncRef.current.disconnect();
        vncRef.current = null;
      }
  
      const details = selectedOption.connectionDetails as ProxmoxConnectionDetails;
      if (!details.vmid || !details.node) {
        onError("VM ID or Node is missing in Proxmox connection details.");
        return;
      }
  
      // CORRECCIÓN: Usar sessionId en lugar de ticket/vncPort
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      
      // Obtener sessionId de la respuesta de /api/vms/:id/console
      const sessionId = (selectedOption as any).sessionId;
      if (!sessionId) {
        onError("Session ID is missing for console connection.");
        return;
      }
  
      const proxyUrl = `${proto}//${host}/api/ws/proxmox-console?vmid=${details.vmid}&node=${details.node}&sessionId=${sessionId}`;
  
      console.log(`Connecting to backend WebSocket proxy: ${proxyUrl}`);
  
      try {
        const rfb = new VNC(screenRef.current, proxyUrl, {
          credentials: {
            // No credentials needed, handled by backend
          }
        });
        
        vncRef.current = rfb;
  
        rfb.addEventListener('connect', () => {
          console.log('noVNC connected successfully');
        });
  
        rfb.addEventListener('disconnect', (event: any) => {
          console.log('noVNC disconnected:', event.detail);
          if (!event.detail.clean) {
            onError(`Console disconnected: ${event.detail.reason || 'Unknown error'}`);
          }
        });
  
        rfb.addEventListener('securityfailure', (event: any) => {
          console.error('noVNC security failure:', event.detail);
          onError('Console authentication failed. Please try again.');
        });
  
      } catch (e: any) {
        console.error('Failed to initialize noVNC:', e);
        onError(`Failed to initialize console: ${e.message}`);
      }
    }
  }, [selectedOption, onError]);
  

  const renderConsoleContent = () => {
    if (!selectedOption) {
      return <div className="p-4 text-center">Loading console or no option selected...</div>;
    }

    if (selectedOption.type === 'proxmox') {
      // This div is the target for the noVNC canvas
      return <div ref={screenRef} className="w-full h-full" />;
    }

    if (selectedOption.type === 'vsphere_html5') {
      const details = selectedOption.connectionDetails as VSphereHtml5ConnectionDetails;
      if (details.url) {
        return (
          <iframe
            src={details.url}
            title={`${consoleDetails.vmName} Console (${selectedOption.name || selectedOption.type})`}
            className="w-full h-full border-0"
            allowFullScreen
          />
        );
      }
    }

    // Fallback for unimplemented types
    return <div className="p-4 text-center">Console type '{selectedOption.type}' is not yet renderable with this method.</div>;
  };

  return (
    <div className="flex flex-col w-screen h-screen bg-slate-900 text-white">
      <header className="bg-slate-800 p-3 flex justify-between items-center shadow-md flex-shrink-0">
        <h1 className="text-lg font-semibold truncate pr-2" title={consoleDetails.vmName}>
          Console: {consoleDetails.vmName}
          {selectedOption && <span className="text-sm text-slate-400 ml-2">({selectedOption.name || selectedOption.type})</span>}
        </h1>
        <button
          onClick={onClose}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md transition-colors"
          title="Close Console Window"
        >
          Close
        </button>
      </header>
      <main className="flex-grow overflow-hidden bg-black">
        {renderConsoleContent()}
      </main>
    </div>
  );
};

export default VMConsoleView;
