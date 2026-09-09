const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Process management
  listProcesses: () => ipcRenderer.invoke('process:list'),
  attachProcess: (pid) => ipcRenderer.invoke('process:attach', pid),
  
  // Memory scanning
  startScan: (params) => ipcRenderer.invoke('scan:start', params),
  
  // Memory operations
  readMemory: (address, size) => ipcRenderer.invoke('memory:read', address, size),
  writeMemory: (address, data) => ipcRenderer.invoke('memory:write', address, data),
  
  // Generic backend command
  command: (cmd) => ipcRenderer.invoke('backend:command', cmd),
});
