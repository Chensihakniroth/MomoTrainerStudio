const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

let mainWindow;
let pythonProcess;
let pythonQueue = [];
let stdoutBuffer = '';

// Paths
const appDataPath = path.join(process.env.APPDATA, 'MomoTrainer Studio');
const logFile = path.join(appDataPath, 'app.log');
const tempPythonDir = path.join(os.tmpdir(), 'momotrainer-python');

// Ensure app data directory exists
if (!fs.existsSync(appDataPath)) {
  fs.mkdirSync(appDataPath, { recursive: true });
}
if (!fs.existsSync(tempPythonDir)) {
  fs.mkdirSync(tempPythonDir, { recursive: true });
}

function log(msg) {
  const timestamp = new Date().toISOString();
  const logMsg = `[${timestamp}] ${msg}`;
  console.log(logMsg);
  fs.appendFileSync(logFile, logMsg + '\n', (err) => {
    if (err && err.code !== 'ENOENT') console.error('Log write error:', err);
  });
}

function extractPythonFilesFromAsar() {
  /**
   * Extract python_backend.py and dependencies from app.asar to temp directory.
   * Returns the path to the extracted python_backend.py, or null if extraction fails.
   */
  try {
    const asarPath = path.join(process.resourcesPath, 'app.asar');
    if (!fs.existsSync(asarPath)) {
      log('app.asar not found, trying direct file access');
      return null;
    }

    log(`Extracting Python files from ${asarPath}...`);
    
    // Use asar module if available (bundled with electron)
    try {
      const asar = require('asar');
      const files = ['python_backend.py', 'memory_scanner.py'];
      
      files.forEach(file => {
        const srcPath = path.join(asarPath, file);
        const dstPath = path.join(tempPythonDir, file);
        try {
          const content = asar.extractFile(asarPath, file);
          fs.writeFileSync(dstPath, content);
          log(`Extracted ${file} to ${dstPath}`);
        } catch (e) {
          log(`Failed to extract ${file}: ${e.message}`);
        }
      });

      const backendPath = path.join(tempPythonDir, 'python_backend.py');
      if (fs.existsSync(backendPath)) {
        log(`Successfully extracted python_backend.py`);
        return backendPath;
      }
    } catch (e) {
      log(`asar module not available: ${e.message}`);
    }

  } catch (err) {
    log(`Error in extractPythonFilesFromAsar: ${err.message}`);
  }
  
  return null;
}

function startPythonBackend() {
  log('Starting Python backend...');
  
  try {
    // Get the path to python_backend.py
    let backendPath = null;

    // Try multiple locations
    const candidates = [
      path.join(__dirname, '..', '..', 'python_backend.py'),  // Dev mode: relative to electron/
      path.join(process.resourcesPath, 'app', 'python_backend.py'),  // Unpacked from asar
      path.join(process.resourcesPath, 'python_backend.py'),  // In resources root
      path.join(tempPythonDir, 'python_backend.py'),  // Previously extracted
    ];
    
    for (const candidate of candidates) {
      log(`Checking candidate: ${candidate}`);
      try {
        if (fs.existsSync(candidate)) {
          backendPath = candidate;
          log(`Found backend at: ${backendPath}`);
          break;
        }
      } catch (e) {
        log(`fs.existsSync threw for ${candidate}: ${e.message}`);
      }
    }

    // If not found, always try to extract from asar
    if (!backendPath) {
      log('Backend not found in standard locations, attempting extraction from asar...');
      backendPath = extractPythonFilesFromAsar();
    } else {
      log('Backend already found, skipping extraction');
    }

    if (!backendPath) {
      log('Could not locate or extract python_backend.py');
      dialog.showErrorBox('Backend Error', 'python_backend.py not found in application package');
      return;
    }
    
    // Try both python and python3
    let pythonCmd = 'python';
    
    pythonProcess = spawn(pythonCmd, [backendPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    });
    
    log(`Python process spawned (PID: ${pythonProcess.pid})`);
    
    // Handle stdout - CRITICAL: buffer incomplete lines
    pythonProcess.stdout.on('data', (data) => {
      stdoutBuffer += data.toString();
      log(`[stdout buffer] +${data.length} bytes, total: ${stdoutBuffer.length}`);
      
      // Split on newlines; keep incomplete line in buffer
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop(); // Keep last (potentially incomplete) line
      
      // Parse complete lines
      lines.forEach(line => {
        if (line.trim()) {
          try {
            const response = JSON.parse(line);
            log(`[response] ${JSON.stringify(response).substring(0, 100)}...`);
            
            if (pythonQueue.length > 0) {
              const { resolve, cmd } = pythonQueue.shift();
              log(`[resolved] queue length now: ${pythonQueue.length}`);
              resolve(response);
            } else {
              log('[orphan response] No pending command for this response');
            }
          } catch (e) {
            log(`[parse error] Line: ${line.substring(0, 100)}, Error: ${e.message}`);
          }
        }
      });
    });
    
    // Handle stderr
    pythonProcess.stderr.on('data', (data) => {
      const msg = data.toString();
      log(`[stderr] ${msg}`);
    });
    
    // Handle process exit
    pythonProcess.on('exit', (code, signal) => {
      log(`Python process exited (code: ${code}, signal: ${signal})`);
      pythonProcess = null;
      
      // Reject all pending commands
      pythonQueue.forEach(({ reject }) => {
        reject(new Error('Python process exited'));
      });
      pythonQueue = [];
    });
    
    pythonProcess.on('error', (err) => {
      log(`Python process error: ${err.message}`);
      dialog.showErrorBox('Backend Error', `Failed to start Python backend: ${err.message}`);
    });
    
  } catch (err) {
    log(`Failed to spawn Python: ${err.message}`);
    dialog.showErrorBox('Backend Error', `Failed to start Python backend: ${err.message}`);
  }
}

function sendPythonCommand(cmd) {
  return new Promise((resolve, reject) => {
    if (!pythonProcess) {
      reject(new Error('Python backend not running'));
      return;
    }
    
    log(`[send] action="${cmd.action}" queue_length=${pythonQueue.length}`);
    
    pythonQueue.push({ cmd, resolve, reject });
    
    // Send the command
    try {
      pythonProcess.stdin.write(JSON.stringify(cmd) + '\n');
    } catch (err) {
      pythonQueue.pop();
      reject(err);
      return;
    }
    
    // Timeout after 10 seconds (commands hang if Python crashes or gets stuck)
    const timeoutId = setTimeout(() => {
      const idx = pythonQueue.findIndex(item => item.cmd === cmd);
      if (idx !== -1) {
        pythonQueue.splice(idx, 1);
        log(`[timeout] action="${cmd.action}"`);
        reject(new Error(`Command timeout: ${cmd.action}`));
      }
    }, 10000);
    
    // Clear timeout if resolved/rejected early
    const wrappedResolve = (result) => {
      clearTimeout(timeoutId);
      resolve(result);
    };
    const wrappedReject = (err) => {
      clearTimeout(timeoutId);
      reject(err);
    };
    
    // Replace resolve/reject in queue
    pythonQueue[pythonQueue.length - 1].resolve = wrappedResolve;
    pythonQueue[pythonQueue.length - 1].reject = wrappedReject;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
    },
  });

  const indexPath = path.join(__dirname, '../dist/index.html');
  log(`Loading UI from: ${indexPath}`);
  mainWindow.loadFile(indexPath);
  
  // Open DevTools in dev mode
  if (process.env.ELECTRON_DEV_MODE) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
  
  log('Window created and UI loaded');
}

// IPC Handlers - Bridge to Python backend
ipcMain.handle('process:list', async () => {
  try {
    const result = await sendPythonCommand({ action: 'list_processes' });
    return result;
  } catch (err) {
    log(`[process:list error] ${err.message}`);
    return { error: err.message };
  }
});

ipcMain.handle('process:attach', async (event, pid) => {
  try {
    const result = await sendPythonCommand({ action: 'attach_process', pid });
    return result;
  } catch (err) {
    log(`[process:attach error] ${err.message}`);
    return { error: err.message };
  }
});

ipcMain.handle('scan:start', async (event, params) => {
  try {
    const cmd = {
      action: 'start_scan',
      value: params.value,
      value_type: params.value_type,
      scan_mode: params.scan_mode,
    };
    const result = await sendPythonCommand(cmd);
    return result;
  } catch (err) {
    log(`[scan:start error] ${err.message}`);
    return { error: err.message };
  }
});

ipcMain.handle('memory:read', async (event, address, size) => {
  try {
    const result = await sendPythonCommand({
      action: 'read_memory',
      address: typeof address === 'string' ? parseInt(address, 16) : address,
      size,
    });
    return result;
  } catch (err) {
    log(`[memory:read error] ${err.message}`);
    return { error: err.message };
  }
});

ipcMain.handle('memory:write', async (event, address, data) => {
  try {
    const result = await sendPythonCommand({
      action: 'write_memory',
      address: typeof address === 'string' ? parseInt(address, 16) : address,
      data,
    });
    return result;
  } catch (err) {
    log(`[memory:write error] ${err.message}`);
    return { error: err.message };
  }
});

app.on('ready', () => {
  log('App ready event');
  startPythonBackend();
  createWindow();
});

app.on('window-all-closed', () => {
  log('All windows closed');
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

// Cleanup on app quit
app.on('before-quit', () => {
  log('App quitting, killing Python process');
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
});
