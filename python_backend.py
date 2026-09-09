"""
python_backend.py - IPC server for MomoTrainer Studio (Electron app)
Receives JSON commands on stdin, sends JSON responses on stdout
"""

import json
import sys
import os
import subprocess
import ctypes
import ctypes.wintypes as w
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import memory_scanner as ms

# Win32 bindings for OpenProcess
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

CloseHandle = k32.CloseHandle
CloseHandle.argtypes = [w.HANDLE]
CloseHandle.restype = w.BOOL

class BackendServer:
    def __init__(self):
        self.attached_handle = None
        self.attached_pid = None
        self.found_addresses = []
        
    def handle_command(self, cmd):
        """Process a command from Electron, return response."""
        try:
            action = cmd.get('action')
            
            if action == 'list_processes':
                return self._list_processes()
            elif action == 'attach_process':
                return self._attach_process(cmd.get('pid'))
            elif action == 'start_scan':
                return self._start_scan(cmd)
            elif action == 'read_memory':
                return self._read_memory(cmd.get('address'), cmd.get('size'))
            elif action == 'write_memory':
                return self._write_memory(cmd.get('address'), cmd.get('data'))
            else:
                return {'error': f'Unknown action: {action}'}
                
        except Exception as e:
            import traceback
            return {'error': f'{str(e)}\n{traceback.format_exc()}'}
    
    def _list_processes(self):
        """Return list of running processes."""
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            processes = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('","')
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        pid_str = parts[1].strip('"')
                        try:
                            pid = int(pid_str)
                            processes.append({'name': name, 'pid': pid})
                        except ValueError:
                            pass
            
            return {'status': 'ok', 'processes': processes}
        except Exception as e:
            return {'error': str(e)}
    
    def _attach_process(self, pid):
        """Attach to a process."""
        try:
            if not pid:
                return {'error': 'PID required'}
            
            # Close previous handle if any
            if self.attached_handle:
                try:
                    CloseHandle(self.attached_handle)
                except:
                    pass
            
            # Open new process handle
            # Flags: PROCESS_VM_READ(0x10) | PROCESS_VM_WRITE(0x20) | PROCESS_VM_OPERATION(0x08) | PROCESS_QUERY_INFORMATION(0x0400)
            flags = 0x10 | 0x20 | 0x08 | 0x0400
            handle = OpenProcess(flags, False, pid)
            
            if not handle or handle == -1:
                return {'error': f'Failed to open process {pid}'}
            
            self.attached_handle = handle
            self.attached_pid = pid
            self.found_addresses = []
            
            return {'status': 'ok', 'pid': pid}
        except Exception as e:
            return {'error': str(e)}
    
    def _start_scan(self, cmd):
        """Start a memory scan."""
        try:
            if not self.attached_handle:
                return {'error': 'No process attached'}
            
            value = cmd.get('value')
            value_type = cmd.get('value_type', 'int32')
            scan_mode = cmd.get('scan_mode', 'exact')
            
            # Convert value string to appropriate type
            if value_type in ('float', 'double'):
                try:
                    scan_value = float(value)
                except:
                    return {'error': f'Invalid {value_type} value: {value}'}
            else:
                try:
                    # Try hex first (0x...)
                    if isinstance(value, str) and value.startswith('0x'):
                        scan_value = int(value, 16)
                    else:
                        scan_value = int(value)
                except:
                    return {'error': f'Invalid {value_type} value: {value}'}
            
            # Run scan
            results = ms.first_scan(
                self.attached_handle,
                value_type,
                scan_value,
                mode=scan_mode,
                fast_scan=True,
                nthreads=None
            )
            
            # Convert Candidate namedtuples to addresses (int)
            self.found_addresses = [int(r.address) for r in results[:1000]]  # Cap at 1000
            
            return {
                'status': 'ok',
                'count': len(self.found_addresses),
                'addresses': self.found_addresses[:100]  # Return first 100 for UI
            }
        except Exception as e:
            import traceback
            return {'error': f'{str(e)}\n{traceback.format_exc()}'}
    
    def _read_memory(self, address, size):
        """Read memory at address."""
        try:
            if not self.attached_handle or not address or not size:
                return {'error': 'Invalid parameters'}
            
            # Convert address if it's a string
            if isinstance(address, str):
                address = int(address, 16) if address.startswith('0x') else int(address)
            
            # Use memory_scanner's read function
            data = ms.read_memory(self.attached_handle, address, size)
            
            # Return as hex string
            return {
                'status': 'ok',
                'address': hex(address),
                'data': data.hex() if data else ''
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _write_memory(self, address, data):
        """Write memory at address."""
        try:
            if not self.attached_handle or not address or not data:
                return {'error': 'Invalid parameters'}
            
            # Convert address if it's a string
            if isinstance(address, str):
                address = int(address, 16) if address.startswith('0x') else int(address)
            
            # Convert hex string to bytes
            data_bytes = bytes.fromhex(data)
            
            # Use memory_scanner's write function
            ms.write_memory(self.attached_handle, address, data_bytes)
            
            return {'status': 'ok', 'address': hex(address), 'size': len(data_bytes)}
        except Exception as e:
            return {'error': str(e)}


def main():
    """Main IPC loop."""
    server = BackendServer()
    
    # Unbuffered JSON communication on stdin/stdout
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            cmd = json.loads(line.strip())
            response = server.handle_command(cmd)
            
            # Send response
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()
            
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps({'error': f'Invalid JSON: {str(e)}'}) + '\n')
            sys.stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            import traceback
            sys.stdout.write(json.dumps({'error': f'Server error: {str(e)}\n{traceback.format_exc()}'}) + '\n')
            sys.stdout.flush()


if __name__ == '__main__':
    main()
