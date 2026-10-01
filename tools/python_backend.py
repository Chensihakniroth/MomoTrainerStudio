import json
import sys
import os
import subprocess
import ctypes
import ctypes.wintypes as w
import time

# Load the Python modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import memory_scanner as ms

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE
CloseHandle = k32.CloseHandle
CloseHandle.argtypes = [w.HANDLE]
CloseHandle.restype = w.BOOL

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

class BackendServer:
    def __init__(self):
        self.attached_process = None
        self.proc_handle = None
        self.found_addresses = []  # list of Candidate(addr, last)
        self.scan_started = False
        self.scan_type = None
        self.scan_mode = None
        self.last_scan_ms = 0

    def _close_handle(self):
        if self.proc_handle is not None:
            try:
                CloseHandle(self.proc_handle)
            finally:
                self.proc_handle = None
                self.attached_process = None

    @staticmethod
    def _parse_address(value):
        if isinstance(value, bool) or value is None:
            raise ValueError('address is required')
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ValueError('address cannot be empty')
            return int(value, 0) if value.lower().startswith('0x') else int(value, 10)
        return int(value)

    @staticmethod
    def _parse_size(value, *, allow_zero=False):
        try:
            size = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError('size must be an integer') from exc
        if size < (0 if allow_zero else 1) or size > 16 * 1024 * 1024:
            raise ValueError('size is outside the supported range')
        return size

    def close(self):
        """Release the process handle; safe to call more than once."""
        self._close_handle()
        self.found_addresses = []
        self.scan_started = False
        
    def handle_command(self, cmd):
        cmd_id = cmd.get('cmdId')
        try:
            action = cmd.get('action')
            
            if action == 'list_processes':
                res = self._list_processes()
            elif action == 'attach_process':
                res = self._attach_process(cmd.get('pid'))
            elif action == 'detach_process':
                self.close()
                res = {'status': 'ok', 'message': 'Detached'}
            elif action == 'get_status':
                res = self._status()
            elif action == 'clear_scan':
                self.found_addresses = []
                self.scan_started = False
                res = {'status': 'ok'}
            elif action == 'start_scan':
                res = self._start_scan(cmd)
            elif action == 'read_memory':
                res = self._read_memory(cmd.get('address'), cmd.get('size'))
            elif action == 'write_memory':
                res = self._write_memory(cmd.get('address'), cmd.get('data'))
            else:
                res = {'error': f'Unknown action: {action}'}

        except Exception as e:
            res = {'error': str(e)}

        if cmd_id is not None and isinstance(res, dict):
            res['cmdId'] = cmd_id
        return res
    
    def _list_processes(self):
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
                        try:
                            pid = int(parts[1].strip('"'))
                            processes.append({'name': name, 'pid': pid})
                        except ValueError:
                            pass
            
            return {'status': 'ok', 'processes': processes}
        except Exception as e:
            return {'error': str(e)}
    
    def _attach_process(self, pid):
        try:
            if not pid:
                return {'error': 'PID required'}

            pid = int(pid)
            if pid <= 0:
                return {'error': 'PID must be a positive integer'}
            self._close_handle()

            h = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h:
                # Retry with read/query permissions
                h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                                False, pid)

            if not h:
                err = ctypes.get_last_error()
                return {'error': f'Failed to open process PID {pid} (error code {err})'}

            self.proc_handle = h
            self.attached_process = pid
            self.found_addresses = []
            self.scan_started = False
            return {'status': 'ok', 'pid': pid, 'message': f'Attached to PID {pid}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _start_scan(self, cmd):
        try:
            if not self.proc_handle:
                return {'error': 'No process attached'}

            raw_val = cmd.get('value')
            value_type = str(cmd.get('value_type', 'int32')).strip().lower()
            scan_mode = str(cmd.get('scan_mode', 'exact')).strip().lower()
            high = cmd.get('high')
            reset = bool(cmd.get('new_scan') or cmd.get('reset'))
            if reset:
                self.found_addresses = []
                self.scan_started = False

            # Parse string to correct numerical/binary representation
            value = raw_val
            if raw_val is not None:
                if value_type in ('int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64'):
                    s = str(raw_val).strip()
                    value = int(s, 16) if s.startswith(('0x', '0X')) else int(s)
                elif value_type in ('float', 'double'):
                    value = float(raw_val)
                elif value_type == 'string':
                    value = str(raw_val)
            if scan_mode not in ('changed', 'unchanged', 'increased', 'decreased') and raw_val is None:
                return {'error': f'Value is required for scan mode {scan_mode!r}'}
            if high is not None and value_type in ('float', 'double'):
                high = float(high)
            elif high is not None and value_type != 'string':
                high = int(str(high), 0) if isinstance(high, str) else int(high)

            started = time.perf_counter()
            was_first_scan = not self.scan_started
            if was_first_scan:
                # First scan
                candidates = ms.first_scan(
                    self.proc_handle,
                    value_type,
                    value,
                    mode=scan_mode,
                    high=high,
                    case_sensitive=bool(cmd.get('case_sensitive', False)),
                    nthreads=cmd.get('nthreads'),
                    fast_scan=True
                )
            else:
                # Next scan
                candidates = ms.rescan(
                    self.proc_handle,
                    self.found_addresses,
                    value_type,
                    value,
                    mode=scan_mode,
                    high=high,
                    case_sensitive=bool(cmd.get('case_sensitive', False)),
                    nthreads=cmd.get('nthreads'),
                    fast_scan=True
                )

            self.found_addresses = candidates
            self.scan_started = True
            self.scan_type = value_type
            self.scan_mode = scan_mode
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_scan_ms = elapsed_ms
            addrs = [c.addr for c in candidates[:100]]
            return {
                'status': 'ok',
                'count': len(candidates),
                'addresses': addrs,
                'returned': len(addrs),
                'truncated': len(candidates) > len(addrs),
                'phase': 'first' if was_first_scan else 'next',
                'elapsed_ms': elapsed_ms,
                'value_type': value_type,
                'scan_mode': scan_mode,
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _read_memory(self, address, size):
        try:
            if not self.proc_handle:
                return {'error': 'Invalid parameters'}

            address = self._parse_address(address)
            size = self._parse_size(size)

            data = ms.rblock(self.proc_handle, address, size)
            if data is None:
                err = ctypes.get_last_error()
                return {'error': f'Unable to read 0x{size:X} bytes at 0x{address:X} (error code {err})'}
            return {
                'status': 'ok',
                'address': hex(address),
                'data': data.hex(),
                'size': len(data),
                'complete': len(data) == size,
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _write_memory(self, address, data):
        try:
            if not self.proc_handle:
                return {'error': 'Invalid parameters'}
            address = self._parse_address(address)
            if not isinstance(data, str) or not data.strip():
                return {'error': 'data must be a non-empty hex string'}
            data_bytes = bytes.fromhex(data)
            
            ok = ms.wblock(self.proc_handle, address, data_bytes)
            if not ok:
                return {'error': 'WriteProcessMemory failed'}
            return {'status': 'ok', 'address': hex(address), 'size': len(data_bytes)}
        except Exception as e:
            return {'error': str(e)}

    def _status(self):
        return {
            'status': 'ok',
            'attached': self.proc_handle is not None,
            'pid': self.attached_process,
            'scan_started': self.scan_started,
            'scan_count': len(self.found_addresses),
            'value_type': self.scan_type,
            'scan_mode': self.scan_mode,
            'last_scan_ms': self.last_scan_ms,
        }


def main():
    server = BackendServer()
    
    try:
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                line_str = line.strip()
                if not line_str:
                    continue

                cmd = json.loads(line_str)
                response = server.handle_command(cmd)

                sys.stdout.write(json.dumps(response) + '\n')
                sys.stdout.flush()
            except json.JSONDecodeError as exc:
                sys.stdout.write(json.dumps({'error': f'Invalid JSON: {exc.msg}'}) + '\n')
                sys.stdout.flush()
            except KeyboardInterrupt:
                break
            except Exception as e:
                sys.stdout.write(json.dumps({'error': f'Server error: {str(e)}'}) + '\n')
                sys.stdout.flush()
    finally:
        server.close()

if __name__ == '__main__':
    main()
