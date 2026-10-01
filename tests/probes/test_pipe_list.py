import subprocess
result = subprocess.run(['cmd', '/c', 'dir', '\\\\.\\pipe\\'], capture_output=True, text=True)
print('Existing pipes (first 500 chars):')
print(result.stdout[:500] if result.stdout else '(none)')
print(result.stderr[:200] if result.stderr else '')
