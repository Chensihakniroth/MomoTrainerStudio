import subprocess
result = subprocess.run(['powershell', '-Command', 'Get-ChildItem \\\\.\\\\pipe\\\\ | Select-Object Name'], capture_output=True, text=True)
print('Existing pipes:')
print(result.stdout[:1000] if result.stdout else '(none)')
print(result.stderr[:500] if result.stderr else '')
