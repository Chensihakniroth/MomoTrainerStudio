<#
  msvc_build.ps1 — compile a C/C++ source to a DLL with MSVC.

  Bare `cl` fails because it needs INCLUDE/LIB/PATH set by vcvars64.
  MSYS bash also mangles `cmd //c` into an interactive shell, so this
  runs through powershell -File instead.

  Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\msvc_build.ps1 `
        -Source x.cpp -Output x.dll [-ExtraArgs "/link /DLL"]
#>
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$ExtraArgs = "",
    [string]$Vcvars = "D:\VS2022BT\VC\Auxiliary\Build\vcvars64.bat",
    # "dll" (default) or "exe". /LD and /SUBSYSTEM:CONSOLE are mutually
    # exclusive — a .exe built with /LD is a DLL with the wrong name.
    [ValidateSet("dll", "exe")][string]$Type = "dll"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Vcvars)) {
    Write-Output "ERROR: vcvars64.bat not found at $Vcvars"
    exit 1
}

if (-not (Test-Path $Source)) {
    Write-Output "ERROR: source not found: $Source"
    exit 1
}

# Import the MSVC environment into this process so cl.exe is usable.
$envDump = & cmd.exe /c "`"$Vcvars`" >nul 2>&1 && set"
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') {
        Set-Item -Path "Env:$($matches[1])" -Value $matches[2]
    }
}

$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $cl) {
    Write-Output "ERROR: cl.exe still not on PATH after vcvars64"
    exit 1
}
Write-Output "[msvc_build] cl = $($cl.Source)"

$objDir = Join-Path $env:TEMP "momo_msvc_obj"
if (-not (Test-Path $objDir)) { New-Item -ItemType Directory -Path $objDir | Out-Null }

# /SUBSYSTEM and /LD are LINKER options, not compiler options. Passing them
# to cl warns D9002 and silently relies on the default — put them after /link.
$typeArgs = if ($Type -eq "exe") { @("/link", "/SUBSYSTEM:CONSOLE") } else { @("/link", "/DLL") }

$argList = @(
    "/nologo", "/O2", "/EHsc",
    $Source,
    "/Fe:$Output",
    "/Fo:$objDir\"
) + $typeArgs
if ($ExtraArgs) { $argList += $ExtraArgs.Split(" ") }

Write-Output "[msvc_build] cl $($argList -join ' ')"
& cl.exe @argList
$code = $LASTEXITCODE

if ($code -ne 0) {
    Write-Output "[msvc_build] FAILED (exit $code)"
    exit $code
}

if (-not (Test-Path $Output)) {
    Write-Output "[msvc_build] cl reported success but $Output is missing"
    exit 1
}
$len = (Get-Item $Output).Length
Write-Output "[msvc_build] OK -> $Output ($len bytes)"
exit 0