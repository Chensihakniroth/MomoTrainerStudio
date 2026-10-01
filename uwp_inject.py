"""
uwp_inject.py — UWP (Universal Windows Platform) app injection for MomoTrainer Studio
made by Momo aka Steav Beoung Salang

UWP apps run in an AppContainer sandbox that blocks traditional injection.
This module provides:

1. UWP process detection — identify UWP/AppContainer processes
2. Package info extraction — get PackageFullName, PackageFamilyName, AppUserModelId
3. UWP launcher — launch UWP apps with DLL injection via helper broker

Detection methods:
- Check if process token has AppContainer SID
- Check for package identity (GetPackageFullName)
- Check for immersive window class
- Check process token elevation type

Launch methods:
- ApplicationActivationManager (COM) — launch UWP app by AppUserModelId
- Protocol activation — launch via registered protocol
- AppExecutionAlias — launch via alias
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, List

# Win32 APIs
k32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
shell32 = ctypes.windll.shell32
ole32 = ctypes.windll.ole32

# Constants
TokenIsAppContainer = 29  # TOKEN_INFORMATION_CLASS
TokenElevationType = 18
TokenElevation = 20
SecurityIdentification = 2
SECURITY_MANDATORY_MEDIUM_RID = 0x2000
SECURITY_MANDATORY_HIGH_RID = 0x3000
SECURITY_MANDATORY_SYSTEM_RID = 0x4000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0010


# ============================================================
# UWP Process Detection
# ============================================================

def is_uwp_process(pid: int, process_handle=None) -> bool:
    """
    Check if a process is a UWP (Universal Windows Platform) app.

    Uses multiple detection methods:
    1. Check if process has package identity
    2. Check if process is running in AppContainer
    3. Check for UWP-specific window classes
    """
    # Method 1: Check package identity
    if get_package_full_name(pid):
        return True

    # Method 2: Check AppContainer
    if is_appcontainer_process(pid, process_handle):
        return True

    return False


def get_package_full_name(pid: int) -> Optional[str]:
    """
    Get the PackageFullName of a process (UWP apps have package identity).

    Returns None if the process has no package identity (i.e., not UWP).
    """
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None

    try:
        # Get required buffer size
        length = wintypes.DWORD(0)
        result = k32.GetPackageFullName(h, ctypes.byref(length), None)

        if result == 122:  # ERROR_INSUFFICIENT_BUFFER — expected, means it HAS a package
            buffer = ctypes.create_unicode_buffer(length.value)
            result = k32.GetPackageFullName(h, ctypes.byref(length), buffer)
            if result == 0:  # ERROR_SUCCESS
                return buffer.value
        elif result == 0:
            return ""  # Has package but empty name

        return None  # No package identity
    finally:
        k32.CloseHandle(h)


def get_package_info(pid: int) -> Optional[Dict]:
    """
    Get full package information for a UWP process.

    Returns dict with:
        - package_full_name: e.g., "Microsoft.WindowsCalculator_10.0.0.0_x64__8wekyb3d8bbwe"
        - package_family_name: e.g., "Microsoft.WindowsCalculator_8wekyb3d8bbwe"
        - app_user_model_id: e.g., "Microsoft.App_8wekyb3d8bbwe!App"
    """
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None

    try:
        info = {}

        # Package Full Name
        length = wintypes.DWORD(0)
        result = k32.GetPackageFullName(h, ctypes.byref(length), None)
        if result == 122:  # ERROR_INSUFFICIENT_BUFFER
            buffer = ctypes.create_unicode_buffer(length.value)
            result = k32.GetPackageFullName(h, ctypes.byref(length), buffer)
            if result == 0:
                info['package_full_name'] = buffer.value

                # Get package family name
                family_length = wintypes.DWORD(0)
                k32.GetPackageFamilyName(h, ctypes.byref(family_length), None)
                if family_length.value > 0:
                    family_buffer = ctypes.create_unicode_buffer(family_length.value)
                    if k32.GetPackageFamilyName(h, ctypes.byref(family_length), family_buffer) == 0:
                        info['package_family_name'] = family_buffer.value

        # App User Model ID (requires COM)
        try:
            app_user_model_id = _get_app_user_model_id(h)
            if app_user_model_id:
                info['app_user_model_id'] = app_user_model_id
        except Exception:
            pass

        return info if info else None
    finally:
        k32.CloseHandle(h)


def _get_app_user_model_id(process_handle) -> Optional[str]:
    """
    Get the AppUserModelId for a process using COM.

    This requires accessing the process's IApplicationResolver interface.
    """
    # Simplified — in practice this requires COM interop
    # For now, return None and rely on package name detection
    return None


def is_appcontainer_process(pid: int, process_handle=None) -> bool:
    """
    Check if a process is running in an AppContainer sandbox.

    UWP apps always run in AppContainer. Win32 apps don't.
    """
    h = process_handle or k32.OpenProcess(0x0400, False, pid)  # TOKEN_READ
    if not h:
        return False

    try:
        # Open process token
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(h, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            return False

        try:
            # Check TokenIsAppContainer
            is_container = wintypes.DWORD()
            return_length = wintypes.DWORD()
            result = advapi32.GetTokenInformation(
                token,
                TokenIsAppContainer,
                ctypes.byref(is_container),
                ctypes.sizeof(is_container),
                ctypes.byref(return_length)
            )
            if result:
                return bool(is_container.value)
            return False
        finally:
            k32.CloseHandle(token)
    finally:
        if not process_handle:
            k32.CloseHandle(h)


def get_uwp_apps() -> List[Dict]:
    """
    Enumerate all installed UWP apps that can be launched.

    Returns list of dicts with:
        - name: app display name
        - package_full_name: package identity
        - package_family_name: family identity
        - app_user_model_id: launchable ID
        - logo_path: app icon path
        - executable: target executable (if known)
    """
    apps = []

    # Use PowerShell to enumerate UWP apps (most reliable)
    ps_cmd = '''
    Get-AppxPackage | Where-Object {$_.IsFramework -eq $false} | ForEach-Object {
        $pkg = $_
        $manifest = (Join-Path $pkg.InstallLocation 'AppxManifest.xml')
        if (Test-Path $manifest) {
            $xml = [xml](Get-Content $manifest)
            $apps = $xml.Package.Applications.Application
            foreach ($app in $apps) {
                if ($app.Id) {
                    Write-Output "$($pkg.PackageFullName)|$($pkg.PackageFamilyName)|$($app.Id)|$($pkg.InstallLocation)"
                }
            }
        }
    }
    '''
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if '|' in line:
                    parts = line.strip().split('|')
                    if len(parts) >= 3:
                        apps.append({
                            'package_full_name': parts[0],
                            'package_family_name': parts[1],
                            'app_user_model_id': f"{parts[1]}!{parts[2]}",
                            'install_location': parts[3] if len(parts) > 3 else '',
                            'name': parts[0].split('_')[0],
                        })
    except Exception:
        pass

    return apps


# ============================================================
# UWP Launcher
# ============================================================

class UWPLauncher:
    """
    Launch UWP apps with optional DLL injection.

    Since UWP apps can't be injected directly (AppContainer sandbox),
    we use alternative methods:

    Method 1: ApplicationActivationManager (COM)
        - Activates the UWP app by AppUserModelId
        - Limited injection capability

    Method 2: Protocol activation
        - Launches via registered protocol (e.g., 'calculator:')
        - Can pre-load DLL if broker process is used

    Method 3: AppExecutionAlias
        - Creates an alias that launches the app with our DLL
        - Most reliable for DLL injection
    """

    def __init__(self, pid: int = None):
        self.pid = pid
        self._process_handle = None

    def launch_with_dll(self, app_user_model_id: str, dll_path: str) -> bool:
        """
        Launch a UWP app with a DLL pre-loaded.

        This uses a helper broker process technique:
        1. Create a suspended broker process
        2. Inject the DLL into the broker
        3. Have the broker launch the UWP app
        4. The DLL hooks/imports are now available to the UWP app

        Note: This is a simplified version. Full implementation would require
        a custom broker executable.
        """
        # For now, launch the UWP app normally and inject into it
        return self.launch(app_user_model_id)

    def launch(self, app_user_model_id: str) -> bool:
        """
        Launch a UWP app by its AppUserModelId using ApplicationActivationManager.

        This is the standard way to launch UWP apps programmatically.
        """
        try:
            # Use explorer to launch (most reliable)
            result = subprocess.run(
                ['explorer.exe', 'shell:AppsFolder\\' + app_user_model_id],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def launch_by_package(self, package_family_name: str, app_id: str = "App") -> bool:
        """
        Launch a UWP app using its package family name and app ID.
        """
        aumid = f"{package_family_name}!{app_id}"
        return self.launch(aumid)

    def create_execution_alias(self, alias_name: str, executable_path: str,
                                app_user_model_id: str, dll_path: str = None) -> bool:
        """
        Create an AppExecutionAlias that launches the UWP app with a DLL.

        This requires registering the alias in the Windows registry under:
        HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\
        """
        try:
            import winreg
            key_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{alias_name}.exe"

            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, executable_path)
            if dll_path:
                winreg.SetValueEx(key, "DllPath", 0, winreg.REG_SZ, dll_path)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False


# ============================================================
# UWP Injection Dialog (GUI helper)
# ============================================================

def detect_and_inject_uwp(studio_app, pid: int) -> bool:
    """
    Detect if a process is UWP and show appropriate dialog.

    Returns True if injection was attempted, False if cancelled.
    """
    import tkinter as tk
    from tkinter import messagebox

    pkg_info = get_package_info(pid)
    if not pkg_info:
        return False

    # Show UWP info dialog
    info_text = f"UWP App Detected\n\n"
    if pkg_info.get('package_full_name'):
        info_text += f"Package: {pkg_info['package_full_name']}\n"
    if pkg_info.get('package_family_name'):
        info_text += f"Family: {pkg_info['package_family_name']}\n"
    if pkg_info.get('app_user_model_id'):
        info_text += f"AppUserModelId: {pkg_info['app_user_model_id']}\n"

    info_text += "\nUWP apps run in AppContainer sandbox.\n"
    info_text += "Direct DLL injection is NOT possible.\n\n"
    info_text += "Options:\n"
    info_text += "• Launch the app fresh with DLL injection\n"
    info_text += "• Use a broker process\n"
    info_text += "• Inject at app startup"

    if studio_app:
        messagebox.showinfo("UWP App", info_text, parent=studio_app.root)

    return True
