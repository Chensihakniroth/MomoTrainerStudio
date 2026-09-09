@echo off
REM ============================================================
REM MomoTrainerStudio Kernel Driver Build Script
REM Requires: Windows Driver Kit (WDK) installed
REM Usage: build.bat [debug|release]
REM ============================================================

setlocal enabledelayedexpansion

REM Check if WDK is installed
if not defined WDDK_ROOT (
    echo ERROR: Windows Driver Kit (WDK) not found.
    echo Please install WDK and set WDDK_ROOT environment variable.
    echo Download: https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit
    exit /b 1
)

REM Default to debug build
set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=debug

REM Change to driver directory
cd /d "%~dp0"

echo ============================================
echo MomoTrainer Kernel Driver Build
echo ============================================
echo Build Type: %BUILD_TYPE%
echo WDK Root: %WDDK_ROOT%
echo Working Dir: %CD%
echo ============================================

REM Set up WDK environment
if exist "%WDDK_ROOT%\bin\x86\build.exe" (
    call "%WDDK_ROOT%\bin\x86\build.exe" /nologo /z
) else (
    echo ERROR: WDK build.exe not found at expected path.
    exit /b 1
)

REM Clean previous build
if exist "MomoTrainerDrv.sys" (
    echo Cleaning previous build...
    del /f "MomoTrainerDrv.sys"
    if exist "*.obj" del /f "*.obj"
    if exist "*.pdb" del /f "*.pdb"
)

REM Build the driver
echo Building MomoTrainer kernel driver...
call "%WDDK_ROOT%\bin\x86\build.exe" -c -x86 -z -nologo -p -f

if errorlevel 1 (
    echo ERROR: Build failed!
    exit /b 1
)

REM Check if driver was built
if exist "MomoTrainerDrv.sys" (
    echo ============================================
    echo BUILD SUCCESSFUL!
    echo Driver: %CD%\MomoTrainerDrv.sys
    echo ============================================
    REM Display driver info
    if exist "MomoTrainerDrv.sys" (
        for %%A in ("MomoTrainerDrv.sys") do (
            echo Size: %%~zA bytes
            echo Date: %%~tA
        )
    )
    exit /b 0
) else (
    echo ERROR: Build failed - MomoTrainerDrv.sys not found!
    exit /b 1
)