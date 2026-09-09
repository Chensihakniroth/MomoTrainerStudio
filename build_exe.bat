@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   Building MomoTrainer Studio Standalone Executable
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Checking Python and PyInstaller environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not found in PATH.
    pause
    exit /b 1
)

pyinstaller --version >nul 2>&1
if %errorlevel% neq 0 (
    echo PyInstaller not found. Installing PyInstaller...
    pip install pyinstaller pyyaml
)

echo [2/2] Running PyInstaller with the latest QoL-enabled spec...
pyinstaller --clean --noconfirm "MoStudio-beta.spec"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed! Check the output above.
    pause
    exit /b %errorlevel%
)

echo.
echo ========================================================
echo   [SUCCESS] MoStudio - beta.exe built successfully!
echo   Output location: %~dp0dist\MoStudio - beta.exe
echo ========================================================
echo.
endlocal
