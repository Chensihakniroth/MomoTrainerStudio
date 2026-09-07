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

echo [2/2] Running PyInstaller with MomoTrainer Studio.spec...
pyinstaller --clean --noconfirm "MomoTrainer Studio.spec"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed! Check the output above.
    pause
    exit /b %errorlevel%
)

echo.
echo ========================================================
echo   [SUCCESS] MomoTrainer Studio.exe built successfully!
echo   Output location: %~dp0dist\MomoTrainer Studio.exe
echo ========================================================
echo.
endlocal
