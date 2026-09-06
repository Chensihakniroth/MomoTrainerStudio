@echo off
title DummyGame - MomoTrainer Testing
echo =========================================
echo  DummyGame for MomoTrainer Testing
echo =========================================
echo.
echo Memory addresses (scan these in MomoStudio):
echo   Health: 0x[printed by game]
echo   Ammo:   0x[printed by game]
echo   Gold:   0x[printed by game]
echo.
echo Commands: D=damage  H=heal  S=shoot  R=reload  G=gold  Q=quit
echo.
python "%~dp0DummyGame.py"
pause
