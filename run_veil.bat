@echo off
title VEIL 3.0 - Network Traffic Exposer - NEATLABS
echo.
echo  ========================================
echo   VEIL 3.0 - Network Traffic Exposer
echo   NEATLABS Intelligence Technology
echo  ========================================
echo.
echo  Starting VEIL dashboard...
echo.
python main.py %*
if errorlevel 1 (
    echo.
    echo  [ERROR] VEIL failed to start.
    echo  Make sure Python 3.9+ and PyQt6 are installed:
    echo    pip install PyQt6 PyQt6-WebEngine psutil
    echo.
    echo  TIP: Put all downloaded files in ONE folder and re-run.
    echo       VEIL will auto-organize them into the right structure.
    echo.
    pause
)
