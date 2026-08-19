@echo off
title AHM Web Scanner
echo [*] Installing dependencies for AHM Web Scanner...
python -m pip install -r requirements.txt --quiet
echo.
echo [*] Starting AHM Web Scanner...
python main.py
pause
