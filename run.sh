#!/bin/bash
echo "[*] Checking Python environment and dependencies..."
python3 -m pip install -r requirements.txt --quiet

echo "[*] Launching AHM Web Scanner..."
python3 main.py
