@echo off
title Cypher UI
cd /d "%~dp0"

REM Ensure pipx-installed tools (sherlock, holehe, maigret, ...) are found.
set "PATH=%USERPROFILE%\.local\bin;%PATH%"

if not exist ".venv\Scripts\python.exe" (
  echo First-time setup: creating virtual environment...
  python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -e ".[all]"
)

echo Starting Cypher UI... your browser will open at http://127.0.0.1:8765
".venv\Scripts\python.exe" -m cypher.web
pause
