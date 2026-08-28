@echo off
title Cypher OSINT
cd /d "%~dp0"
set "PATH=%USERPROFILE%\.local\bin;%PATH%"

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Python 3.10+ is required and was not found.
  echo   Install it from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
  echo   then double-click this file again.
  echo.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo First run - setting up Cypher. This takes a few minutes...
  python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -e ".[all]"
  ".venv\Scripts\python.exe" -m pip install pipx
  for %%T in (sherlock-project holehe maigret socialscan) do ".venv\Scripts\python.exe" -m pipx install %%T
  ".venv\Scripts\python.exe" -m pipx ensurepath
  echo Setup complete.
  echo.
)

if not exist ".env" echo CYPHER_LLM=cli> .env

where claude >nul 2>nul
if errorlevel 1 (
  echo.
  echo   NOTE: AI chat and briefings run on your Claude subscription via Claude Code.
  echo   Install it and run 'claude' once to log in - then it's free, no credits.
  echo   Scans, graph and profile cards work now without it.
  echo.
)

echo Starting Cypher UI - your browser will open at http://127.0.0.1:8765
".venv\Scripts\python.exe" -m cypher.web
pause
