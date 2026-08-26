@echo off
title Cypher OSINT
cd /d "%~dp0"

REM Ensure pipx-installed tools (sherlock, holehe, maigret, ...) are found.
set "PATH=%USERPROFILE%\.local\bin;%PATH%"

REM Require Python.
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

REM First run: build the venv, install Cypher, and install the OSINT tools.
if not exist ".venv\Scripts\python.exe" (
  echo First run - setting up Cypher. This takes a few minutes...
  python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -e ".[all]"
  echo Installing OSINT tools ^(sherlock, holehe, maigret, socialscan^)...
  ".venv\Scripts\python.exe" -m pip install pipx
  for %%T in (sherlock-project holehe maigret socialscan) do ".venv\Scripts\python.exe" -m pipx install %%T
  ".venv\Scripts\python.exe" -m pipx ensurepath
  echo Setup complete.
  echo.
)

REM Default to subscription mode (free — uses the Claude CLI, no API credits).
if not exist ".env" echo CYPHER_LLM=cli> .env

REM Check the Claude CLI (needed for AI on your subscription).
where claude >nul 2>nul
if errorlevel 1 (
  echo.
  echo   NOTE: AI (chat + briefings) runs on your Claude subscription via Claude Code.
  echo   Install it and run 'claude' once to log in - then it's free, no credits.
  echo   Scans, graph and profile cards work right now without it.
  echo.
)

echo Starting Cypher UI - your browser will open at http://127.0.0.1:8765
".venv\Scripts\python.exe" -m cypher.web
pause
