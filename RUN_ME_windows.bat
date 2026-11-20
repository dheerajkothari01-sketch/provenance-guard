@echo off
cd /d "%~dp0"
set PY=
python --version >nul 2>&1 && set PY=python
if not defined PY (py --version >nul 2>&1 && set PY=py)
if not defined PY (
  echo.
  echo  Python was not found.
  echo  1. Install Python 3 from python.org and TICK "Add python.exe to PATH".
  echo  2. Or turn off Settings ^> Apps ^> Advanced app settings ^> App execution aliases ^> python.exe / python3.exe
  echo  3. Then close this window and double-click RUN_ME_windows.bat again.
  echo.
  pause
  exit /b 1
)
echo Using: %PY%
%PY% --version
echo Installing libraries (first run only, takes a minute)...
%PY% -m pip install -r requirements.txt
echo.
echo Starting Provenance Guard at http://localhost:8501  (keep this window open)
%PY% -m streamlit run app.py
pause
