@echo off
setlocal
cd /d "%~dp0"

if not exist "dnf-windows-node-client.conf" (
  copy "dnf-windows-node-client.conf.example" "dnf-windows-node-client.conf" >nul
  echo Created dnf-windows-node-client.conf from example.
  echo Edit dnf-windows-node-client.conf before first run.
  pause
  exit /b 1
)

"%~dp0DNF_Windows_Node_Client_v1.0.exe" --config "%~dp0dnf-windows-node-client.conf"
