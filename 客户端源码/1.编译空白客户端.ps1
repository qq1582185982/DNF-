$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Compiling DNF Proxy Client (Base Version)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Compile client
Write-Host "[1/1] Compiling client..." -ForegroundColor Yellow

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $vsPath)) {
    Write-Host "ERROR: Visual Studio 2022 not found" -ForegroundColor Red
    exit 1
}

cmd /c "`"$vsPath`" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe`"tcp_proxy_client_base.exe`" tcp_proxy_client_no_config.cpp tcp_config_client.cpp ip_lease_client.cpp wintun_manager.cpp packet_tunnel_client.cpp server_selector_gui.cpp config_manager.cpp auto_updater.cpp /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ws2_32.lib advapi32.lib iphlpapi.lib shell32.lib comctl32.lib user32.lib gdi32.lib gdiplus.lib ole32.lib"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    exit 1
}

# Clean up temp files
Remove-Item "tcp_proxy_client_no_config.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Output: tcp_proxy_client_base.exe"
Write-Host ""
Write-Host "Note: Base client now uses Wintun + IP Tunnel virtual LAN path" -ForegroundColor Cyan
