$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Compiling DNF Proxy Client (Base Version)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Generate embedded WinDivert files
Write-Host "[1/2] Generating embedded WinDivert files..." -ForegroundColor Yellow
python generate_embedded_windivert.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to generate embedded WinDivert!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 2: Compile client
Write-Host "[2/2] Compiling client..." -ForegroundColor Yellow

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $vsPath)) {
    Write-Host "ERROR: Visual Studio 2022 not found" -ForegroundColor Red
    exit 1
}

cmd /c "`"$vsPath`" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /Fe`"tcp_proxy_client_base.exe`" tcp_proxy_client_no_config.cpp /link ws2_32.lib advapi32.lib"

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
Write-Host "Note: WinDivert files embedded in client, single-file distribution" -ForegroundColor Cyan
