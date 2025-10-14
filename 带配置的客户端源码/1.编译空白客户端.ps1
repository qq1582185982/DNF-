$ErrorActionPreference = "Stop"

Write-Host "Compiling base client (no config)..."
Write-Host ""

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $vsPath)) {
    Write-Host "ERROR: Visual Studio 2022 not found" -ForegroundColor Red
    exit 1
}

cmd /c "`"$vsPath`" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /Fe`"tcp_proxy_client_base.exe`" tcp_proxy_client_no_config.cpp /link WinDivert.lib ws2_32.lib advapi32.lib"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    exit 1
}

# Clean up temp files
Remove-Item "tcp_proxy_client_no_config.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Compilation successful!" -ForegroundColor Green
Write-Host "Output: tcp_proxy_client_base.exe"
