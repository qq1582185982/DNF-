$ErrorActionPreference = "Stop"

Write-Host "Compiling config injector..."
Write-Host ""

# Check if embedded_client.h exists
if (-not (Test-Path "embedded_client.h")) {
    Write-Host "ERROR: embedded_client.h not found" -ForegroundColor Red
    Write-Host "Please run exe_to_cpp_array.py first to generate this file."
    exit 1
}

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $vsPath)) {
    Write-Host "ERROR: Visual Studio 2022 not found" -ForegroundColor Red
    exit 1
}

cmd /c "`"$vsPath`" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /Fe`"DNFConfigInjector.exe`" config_injector.cpp"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    exit 1
}

# Clean up temp files
Remove-Item "config_injector.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Compilation successful!" -ForegroundColor Green
Write-Host "Output: DNFConfigInjector.exe"
Write-Host ""
Write-Host "Embedded client size: $((Get-Item 'tcp_proxy_client_base.exe').Length / 1KB) KB"
Write-Host "Injector size: $((Get-Item 'DNFConfigInjector.exe').Length / 1KB) KB"
