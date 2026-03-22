$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Resolve-VsVcvars.ps1"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Compiling Config Injector" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path "embedded_client.h")) {
    Write-Host "ERROR: embedded_client.h not found!" -ForegroundColor Red
    exit 1
}

$vsPath = Get-VsVcvarsPath
Write-Host "✓ Visual Studio C++ environment found" -ForegroundColor Green
Write-Host "  $vsPath" -ForegroundColor DarkGray
Write-Host ""

$compileCommand = @"
"$vsPath" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe:config_injector.exe config_injector.cpp 2>&1
"@

$output = cmd /c $compileCommand
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    Write-Host $output
    exit 1
}

Remove-Item "config_injector.obj" -ErrorAction SilentlyContinue
Write-Host "Compilation Successful!" -ForegroundColor Green
