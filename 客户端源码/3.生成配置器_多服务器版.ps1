$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Resolve-VsVcvars.ps1"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Compiling Multi-Server Config Injector" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path "embedded_client_multiserver.h")) {
    Write-Host "ERROR: embedded_client_multiserver.h not found!" -ForegroundColor Red
    Write-Host "Please run Step 2 first (Generate embedded client binary)" -ForegroundColor Yellow
    exit 1
}

Write-Host "Found embedded_client_multiserver.h" -ForegroundColor Green
Write-Host ""

Write-Host "Checking Visual Studio environment..." -ForegroundColor Yellow
$vsPath = Get-VsVcvarsPath
Write-Host "Visual Studio C++ environment found" -ForegroundColor Green
Write-Host "  $vsPath" -ForegroundColor DarkGray
Write-Host ""

Write-Host "Compiling config injector for multi-server version..." -ForegroundColor Yellow
Write-Host "  Source: config_injector_multiserver.cpp" -ForegroundColor Gray
Write-Host "  Output: DNFConfigInjector_MultiServer.exe" -ForegroundColor Gray
Write-Host ""

$batchFile = Join-Path $env:TEMP "dnf-build-multi-server-injector.bat"
$batchContent = @(
    '@echo off',
    ('call "{0}" >nul 2>&1' -f $vsPath),
    'if errorlevel 1 exit /b 1',
    'cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe:DNFConfigInjector_MultiServer.exe config_injector_multiserver.cpp'
)
Set-Content -Path $batchFile -Value $batchContent -Encoding Ascii
$stdoutFile = Join-Path $env:TEMP "dnf-build-multi-server-injector.stdout.log"
$stderrFile = Join-Path $env:TEMP "dnf-build-multi-server-injector.stderr.log"
Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

$startTime = Get-Date
$proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFile`"" -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
while (-not $proc.HasExited) {
    Start-Sleep -Seconds 15
    $proc.Refresh()
    if (-not $proc.HasExited) {
        $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
        Write-Host ("  - Still compiling... {0}s" -f $elapsed) -ForegroundColor DarkGray
    }
}
$exitCode = $proc.ExitCode
$stdout = if (Test-Path $stdoutFile) { Get-Content $stdoutFile -Raw } else { "" }
$stderr = if (Test-Path $stderrFile) { Get-Content $stderrFile -Raw } else { "" }
$outputParts = @()
if ($stdout) { $outputParts += $stdout }
if ($stderr) { $outputParts += $stderr }
$output = $outputParts -join [Environment]::NewLine
Remove-Item $batchFile,$stdoutFile,$stderrFile -ErrorAction SilentlyContinue

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error output:" -ForegroundColor Yellow
    $output | ForEach-Object { Write-Host $_ }
    exit 1
}

if ($output -match "warning") {
    Write-Host ""
    Write-Host "Compilation succeeded with warnings:" -ForegroundColor Yellow
    $output | Select-String "warning" | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host ""
}

Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
Remove-Item "config_injector_multiserver.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

if (Test-Path "DNFConfigInjector_MultiServer.exe") {
    $fileSize = (Get-Item "DNFConfigInjector_MultiServer.exe").Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)

    Write-Host "Output file: DNFConfigInjector_MultiServer.exe" -ForegroundColor Cyan
    Write-Host "File size: $fileSizeKB KB" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "ERROR: Output file not found!" -ForegroundColor Red
    exit 1
}
