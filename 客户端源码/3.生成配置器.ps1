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
Write-Host "Visual Studio C++ environment found" -ForegroundColor Green
Write-Host "  $vsPath" -ForegroundColor DarkGray
Write-Host ""

$batchFile = Join-Path $env:TEMP "dnf-build-injector.bat"
$batchContent = @(
    '@echo off',
    ('call "{0}" >nul 2>&1' -f $vsPath),
    'if errorlevel 1 exit /b 1',
    'cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe:config_injector.exe config_injector.cpp'
)
Set-Content -Path $batchFile -Value $batchContent -Encoding Ascii
$stdoutFile = Join-Path $env:TEMP "dnf-build-injector.stdout.log"
$stderrFile = Join-Path $env:TEMP "dnf-build-injector.stderr.log"
Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
$exitCode = $proc.ExitCode
$stdout = if (Test-Path $stdoutFile) { Get-Content $stdoutFile -Raw } else { "" }
$stderr = if (Test-Path $stderrFile) { Get-Content $stderrFile -Raw } else { "" }
$outputParts = @()
if ($stdout) { $outputParts += $stdout }
if ($stderr) { $outputParts += $stderr }
$output = $outputParts -join [Environment]::NewLine
Remove-Item $batchFile,$stdoutFile,$stderrFile -ErrorAction SilentlyContinue

if ($exitCode -ne 0) {
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    $output | ForEach-Object { Write-Host $_ }
    exit 1
}

Remove-Item "config_injector.obj" -ErrorAction SilentlyContinue
Write-Host "Compilation Successful!" -ForegroundColor Green
