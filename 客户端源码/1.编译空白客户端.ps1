$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Resolve-VsVcvars.ps1"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Compiling DNF Proxy Client (Base Version)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/2] Preparing embedded Wintun runtime..." -ForegroundColor Yellow
python generate_embedded_wintun.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to prepare embedded Wintun runtime!" -ForegroundColor Red
    exit 1
}
Write-Host ""

Write-Host "[2/2] Compiling client..." -ForegroundColor Yellow
$vsPath = Get-VsVcvarsPath
Write-Host "Visual Studio C++ environment found" -ForegroundColor Green
Write-Host "  $vsPath" -ForegroundColor DarkGray

$batchFile = Join-Path $env:TEMP "dnf-build-base-client.bat"
$batchContent = @(
    '@echo off',
    ('call "{0}" >nul 2>&1' -f $vsPath),
    'if errorlevel 1 exit /b 1',
    'cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe"tcp_proxy_client_base.exe" tcp_proxy_client_no_config.cpp tcp_config_client.cpp ip_lease_client.cpp wintun_manager.cpp packet_tunnel_client.cpp server_selector_gui.cpp config_manager.cpp auto_updater.cpp /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ws2_32.lib advapi32.lib iphlpapi.lib shell32.lib comctl32.lib user32.lib gdi32.lib gdiplus.lib ole32.lib',
    'if errorlevel 1 exit /b 1',
    'exit /b 0'
)
Set-Content -Path $batchFile -Value $batchContent -Encoding Ascii
$stdoutFile = Join-Path $env:TEMP "dnf-build-base-client.stdout.log"
$stderrFile = Join-Path $env:TEMP "dnf-build-base-client.stderr.log"
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
    $output | ForEach-Object { Write-Host $_ }
    exit 1
}

Remove-Item "tcp_proxy_client_no_config.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Output: tcp_proxy_client_base.exe"
Write-Host ""
Write-Host "Note: Base client now uses Wintun + IP Tunnel virtual LAN path" -ForegroundColor Cyan
