$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Resolve-VsVcvars.ps1"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Compiling DNF Proxy Client v12.4.0" -ForegroundColor Cyan
Write-Host "Multi-Server Version with GUI Selector" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/4] Preparing embedded Wintun runtime..." -ForegroundColor Yellow
python generate_embedded_wintun.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to prepare embedded Wintun runtime!" -ForegroundColor Red
    exit 1
}
Write-Host "Embedded Wintun runtime prepared" -ForegroundColor Green
Write-Host ""

Write-Host "[2/4] Checking Visual Studio environment..." -ForegroundColor Yellow
$vsPath = Get-VsVcvarsPath
Write-Host "Visual Studio C++ environment found" -ForegroundColor Green
Write-Host "  $vsPath" -ForegroundColor DarkGray
Write-Host ""

Write-Host "[3/4] Compiling resources..." -ForegroundColor Yellow
Write-Host "  - Background image: background.jpg" -ForegroundColor Gray
Write-Host ""

$batchFile = Join-Path $env:TEMP "dnf-build-client.bat"
$batchContent = @(
    '@echo off',
    ('call "{0}" >nul 2>&1' -f $vsPath),
    'if errorlevel 1 exit /b 1',
    'rc /fo app.res app.rc || exit /b 1',
    'cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe"DNF_Proxy_Client_MultiServer_v12.4.0.exe" tcp_proxy_client_no_config.cpp tcp_config_client.cpp ip_lease_client.cpp wintun_manager.cpp packet_tunnel_client.cpp server_selector_gui.cpp config_manager.cpp auto_updater.cpp app.res /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ws2_32.lib advapi32.lib iphlpapi.lib shell32.lib comctl32.lib user32.lib gdi32.lib gdiplus.lib ole32.lib'
)
Set-Content -Path $batchFile -Value $batchContent -Encoding Ascii
$stdoutFile = Join-Path $env:TEMP "dnf-build-client.stdout.log"
$stderrFile = Join-Path $env:TEMP "dnf-build-client.stderr.log"
Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

Write-Host "[4/4] Compiling multi-server version..." -ForegroundColor Yellow
Write-Host "  - Main: tcp_proxy_client_no_config.cpp" -ForegroundColor Gray
Write-Host "  - TCP Config: tcp_config_client.cpp" -ForegroundColor Gray
Write-Host "  - IP Lease: ip_lease_client.cpp" -ForegroundColor Gray
Write-Host "  - Wintun Runtime: wintun_manager.cpp + wintun.dll" -ForegroundColor Gray
Write-Host "  - IP Tunnel Session: packet_tunnel_client.cpp" -ForegroundColor Gray
Write-Host "  - GUI: server_selector_gui.cpp" -ForegroundColor Gray
Write-Host "  - Config: config_manager.cpp" -ForegroundColor Gray
Write-Host "  - Auto Update: auto_updater.cpp" -ForegroundColor Gray
Write-Host "  - Resources: app.res" -ForegroundColor Gray
Write-Host ""

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
Remove-Item "tcp_proxy_client_no_config.obj" -ErrorAction SilentlyContinue
Remove-Item "tcp_config_client.obj" -ErrorAction SilentlyContinue
Remove-Item "ip_lease_client.obj" -ErrorAction SilentlyContinue
Remove-Item "wintun_manager.obj" -ErrorAction SilentlyContinue
Remove-Item "packet_tunnel_client.obj" -ErrorAction SilentlyContinue
Remove-Item "server_selector_gui.obj" -ErrorAction SilentlyContinue
Remove-Item "config_manager.obj" -ErrorAction SilentlyContinue
Remove-Item "auto_updater.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

if (Test-Path "DNF_Proxy_Client_MultiServer_v12.4.0.exe") {
    $fileSize = (Get-Item "DNF_Proxy_Client_MultiServer_v12.4.0.exe").Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)

    Write-Host "Output file: DNF_Proxy_Client_MultiServer_v12.4.0.exe" -ForegroundColor Cyan
    Write-Host "File size: $fileSizeKB KB ($fileSizeMB MB)" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "New features in v12.4.0:" -ForegroundColor Yellow
    Write-Host "  - TCP protocol integration - fetch server list via TCP" -ForegroundColor Gray
    Write-Host "  - GUI server selector - Windows-style dialog" -ForegroundColor Gray
    Write-Host "  - Remember last choice - saved to %APPDATA%\\DNFProxy\\" -ForegroundColor Gray
    Write-Host "  - Wintun + IP Tunnel virtual LAN path" -ForegroundColor Gray
    Write-Host "  - Auto-update feature - download and replace on startup" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "ERROR: Output file not found!" -ForegroundColor Red
    exit 1
}
