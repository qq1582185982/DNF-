param(
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64",
    [string]$OutputExe = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Resolve-VsVcvars.ps1"

if ([string]::IsNullOrWhiteSpace($OutputExe)) {
    $OutputExe = if ($Arch -eq "x86") {
        "DNF_Windows_Node_Client_v1.0_x86.exe"
    } else {
        "DNF_Windows_Node_Client_v1.0.exe"
    }
}

Push-Location $PSScriptRoot
try {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Compiling DNF Windows Node Client" -ForegroundColor Cyan
    Write-Host "Linux-node-compatible control flow ($Arch)" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[1/3] Preparing embedded Wintun runtime..." -ForegroundColor Yellow
    python (Join-Path $PSScriptRoot "generate_embedded_wintun.py")
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to prepare embedded Wintun runtime."
    }

    Write-Host "[2/3] Checking Visual Studio environment..." -ForegroundColor Yellow
    $vsPath = Get-VsVcvarsPath -Arch $Arch
    Write-Host "Visual Studio C++ environment found" -ForegroundColor Green
    Write-Host "  $vsPath" -ForegroundColor DarkGray
    Write-Host ""

    $batchFile = Join-Path $env:TEMP "dnf-build-windows-node-client.bat"
    $batchContent = @(
        '@echo off',
        ('call "{0}" >nul 2>&1' -f $vsPath),
        'if errorlevel 1 exit /b 1',
        ('cl /EHsc /O2 /MT /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe"{0}" windows_node_client.cpp tcp_config_client.cpp ip_lease_client.cpp wintun_manager.cpp packet_tunnel_client.cpp peer_link_manager.cpp /link /SUBSYSTEM:CONSOLE ws2_32.lib advapi32.lib iphlpapi.lib shell32.lib dnsapi.lib' -f $OutputExe),
        'if errorlevel 1 exit /b 1',
        'exit /b 0'
    )
    Set-Content -Path $batchFile -Value $batchContent -Encoding Ascii

    $stdoutFile = Join-Path $env:TEMP "dnf-build-windows-node-client.stdout.log"
    $stderrFile = Join-Path $env:TEMP "dnf-build-windows-node-client.stderr.log"
    Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

    Write-Host "[3/3] Compiling node client..." -ForegroundColor Yellow
    Remove-Item $OutputExe -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFile`"" -WorkingDirectory $PSScriptRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
    $proc.WaitForExit()
    $proc.Refresh()
    $exitCode = if ($null -eq $proc.ExitCode) { 0 } else { [int]$proc.ExitCode }

    $stdout = if (Test-Path $stdoutFile) { Get-Content $stdoutFile -Raw } else { "" }
    $stderr = if (Test-Path $stderrFile) { Get-Content $stderrFile -Raw } else { "" }
    Remove-Item $batchFile,$stdoutFile,$stderrFile -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        Write-Host ""
        Write-Host "Compilation FAILED!" -ForegroundColor Red
        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr }
        exit 1
    }

    if ($stdout -match "warning" -or $stderr -match "warning") {
        Write-Host "Compilation succeeded with warnings:" -ForegroundColor Yellow
        ($stdout + [Environment]::NewLine + $stderr) | Select-String "warning" | ForEach-Object {
            Write-Host $_ -ForegroundColor Yellow
        }
    }

    Remove-Item "windows_node_client.obj","tcp_config_client.obj","ip_lease_client.obj","wintun_manager.obj","packet_tunnel_client.obj","peer_link_manager.obj" -ErrorAction SilentlyContinue

    if (-not (Test-Path $OutputExe)) {
        throw "Output file not found: $OutputExe"
    }

    $fileSize = (Get-Item $OutputExe).Length
    Write-Host ""
    Write-Host "Compilation Successful!" -ForegroundColor Green
    Write-Host "Output file: $OutputExe" -ForegroundColor Cyan
    Write-Host ("File size: {0:N2} MB" -f ($fileSize / 1MB)) -ForegroundColor Cyan
}
finally {
    Pop-Location
}
