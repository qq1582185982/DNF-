param(
    [Parameter(Mandatory = $true)]
    [string]$ApiHost,

    [Parameter(Mandatory = $true)]
    [int]$ApiPort,

    [string]$ServerKey = "1",
    [string]$ClientId = "",
    [switch]$Build,
    [ValidateSet("Debug", "Release")]
    [string]$Variant = "Debug"
)

$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    if ([string]::IsNullOrWhiteSpace($ApiHost)) {
        throw "ApiHost must not be empty."
    }
    if ($ApiPort -le 0 -or $ApiPort -gt 65535) {
        throw "ApiPort must be between 1 and 65535."
    }

    $assetsDir = Join-Path $PSScriptRoot "app\src\main\assets"
    New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null

    $config = [ordered]@{
        config_api_url = $ApiHost.Trim()
        config_api_port = $ApiPort
        server_key = $ServerKey.Trim()
        client_id = $ClientId.Trim()
    }
    $configPath = Join-Path $assetsDir "dnf_android_config.json"
    $json = $config | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($configPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

    Write-Host "Android embedded config written: $configPath" -ForegroundColor Green
    Write-Host "API: $($config.config_api_url):$($config.config_api_port)" -ForegroundColor Cyan
    Write-Host "ServerKey: $($config.server_key)" -ForegroundColor Cyan

    if (-not $Build) {
        Write-Host ""
        Write-Host "Config generated. Open this directory in Android Studio and build the APK." -ForegroundColor Yellow
        Write-Host "If Gradle/Android SDK is installed, add -Build to build automatically." -ForegroundColor Yellow
        return
    }

    $task = if ($Variant -eq "Release") { "assembleRelease" } else { "assembleDebug" }
    if (Test-Path ".\gradlew.bat") {
        & ".\gradlew.bat" $task
    } elseif (Get-Command gradle -ErrorAction SilentlyContinue) {
        & gradle $task
    } else {
        throw "gradlew.bat or gradle was not found. Install Android Studio/Gradle first."
    }

    $apkDir = Join-Path $PSScriptRoot ("app\build\outputs\apk\" + $Variant.ToLowerInvariant())
    Write-Host "Build complete. APK directory: $apkDir" -ForegroundColor Green
}
finally {
    Pop-Location
}
