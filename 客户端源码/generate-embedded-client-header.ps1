$ErrorActionPreference = "Stop"

$target = Get-ChildItem -LiteralPath $PSScriptRoot -Filter "2.*.py" |
    Select-Object -First 1

if (-not $target) {
    throw "Unable to locate embedded client header generator."
}

$env:PYTHONIOENCODING = "utf-8"
python $target.FullName `
    (Join-Path $PSScriptRoot "DNF_Proxy_Client_MultiServer_v12.4.0.exe") `
    (Join-Path $PSScriptRoot "embedded_client_multiserver.h")
