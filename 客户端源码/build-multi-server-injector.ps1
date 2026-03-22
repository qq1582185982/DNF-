$ErrorActionPreference = "Stop"

$target = Get-ChildItem -LiteralPath $PSScriptRoot -Filter "3.*.ps1" |
    Where-Object { Select-String -LiteralPath $_.FullName -Pattern "config_injector_multiserver.cpp" -Quiet } |
    Select-Object -First 1

if (-not $target) {
    throw "Unable to locate multi-server injector build script."
}

& $target.FullName
