$ErrorActionPreference = "Stop"

$target = Get-ChildItem -LiteralPath $PSScriptRoot -Filter "1.*.ps1" |
    Where-Object { Select-String -LiteralPath $_.FullName -Pattern "embedded Wintun runtime" -Quiet } |
    Select-Object -First 1

if (-not $target) {
    throw "Unable to locate multi-server client build script."
}

& $target.FullName
