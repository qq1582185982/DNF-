$ErrorActionPreference = "Stop"

$inputExe = Join-Path $PSScriptRoot "DNF_Proxy_Client_MultiServer_v12.4.0.exe"
$outputHeader = Join-Path $PSScriptRoot "embedded_client_multiserver.h"

if (-not (Test-Path -LiteralPath $inputExe)) {
    throw "Unable to locate multi-server client binary: $inputExe"
}

$bytes = [System.IO.File]::ReadAllBytes($inputExe)
$sb = New-Object System.Text.StringBuilder

[void]$sb.AppendLine("// Auto-generated embedded client binary")
[void]$sb.AppendLine("// DNF Proxy Client v12.4.0 Multi-Server Version")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("#ifndef EMBEDDED_CLIENT_MULTISERVER_H")
[void]$sb.AppendLine("#define EMBEDDED_CLIENT_MULTISERVER_H")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("#include <cstdint>")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("const size_t EMBEDDED_CLIENT_SIZE = {0};" -f $bytes.Length))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("const uint8_t EMBEDDED_CLIENT_DATA[] = {")

for ($offset = 0; $offset -lt $bytes.Length; $offset += 16) {
    $count = [Math]::Min(16, $bytes.Length - $offset)
    $hexBytes = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $count; $i++) {
        $hexBytes.Add(("0x{0:x2}" -f $bytes[$offset + $i]))
    }

    $line = "    " + ($hexBytes -join ", ")
    if (($offset + $count) -lt $bytes.Length) {
        $line += ","
    }
    [void]$sb.AppendLine($line)
}

[void]$sb.AppendLine("};")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("#endif  // EMBEDDED_CLIENT_MULTISERVER_H")
[void]$sb.AppendLine("")

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputHeader, $sb.ToString(), $utf8NoBom)

Write-Host "Generated embedded client header: $outputHeader"
Write-Host ("Embedded client size: {0} bytes" -f $bytes.Length)
