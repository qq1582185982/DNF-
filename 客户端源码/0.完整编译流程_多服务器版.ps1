$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DNF Build v12.4.0 - Multi-Server Version" -ForegroundColor Cyan
Write-Host " Complete Compilation Process" -ForegroundColor Cyan
Write-Host " Auto Build: Multi-Server Client -> Binary Encoding -> Config Injector" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Compile multi-server client
Write-Host "[Step 1/3] Compiling multi-server client..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
& .\1.编译多服务器版.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "✗ Step 1 failed: Client compilation error" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[Step 2/3] Generating client binary encoding (embedded_client_multiserver.h)..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray

# Check if source file exists
if (-not (Test-Path "DNF_Proxy_Client_MultiServer_v12.4.0.exe")) {
    Write-Host "✗ Error: DNF_Proxy_Client_MultiServer_v12.4.0.exe not found!" -ForegroundColor Red
    exit 1
}

# Generate binary encoding for multi-server version
$pythonScript = @"
import sys

def generate_embedded_client(input_exe, output_h):
    print(f'Generating embedded client from {input_exe}...')

    # Read binary
    with open(input_exe, 'rb') as f:
        data = f.read()

    size = len(data)
    print(f'  Client size: {size:,} bytes ({size/1024:.2f} KB)')

    # Generate header file
    with open(output_h, 'w', encoding='utf-8') as f:
        f.write('// Auto-generated embedded client binary\n')
        f.write('// DNF Proxy Client v12.4.0 Multi-Server Version\n\n')
        f.write('#ifndef EMBEDDED_CLIENT_MULTISERVER_H\n')
        f.write('#define EMBEDDED_CLIENT_MULTISERVER_H\n\n')
        f.write('#include <cstdint>\n\n')
        f.write(f'const size_t EMBEDDED_CLIENT_SIZE = {size};\n\n')
        f.write('const uint8_t EMBEDDED_CLIENT_DATA[] = {\n')

        # Write data in chunks of 16 bytes per line
        for i in range(0, size, 16):
            chunk = data[i:i+16]
            hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
            f.write(f'    {hex_str},\n')

        f.write('};\n\n')
        f.write('#endif // EMBEDDED_CLIENT_MULTISERVER_H\n')

    print(f'✓ Generated: {output_h}')
    print(f'  Total size: {size:,} bytes')

if __name__ == '__main__':
    generate_embedded_client('DNF_Proxy_Client_MultiServer_v12.4.0.exe',
                            'embedded_client_multiserver.h')
"@

$pythonScript | python -
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "✗ Step 2 failed: Binary encoding generation error" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[Step 3/3] Compiling config injector for multi-server version..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray

# Compile multi-server config injector
& .\3.生成配置器_多服务器版.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "✗ Step 3 failed: Config injector compilation error" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " ✓ Complete compilation successful!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Generated files:" -ForegroundColor Cyan
Write-Host "  1. DNF_Proxy_Client_MultiServer_v12.4.0.exe - Multi-server client (with embedded WinDivert)" -ForegroundColor White
Write-Host "  2. embedded_client_multiserver.h            - Client binary encoding" -ForegroundColor White
Write-Host "  3. DNFConfigInjector_MultiServer.exe        - Config injector for multi-server" -ForegroundColor White
Write-Host ""
Write-Host "New features in v12.4.0:" -ForegroundColor Cyan
Write-Host "  ✓ HTTP API integration - Fetch server list dynamically" -ForegroundColor Green
Write-Host "  ✓ GUI server selector - Windows-style dialog with server list" -ForegroundColor Green
Write-Host "  ✓ Remember last choice - Saved to %APPDATA%\DNFProxy\" -ForegroundColor Green
Write-Host "  ✓ WinDivert embedded - Single-file distribution" -ForegroundColor Green
Write-Host ""
Write-Host "Config format for multi-server version:" -ForegroundColor Cyan
Write-Host '  {"config_api_url":"config.server.com","config_api_port":8080,"version_name":"龙鸣86"}' -ForegroundColor DarkGray
Write-Host ""
Write-Host "API endpoint format:" -ForegroundColor Cyan
Write-Host "  GET http://config.server.com:8080/api/servers" -ForegroundColor DarkGray
Write-Host "  Response: {\"servers\":[{\"id\":1,\"name\":\"龙鸣86\",\"game_server_ip\":\"...\",\"tunnel_server_ip\":\"...\",\"tunnel_port\":33223}]}" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  1. Setup your API server to return server list" -ForegroundColor White
Write-Host "  2. Run 'DNFConfigInjector_MultiServer.exe' to inject API config into client" -ForegroundColor White
Write-Host "  3. Distribute the configured client to users" -ForegroundColor White
Write-Host "  4. Users run the client and select server from GUI" -ForegroundColor White
Write-Host ""
