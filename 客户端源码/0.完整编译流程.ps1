$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DNF Build - Complete Compilation Process" -ForegroundColor Cyan
Write-Host " Auto Build: Base Client -> Embed Binary -> Config Injector" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Compile base client
Write-Host "[Step 1/3] Compiling base client (tcp_proxy_client_base.exe)..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
& .\1.编译空白客户端.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "X Step 1 failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[Step 2/3] Generating client binary encoding (embedded_client.h)..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
python 2.生成客户端2进制编码.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "X Step 2 failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[Step 3/3] Compiling config injector..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray
& .\3.生成配置器.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "X Step 3 failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " OK Complete compilation successful!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Generated files:" -ForegroundColor Cyan
Write-Host "  1. tcp_proxy_client_base.exe    - Base client (with embedded WinDivert)" -ForegroundColor White
Write-Host "  2. embedded_client.h            - Client binary encoding" -ForegroundColor White
Write-Host "  3. DNF配置注入工具.exe          - Config injector" -ForegroundColor White
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  Run 'DNF配置注入工具.exe' to generate configured client" -ForegroundColor White
Write-Host "  Generated client includes full WinDivert support, single-file distribution" -ForegroundColor White
Write-Host ""
