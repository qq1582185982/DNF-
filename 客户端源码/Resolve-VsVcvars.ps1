$ErrorActionPreference = "Stop"

function Get-VsVcvarsPath {
    param(
        [ValidateSet("x64", "x86")]
        [string]$Arch = "x64"
    )

    $candidates = @()
    $vcvarsName = if ($Arch -eq "x86") { "vcvars32.bat" } else { "vcvars64.bat" }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($LASTEXITCODE -eq 0 -and $installationPath) {
            $candidates += (Join-Path $installationPath "VC\Auxiliary\Build\$vcvarsName")
        }
    }

    $candidates += @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\$vcvarsName",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\$vcvarsName",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\$vcvarsName",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\$vcvarsName"
    )

    foreach ($path in $candidates | Select-Object -Unique) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    throw "未找到 Visual Studio C++ 构建环境（$vcvarsName）"
}
