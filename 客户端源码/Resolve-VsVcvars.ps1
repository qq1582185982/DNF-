$ErrorActionPreference = "Stop"

function Get-VsVcvarsPath {
    $candidates = @()

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($LASTEXITCODE -eq 0 -and $installationPath) {
            $candidates += (Join-Path $installationPath "VC\Auxiliary\Build\vcvars64.bat")
        }
    }

    $candidates += @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )

    foreach ($path in $candidates | Select-Object -Unique) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    throw "未找到 Visual Studio C++ 构建环境（vcvars64.bat）"
}
