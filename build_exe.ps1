#requires -Version 5.1
<#
.SYNOPSIS
    Builds dist\AEGIS.exe as a single-file Windows console application.

.DESCRIPTION
    Requires Python 3.10+ and the build-only packages PyInstaller and Pillow.
    The scanner itself has no runtime dependencies; these are used only here.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
#>
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "==> Checking build dependencies"
py -3 -c "import PyInstaller, PIL" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "==> Installing PyInstaller and Pillow (build-time only)"
    py -3 -m pip install --upgrade pyinstaller pillow
}

Write-Host "==> Generating icon"
py -3 .\packaging\make_icon.py

Write-Host "==> Building AEGIS.exe"
py -3 -m PyInstaller --noconfirm --clean .\aegis.spec

$exe = Join-Path $PSScriptRoot "dist\AEGIS.exe"
if (-not (Test-Path $exe)) {
    throw "Build failed: $exe was not produced."
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "==> Built $exe ($size MB)"
Write-Host "==> Smoke test"
& $exe --version
