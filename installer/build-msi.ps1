# Build the MSI on Windows (WiX does not run on Linux: WIX0389 on Directory/@Name).
# Prerequisites: .NET SDK 8+ and the exes in build\win (mingw cross-build or MSVC).
# Usage: powershell -ExecutionPolicy Bypass -File installer\build-msi.ps1
param(
    [string]$BuildDir = "$PSScriptRoot\..\build\win",
    [string]$SourceDir = "$PSScriptRoot\..",
    [string]$OutMsi = "$PSScriptRoot\..\build\avscan-0.4.0-x64.msi"
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path "$BuildDir\avscan.exe")) { throw "build\win\avscan.exe missing: build the Windows exes first" }
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version "6.*"
}
$env:DOTNET_ROLL_FORWARD = 'Major'
wix build -arch x64 `
    -d BuildDir=(Resolve-Path $BuildDir).Path `
    -d SourceDir=(Resolve-Path $SourceDir).Path `
    "$PSScriptRoot\avscan.wxs" -o $OutMsi
Write-Host "MSI: $OutMsi"
