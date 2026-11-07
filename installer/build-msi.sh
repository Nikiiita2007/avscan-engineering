#!/bin/sh
# Build the MSI from previously built Windows exes (build/win).
# Requires the WiX v5 dotnet tool: dotnet tool install --global wix
set -e
cd "$(dirname "$0")"
BUILD=../build/win
[ -f "$BUILD/avscan.exe" ] || { echo "build/win/*.exe missing: run the Windows build first"; exit 1; }
wix build -arch x64 \
  -d BuildDir="$(cd "$BUILD" && pwd)" \
  -d SourceDir="$(cd .. && pwd)" \
  avscan.wxs -o ../build/avscan-0.4.0-x64.msi
echo "MSI: ../build/avscan-0.4.0-x64.msi"
