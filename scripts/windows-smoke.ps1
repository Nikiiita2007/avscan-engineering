param([string]$Exe=".\build\windows\Release\avmonitor.exe")
$root=Join-Path $env:TEMP ("avscan-smoke-"+[guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory "$root\excluded" -Force | Out-Null
Write-Host "In another elevated terminal: $Exe --watch `"$root`" --exclude `"$root\excluded`" --etw"
Read-Host "Press Enter when monitor is running"
$p=Join-Path $root "медленная запись.txt"
[IO.File]::WriteAllText($p,"hello")
1..10 | ForEach-Object {[IO.File]::AppendAllText($p," chunk");Start-Sleep -Milliseconds 150}
Rename-Item $p "renamed.txt"
[IO.File]::WriteAllText("$root\excluded\ignored.txt","ignored")
1..1000 | ForEach-Object {[IO.File]::WriteAllText("$root\bulk-$_.txt","hello")}
Start-Process "$env:WINDIR\System32\notepad.exe"
Write-Host "Inspect stable file, no ignored scan, ETW process/module logs. Not an automated overflow proof. Test root: $root"
