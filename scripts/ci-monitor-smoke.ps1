# Automated smoke test for avmonitor.exe (console mode, no ETW, no service). Run with PowerShell 7 (pwsh).
# Usage: pwsh scripts/ci-monitor-smoke.ps1 -Dir build/windows/Release
param(
    [string]$Dir = "build/windows/Release",
    [string]$Db = "tests/monitor/smoke.db",
    [string]$LogDir = "smoke-logs",
    [int]$TimeoutSec = 90
)
$ErrorActionPreference = "Stop"

$exe = (Resolve-Path (Join-Path $Dir "avmonitor.exe")).Path
$db = (Resolve-Path $Db).Path
New-Item -ItemType Directory -Force $LogDir | Out-Null
$log = (Resolve-Path $LogDir).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ("avmon-smoke-" + [guid]::NewGuid().ToString("N"))
$watch = Join-Path $root "watch"
$excl = Join-Path $watch "excluded"
New-Item -ItemType Directory -Force $excl | Out-Null
$out = Join-Path $log "monitor.out.txt"
$err = Join-Path $log "monitor.err.txt"
$marker = "AVSCAN-MONITOR-SMOKE-MARKER-1"
$bulkCount = 200
# Cyrillic file name built from code points, so this script stays pure ASCII.
$uni = (-join [char[]](0x0442, 0x0435, 0x0441, 0x0442, 0x2D, 0x044E, 0x043D, 0x0438, 0x043A, 0x043E, 0x0434)) + ".txt"

function Get-Results {
    if (-not (Test-Path $out)) { return @() }
    $text = Get-Content -LiteralPath $out -Raw -Encoding UTF8
    if (-not $text) { return @() }
    $list = @()
    foreach ($m in [regex]::Matches($text, '"path": "((?:[^"\\]|\\.)*)",\s*"status": "(\w+)"')) {
        $list += [pscustomobject]@{ Path = ($m.Groups[1].Value -replace '\\\\', '\'); Status = $m.Groups[2].Value }
    }
    return $list
}

function Statuses([string]$name) {
    @($script:res | Where-Object { $_.Path -like "*\$name" } | ForEach-Object { $_.Status })
}

$failures = New-Object System.Collections.Generic.List[string]
function Expect([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "PASS $what" } else { Write-Host "FAIL $what"; $failures.Add($what) }
}

$argList = @("--watch", "`"$watch`"", "--exclude", "`"$excl`"", "--db", "`"$db`"", "--threads", "2")
$proc = Start-Process -FilePath $exe -ArgumentList $argList -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        if (Test-Path $err) { Get-Content $err | Write-Host }
        throw "avmonitor exited early with code $($proc.ExitCode)"
    }

    [IO.File]::WriteAllText("$watch\clean.txt", "hello")
    [IO.File]::WriteAllText("$watch\bad.txt", "xx $marker xx")
    [IO.File]::WriteAllText("$excl\ignored.txt", $marker)
    [IO.File]::WriteAllText("$watch\$uni", $marker)
    [IO.File]::WriteAllText("$watch\before.txt", "rename $marker")
    Rename-Item "$watch\before.txt" "after.txt"
    $slow = "$watch\slow.txt"
    [IO.File]::WriteAllText($slow, "start ")
    1..10 | ForEach-Object { [IO.File]::AppendAllText($slow, "chunk "); Start-Sleep -Milliseconds 150 }
    [IO.File]::AppendAllText($slow, $marker)
    1..$bulkCount | ForEach-Object { [IO.File]::WriteAllText("$watch\bulk-$_.txt", "hello $_") }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        Start-Sleep -Milliseconds 500
        $script:res = @(Get-Results)
        $bulkDone = @($script:res | Where-Object { $_.Path -like "*\bulk-*.txt" } | ForEach-Object { $_.Path } | Select-Object -Unique).Count
        $missing = @('bad.txt', 'after.txt', 'slow.txt', $uni, 'clean.txt') | Where-Object { (Statuses $_).Count -eq 0 }
    } while ((@($missing).Count -gt 0 -or $bulkDone -lt $bulkCount) -and (Get-Date) -lt $deadline)
    # Grace period: the excluded file and duplicate scans would show up here.
    Start-Sleep -Seconds 4
    $script:res = @(Get-Results)
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}

$bulkPaths = @($script:res | Where-Object { $_.Path -like "*\bulk-*.txt" })
Expect ((Statuses 'clean.txt') -contains 'Clean' -and -not ((Statuses 'clean.txt') -contains 'Infected')) "clean file -> Clean"
Expect ((Statuses 'bad.txt') -contains 'Infected') "marker file -> Infected"
Expect ((Statuses $uni) -contains 'Infected') "unicode file name -> Infected"
Expect ((Statuses 'after.txt') -contains 'Infected') "renamed file -> Infected"
Expect (((Statuses 'slow.txt') -contains 'Infected') -and -not ((Statuses 'slow.txt') -contains 'Clean')) "chunked write scanned only after it is stable (no early Clean)"
Expect (@($script:res | Where-Object { $_.Path -like "*\excluded\*" }).Count -eq 0) "excluded directory is not scanned"
Expect (@($bulkPaths | ForEach-Object { $_.Path } | Select-Object -Unique).Count -ge $bulkCount) "all $bulkCount bulk files scanned"
Expect (@($bulkPaths | Where-Object { $_.Status -ne 'Clean' }).Count -eq 0) "bulk files are all Clean"
Expect (@($script:res | Where-Object { $_.Status -eq 'Error' }).Count -eq 0) "no Error results"

if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @("### avmonitor smoke test", "", "Results parsed: $(@($script:res).Count); failures: $($failures.Count)")
    foreach ($f in $failures) { $lines += "- FAIL: $f" }
    $lines | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}

if ($failures.Count -gt 0) {
    Write-Host "avmonitor smoke test FAILED ($($failures.Count)); see $log"
    exit 1
}
Write-Host "avmonitor smoke test OK"
