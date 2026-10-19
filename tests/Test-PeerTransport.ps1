param(
    [string]$Zig = 'zig',
    [string]$WorkDirectory = (Join-Path $PSScriptRoot '..\work\peer-transport-tests'),
    [string]$CacheDirectory = (Join-Path $PSScriptRoot '..\work\peer-transport-cache')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
$CacheDirectory = (Resolve-Path -LiteralPath $CacheDirectory).Path
$exe = Join-Path $WorkDirectory 'PeerTransportTests.exe'
$hostOut = Join-Path $WorkDirectory 'peer-host.stdout.txt'
$hostErr = Join-Path $WorkDirectory 'peer-host.stderr.txt'
$clientOut = Join-Path $WorkDirectory 'peer-client.stdout.txt'
$clientErr = Join-Path $WorkDirectory 'peer-client.stderr.txt'
$oldGlobal = $env:ZIG_GLOBAL_CACHE_DIR
$oldLocal = $env:ZIG_LOCAL_CACHE_DIR
$hostProcess = $null
$clientProcess = $null
function Read-SharedText([string]$Path) {
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = [IO.StreamReader]::new($stream)
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
try {
    $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $CacheDirectory 'zig-global'
    $env:ZIG_LOCAL_CACHE_DIR = Join-Path $CacheDirectory 'zig-local'
    & $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $exe `
        (Join-Path $PSScriptRoot 'PeerTransportTests.c') `
        (Join-Path $root 'native\peer_protocol.c') -lbcrypt -lws2_32
    if ($LASTEXITCODE -ne 0) { throw 'Peer transport fixture compile failed' }

    Remove-Item -LiteralPath $hostOut,$hostErr,$clientOut,$clientErr -Force -ErrorAction SilentlyContinue
    $hostProcess = Start-Process -FilePath $exe -ArgumentList @('--host') -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $hostOut -RedirectStandardError $hostErr
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $ready = $null
    while ($watch.Elapsed.TotalSeconds -lt 5) {
        if ($hostProcess.HasExited) { throw 'Loopback host exited before binding its ephemeral port' }
        if (Test-Path -LiteralPath $hostOut) {
            $contents = Read-SharedText $hostOut
            if ($contents -match '(?m)^READY ([0-9]+) ([0-9]+) ([0-9]+)\r?\n') {
                $ready = [pscustomobject]@{ Port = [int]$Matches[1]; Pid = [int]$Matches[2]; Context = [UInt64]$Matches[3] }
                break
            }
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $ready) { throw 'Loopback host did not publish a bound port within five seconds' }
    if ($ready.Pid -ne $hostProcess.Id -or $ready.Port -lt 1 -or $ready.Port -gt 65535) {
        throw 'Loopback host PID or ephemeral port was invalid'
    }

    $clientArgs = @('--client', [string]$ready.Port, [string]$ready.Pid, [string]$ready.Context)
    $clientProcess = Start-Process -FilePath $exe -ArgumentList $clientArgs -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $clientOut -RedirectStandardError $clientErr
    if (-not $clientProcess.WaitForExit(20000)) {
        $clientProcess.Kill()
        $clientProcess.WaitForExit(1000) | Out-Null
        throw 'Loopback client exceeded the bounded 20-second process timeout'
    }
    if ($clientProcess.ExitCode -ne 0) {
        $detail = if (Test-Path -LiteralPath $clientErr) { Read-SharedText $clientErr } else { '' }
        throw ('Loopback client failed with exit code {0}: {1}' -f $clientProcess.ExitCode,$detail)
    }
    if (-not $hostProcess.WaitForExit(7000)) {
        $hostProcess.Kill()
        $hostProcess.WaitForExit(1000) | Out-Null
        throw 'Loopback host exceeded the bounded post-client timeout'
    }
    if ($hostProcess.ExitCode -ne 0) {
        $detail = if (Test-Path -LiteralPath $hostErr) { Read-SharedText $hostErr } else { '' }
        throw ('Loopback host failed with exit code {0}: {1}' -f $hostProcess.ExitCode,$detail)
    }
    $hostText = Read-SharedText $hostOut
    $clientText = Read-SharedText $clientOut
    if ($hostText -notmatch 'admitted=1 mismatch-refused replay-offer-refused replay-response-refused' -or
        $clientText -notmatch 'separate-process-contexts') {
        throw 'Loopback peers did not report all required outcomes'
    }
    Write-Output $hostText.Trim()
    Write-Output $clientText.Trim()
    Write-Output 'PASS two-process UDP loopback: 150 ms delayed offer/challenge/response, mismatched build refusal, exact single admission, and offer/response replay refusal; no HOI4 or Steam files used.'
} finally {
    foreach ($process in @($clientProcess,$hostProcess)) {
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(1000) | Out-Null
        }
        if ($process) { $process.Dispose() }
    }
    if ($null -eq $oldGlobal) { Remove-Item Env:ZIG_GLOBAL_CACHE_DIR -ErrorAction SilentlyContinue }
    else { $env:ZIG_GLOBAL_CACHE_DIR = $oldGlobal }
    if ($null -eq $oldLocal) { Remove-Item Env:ZIG_LOCAL_CACHE_DIR -ErrorAction SilentlyContinue }
    else { $env:ZIG_LOCAL_CACHE_DIR = $oldLocal }
}
