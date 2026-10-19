[CmdletBinding()]
param(
    [string]$Zig = 'zig',
    [string]$WorkDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('HOI4Stability-tests-' + [Guid]::NewGuid().ToString('N'))),
    [string]$CacheDirectory
)

$ErrorActionPreference = 'Stop'
$zigCommand = Get-Command $Zig -ErrorAction Stop
$resolvedZig = $zigCommand.Source
$zigVersion = (& $resolvedZig version).Trim()
if ($LASTEXITCODE -ne 0 -or $zigVersion -ne '0.15.2') {
    throw "Stability tests require Zig 0.15.2; found $zigVersion."
}
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $WorkDirectory 'zig-cache' }
New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null
$CacheDirectory = (Resolve-Path -LiteralPath $CacheDirectory).Path

# Reuse this directory on subsequent runs to avoid rebuilding Zig's runtime.
$savedGlobalCache = $env:ZIG_GLOBAL_CACHE_DIR
$savedLocalCache = $env:ZIG_LOCAL_CACHE_DIR
try {
    $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $CacheDirectory 'global'
    $env:ZIG_LOCAL_CACHE_DIR = Join-Path $CacheDirectory 'local'
    $careerExecutable = Join-Path $WorkDirectory 'career_guard_test.exe'
    & $resolvedZig cc -target x86_64-windows-gnu -std=c11 -O2 -g -Wall -Wextra -Werror -fno-fast-math (Join-Path $PSScriptRoot 'career_guard_test.c') -o $careerExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Career guard test compilation failed.' }
    & $careerExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Career guard tests failed.' }

    $transactionExecutable = Join-Path $WorkDirectory 'hook_transaction_test.exe'
    & $resolvedZig cc -target x86_64-windows-gnu -std=c11 -O2 -g -Wall -Wextra -Werror -fno-fast-math (Join-Path $PSScriptRoot 'hook_transaction_test.c') -o $transactionExecutable -lbcrypt -lpsapi
    if ($LASTEXITCODE -ne 0) { throw 'Stability hook transaction test compilation failed.' }
    & $transactionExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Stability hook transaction tests failed.' }
    # Poisoned lifecycle scenarios run in isolated disposable processes.
    foreach ($mode in @('--protect-restore-failure', '--persistent-flush-failure', '--persistent-resume-failure')) {
        & $transactionExecutable $mode
        if ($LASTEXITCODE -ne 0) { throw "Stability transaction recovery test failed: $mode" }
    }
    Write-Output 'All standalone stability tests passed. These authored fixtures do not launch or inject into HOI4.'
}
finally {
    $env:ZIG_GLOBAL_CACHE_DIR = $savedGlobalCache
    $env:ZIG_LOCAL_CACHE_DIR = $savedLocalCache
}
