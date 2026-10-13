param([string]$Zig = 'zig', [string]$WorkDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('HOI4Admission-test-' + [Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Path $WorkDirectory -Force | Out-Null
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$tests = Join-Path $WorkDirectory 'PolicyTests.exe'
& $compiler /nologo /target:exe /platform:x64 /warn:4 /warnaserror+ ('/out:' + $tests) /reference:System.Core.dll /reference:System.Web.Extensions.dll (Join-Path $root 'service\Shared.cs') (Join-Path $PSScriptRoot 'PolicyTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Policy test compile failed' }
& $tests
if ($LASTEXITCODE -ne 0) { throw 'Policy checks failed' }
$ticketTests = Join-Path $WorkDirectory 'JoinTicketTests.exe'
& $compiler /nologo /target:exe /platform:x64 /warn:4 /warnaserror+ ('/out:' + $ticketTests) /reference:System.Core.dll /reference:System.Web.Extensions.dll (Join-Path $root 'service\Shared.cs') (Join-Path $root 'service\JoinTickets.cs') (Join-Path $PSScriptRoot 'JoinTicketTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Join ticket test compile failed' }
& $ticketTests
if ($LASTEXITCODE -ne 0) { throw 'Join ticket checks failed' }
$crypto = Join-Path $WorkDirectory 'CryptoTests.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $WorkDirectory 'zig-global'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $WorkDirectory 'zig-local'
& $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $crypto (Join-Path $PSScriptRoot 'CryptoTests.c') -lbcrypt
if ($LASTEXITCODE -ne 0) { throw 'Native crypto test compile failed' }
$native = (& $crypto).Trim()
$hmac = [Security.Cryptography.HMACSHA256]::new([byte[]](@(0xaa) * 32))
try { $expected = [BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes('HOI4-admission-protocol-1'))).Replace('-','').ToLowerInvariant() } finally { $hmac.Dispose() }
if ($native -ne $expected) { throw 'Native/C# HMAC implementations differ' }
Write-Output 'PASS native BCrypt and managed HMAC-SHA256 agree'
$vtableTests = Join-Path $WorkDirectory 'VtableTests.exe'
& $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $vtableTests (Join-Path $PSScriptRoot 'VtableTests.c') (Join-Path $root 'native\vtable_hook.c')
if ($LASTEXITCODE -ne 0) { throw 'Vtable test compile failed' }
& $vtableTests
if ($LASTEXITCODE -ne 0) { throw 'Vtable checks failed' }
$lobbyTests = Join-Path $WorkDirectory 'LobbyGuardTests.exe'
& $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $lobbyTests (Join-Path $PSScriptRoot 'LobbyGuardTests.c') (Join-Path $root 'native\vtable_hook.c') -lbcrypt
if ($LASTEXITCODE -ne 0) { throw 'Lobby gate test compile failed' }
& $lobbyTests
if ($LASTEXITCODE -ne 0) { throw 'Lobby gate checks failed' }

Write-Output 'All standalone policy, ticket, cryptographic and native guard tests passed.'
