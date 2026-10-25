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
foreach ($name in @('AuthorityPolicyTests', 'CommandProvenanceTests', 'AuthorityGuardTests', 'AuthorityEventPayloadTests', 'AuthorityFactoryPayloadTests', 'AuthorityEquipmentPayloadTests', 'AuthorityEquipmentBonusTests')) {
    $authorizationTests = Join-Path $WorkDirectory ($name + '.exe')
    $authorizationSources = @((Join-Path $PSScriptRoot ($name + '.c')))
    if ($name -eq 'AuthorityGuardTests') {
        $authorizationSources += Join-Path $root 'native\authorization\event_payload.c'
        $authorizationSources += Join-Path $root 'native\authorization\factory_payload.c'
        $authorizationSources += Join-Path $root 'native\authorization\equipment_payload.c'
        $authorizationSources += Join-Path $root 'native\authorization\equipment_bonus.c'
    }
    & $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $authorizationTests @authorizationSources -lbcrypt
    if ($LASTEXITCODE -ne 0) { throw ($name + ' compile failed') }
    & $authorizationTests
    if ($LASTEXITCODE -ne 0) { throw ($name + ' failed') }
}
foreach ($name in @('AuthorityNativeWrapperTests', 'AuthorityCountryWrapperTests', 'AuthorityIdeaWrapperTests', 'AuthorityEventWrapperTests', 'AuthorityFactoryWrapperTests', 'AuthoritySettingsWrapperTests', 'AuthorityMioWrapperTests', 'AuthorityEquipmentWrapperTests')) {
    $wrapperTests = Join-Path $WorkDirectory ($name + '.exe')
    $wrapperSources = @((Join-Path $PSScriptRoot ($name + '.c')), (Join-Path $root 'native\authorization\authority_policy.c'), (Join-Path $root 'native\authorization\command_provenance.c'), (Join-Path $root 'native\vtable_hook.c'))
    if ($name -notin @('AuthorityEventWrapperTests', 'AuthorityFactoryWrapperTests')) { $wrapperSources += Join-Path $root 'native\authorization\event_payload.c' }
    if ($name -notin @('AuthorityEventWrapperTests', 'AuthorityFactoryWrapperTests')) { $wrapperSources += Join-Path $root 'native\authorization\factory_payload.c' }
    if ($name -ne 'AuthorityEquipmentWrapperTests') {
        $wrapperSources += Join-Path $root 'native\authorization\equipment_payload.c'
        $wrapperSources += Join-Path $root 'native\authorization\equipment_bonus.c'
    }
    & $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $wrapperTests @wrapperSources -lbcrypt
    if ($LASTEXITCODE -ne 0) { throw ($name + ' compile failed') }
    & $wrapperTests
    if ($LASTEXITCODE -ne 0) { throw ($name + ' checks failed') }
}
$lobbyTests = Join-Path $WorkDirectory 'LobbyGuardTests.exe'
& $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $lobbyTests (Join-Path $PSScriptRoot 'LobbyGuardTests.c') (Join-Path $root 'native\vtable_hook.c') (Join-Path $root 'native\peer_protocol.c') -lbcrypt
if ($LASTEXITCODE -ne 0) { throw 'Lobby gate test compile failed' }
& $lobbyTests
if ($LASTEXITCODE -ne 0) { throw 'Lobby gate checks failed' }
$peerTests = Join-Path $WorkDirectory 'PeerProtocolTests.exe'
& $Zig cc -target x86_64-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -o $peerTests (Join-Path $PSScriptRoot 'PeerProtocolTests.c') -lbcrypt
if ($LASTEXITCODE -ne 0) { throw 'Peer protocol test compile failed' }
& $peerTests
if ($LASTEXITCODE -ne 0) { throw 'Peer protocol checks failed' }
& (Join-Path $PSScriptRoot 'Test-PeerTransport.ps1') -Zig $Zig -WorkDirectory (Join-Path $WorkDirectory 'peer-transport') -CacheDirectory $WorkDirectory
if ($LASTEXITCODE -ne 0) { throw 'Peer transport checks failed' }

& (Join-Path $PSScriptRoot 'stability\Test-Stability.ps1') -Zig $Zig -WorkDirectory (Join-Path $WorkDirectory 'stability') -CacheDirectory $WorkDirectory
if ($LASTEXITCODE -ne 0) { throw 'Stability guard checks failed' }
Write-Output 'All standalone policy, authorization, native wrapper, ticket, cryptographic, lobby and stability guard tests passed.'
