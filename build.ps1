param(
    [string]$Zig = 'zig',
    [string]$WorkDirectory = (Join-Path $PSScriptRoot 'work')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $WorkDirectory 'zig-global'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $WorkDirectory 'zig-local'
$bin = Join-Path $WorkDirectory 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$dll = Join-Path $bin 'HOI4Admission.dll'
$nativeSources = @(
    'native\admission.c', 'native\lobby_guard.c', 'native\vtable_hook.c',
    'native\stability\stability_guard.c', 'native\peer_protocol.c',
    'native\authorization\authority_policy.c', 'native\authorization\command_provenance.c',
    'native\authorization\event_payload.c',
    'native\authorization\factory_payload.c',
    'native\authorization\equipment_payload.c',
    'native\authorization\equipment_bonus.c',
    'native\authorization\authority_guard.c'
) | ForEach-Object { Join-Path $PSScriptRoot $_ }
& $Zig cc -target x86_64-windows-gnu -shared -std=c11 -O2 -Wall -Wextra -Werror -fno-fast-math -o $dll @nativeSources -lbcrypt
if ($LASTEXITCODE -ne 0) { throw 'Native DLL build failed' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.8 C# compiler is required' }
$shared = Join-Path $PSScriptRoot 'service\Shared.cs'
$service = Join-Path $bin 'AdmissionService.exe'
& $compiler /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ ('/out:' + $service) /reference:System.Core.dll /reference:System.Web.Extensions.dll $shared (Join-Path $PSScriptRoot 'service\JoinTickets.cs') (Join-Path $PSScriptRoot 'service\Service.cs')
if ($LASTEXITCODE -ne 0) { throw 'Service build failed' }
# Diagnostic executables are deliberately excluded from the module archive.
& $compiler /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ ('/out:' + (Join-Path $bin 'AdmissionProbe.exe')) /reference:System.Core.dll /reference:System.Web.Extensions.dll $shared (Join-Path $PSScriptRoot 'tests\RuntimeProbe.cs')
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic probe build failed' }
& $compiler /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ ('/out:' + (Join-Path $bin 'LobbyInspector.exe')) /reference:System.Core.dll /reference:System.Web.Extensions.dll $shared (Join-Path $PSScriptRoot 'tests\LobbyInspector.cs')
if ($LASTEXITCODE -ne 0) { throw 'Lobby inspector build failed' }
$manifestPath = Join-Path $PSScriptRoot 'mod-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.nativeModules.Count -ne 1 -or $manifest.nativeModules[0].name -ne 'HOI4Admission' -or $manifest.nativeModules[0].protocol -ne 2) { throw 'Invalid module manifest' }
$version = [string]$manifest.nativeModules[0].version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Release version must be major.minor.patch' }
if ($env:GITHUB_REF_TYPE -eq 'tag' -and $env:GITHUB_REF_NAME -ne ('v' + $version)) { throw 'Release tag does not match mod-manifest.json' }
$payload = @(
    [ordered]@{ path = 'HOI4Admission.dll'; sha256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() },
    [ordered]@{ path = 'AdmissionService.exe'; sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant() },
    [ordered]@{ path = 'mod-manifest.json'; sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() }
)
$descriptor = [ordered]@{
    schema = 1
    version = $version
    protocol = 2
    minimumInjectorVersion = '0.4.0'
    gameVersion = [string]$manifest.gameVersion
    gameSha256 = '7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5'
    files = $payload
}
$dist = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$descriptorPath = Join-Path $dist 'module-release.json'
[IO.File]::WriteAllText($descriptorPath, ($descriptor | ConvertTo-Json -Depth 5) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$archivePath = Join-Path $dist 'HOI4-Admission-Mod-win-x64.zip'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Replacing an owned archive is safe; no extraction or recursive deletion occurs.
$stream = [IO.File]::Open($archivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($entry in @(
            @{ Name = 'module-release.json'; Source = $descriptorPath },
            @{ Name = 'HOI4Admission.dll'; Source = $dll },
            @{ Name = 'AdmissionService.exe'; Source = $service },
            @{ Name = 'mod-manifest.json'; Source = $manifestPath }
        )) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $entry.Source, $entry.Name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $archive.Dispose() }
} finally { $stream.Dispose() }
Write-Output ('Built module ' + $version + ': ' + $archivePath)
Write-Output ('ZIP SHA256: ' + (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant())
