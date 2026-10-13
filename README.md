# HOI4 Admission Mod

Native lobby admission module and local verification service for **Hearts of Iron IV 1.19.3.0, Windows x64**. The separate [HOI4 Injector](https://github.com/Razzyk/hoi4-injector) installs this release, watches for `hoi4.exe`, loads the DLL and runs the service. Download the injector to use the module; this repository does not contain the injector GUI or loader.

The injected host checks a one-use authorization ticket before forwarding a normal join request to HOI4's original admission callback. The client DLL adds the ticket, and the service checks the live process, game/DLL/manifest identity, session permission and current verification lease. Tickets expire after ten seconds, are bound to the original join packet and cannot be reused. A missing or invalid ticket blocks admission. Stopping verification leaves the installed guard in place and refuses subsequent joins.

The existing local test demonstrated both outcomes: a plain client was refused and the verified injected client entered the lobby. The plain game's UI displayed **timed out**; the injected host's log identified the rejected ticket. See [VALIDATION.md](VALIDATION.md) for the evidence and [TARGETS.md](TARGETS.md) for the supported native boundaries.

## Install and update

1. Download the latest installer or portable release from [Razzyk/hoi4-injector](https://github.com/Razzyk/hoi4-injector/releases/latest).
2. Run the injector, select the HOI4 installation if it is not detected, and let it fetch the module release.
3. Start HOI4 with the injector running. The manager shows whether the DLL has loaded and verification succeeded.

Module releases are independent of injector releases. Each release publishes `HOI4-Admission-Mod-win-x64.zip` and `module-release.json`. The injector checks the descriptor's version, protocol, minimum injector version, supported game identity and SHA256 file hashes before activating the package. Its archive contains exactly four flat entries: the descriptor, `HOI4Admission.dll`, `AdmissionService.exe` and `mod-manifest.json`. No game executable, game asset, configuration credential or user profile is included.

## Scope

This first module uses a **local Windows named-pipe service**. Verified participants must run on the same machine. A network broker is still needed for verified players on other computers. Local tickets are not remote attestation or tamper-proof anti-cheat.

Normal join is live-tested. Hotjoin and reconnect requests are guarded by authored code and unit checks, but positive live hotjoin/reconnect tests and crossplay/Nakama coverage remain unverified. Existing admitted players are not continuously ejected when a lease expires. A different HOI4 executable hash is refused; every game update requires rediscovery and a compatible module release.

## Build and test

Windows x64, PowerShell, **Zig 0.15.2** and the **.NET Framework 4.8** compiler are required. No proprietary game file is needed to build or run the standalone tests.

```powershell
.\build.ps1 -Zig C:\tools\zig\zig.exe
.\tests\Test.ps1 -Zig C:\tools\zig\zig.exe
```

Build output is `dist/HOI4-Admission-Mod-win-x64.zip` and `dist/module-release.json`. `work/bin` also contains the read-only `AdmissionProbe.exe` and `LobbyInspector.exe` diagnostics; these are excluded from the update package. A `v<version>` Git tag must match `mod-manifest.json`; the Windows release workflow builds, tests and publishes both assets.

The standalone suite covers 14 verification-policy checks, 26 ticket-store checks, 43 native guard cases with 1,466 assertions, repeated concurrent atomic vtable publication, and agreement between native and managed HMAC-SHA256. The injector's separate tests own executable detection and loader rejection. Source provenance is documented in [PROVENANCE.md](PROVENANCE.md).
