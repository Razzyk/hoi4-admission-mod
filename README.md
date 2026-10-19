# HOI4 Admission Mod

A combined lobby admission and career-profile stability DLL for **Hearts of Iron IV 1.19.3.0, Windows x64**. The separate [HOI4 Injector](https://github.com/Razzyk/hoi4-injector) detects `hoi4.exe`, loads this DLL and runs its local verification helper.

## Play with other computers

1. Every participant installs/runs the injector and uses the **same module release**. Wait for `Verified - eligible` before joining or hosting.
2. Host an ordinary HOI4 Steam multiplayer lobby. Share its usual game ID or Steam invitation.
3. Other players join normally. The injected host holds each joining request until the peer completes a fresh, connection-bound module handshake. Plain clients and incompatible module builds are refused before the original admission callback.

The handshake travels over HOI4's existing multiplayer connection, so it can cross internet connections through the game's normal transport. It needs no dedicated HOI4 server, verification broker, port forwarding for this mod, shared session file, credentials exchanged between players, or LAN discovery. Each installation keeps its own private local service and session; those identifiers do not need to match. Normal game/Steam connectivity is still required. LAN is not deliberately disabled.

**Validation:** the peer protocol and actual native wrappers have automated checks. A live join between separate internet connections has not yet been observed. Crossplay/Nakama and positive live hotjoin/reconnect coverage remain unverified. See [VALIDATION.md](VALIDATION.md).

## What the check means

The local helper checks the actual local process identity, loaded DLL, game/DLL/manifest hashes and a live lease. Only then does the shipped DLL participate in peer admission. Hosts compare DLL and manifest build hashes, generate a fresh random challenge, bind it to the exact original join packet and transport connection, and accept a response once within ten seconds. Extension messages are consumed by the DLL before HOI4 parses them; accepted requests reach the original callback with their original bytes.

This is a **cooperative compatibility check**, not remote attestation or tamper-proof anti-cheat. The peer confirmation uses a public protocol; a deliberately modified client can imitate it or report hashes. It rejects ordinary clients without the matching mod, but cannot prove a hostile remote machine is running an unmodified DLL. Existing admitted players are not continuously kicked if verification stops. Missing/invalid proofs are recorded in the host's injector logs; the unmodified game's refusal UI may show a generic timeout or join-disabled error.

## Included stability guard

The same `HOI4Admission.dll` includes the [stability guard](https://github.com/Razzyk/hoi4-mp-stability-guard): duplicate country entries in a career-profile update use the original native range kernel sequentially, preserving entries and order. Unique-country updates keep the original scheduler. Both lobby and stability guards must install before local eligibility is granted. No separate stability launcher or DLL should be run alongside it.

This is an experimental workaround for the targeted co-op career-profile race. **Army modifier-tree teardown is not patched; campaign crash reduction is unverified.** Source revision, port changes and installation safeguards are recorded in [STABILITY-PROVENANCE.md](STABILITY-PROVENANCE.md).

## Install and update

Download the [injector installer or portable release](https://github.com/Razzyk/hoi4-injector/releases/latest). Start it before HOI4; module updates come independently from this repository. Close **all** HOI4 instances before activating an update, then have every player use that release. The pinned executable hash must match; a game update requires a compatible module update.

Each module release publishes `HOI4-Admission-Mod-win-x64.zip` and `module-release.json`. The updater validates version, protocol, supported game and SHA256 file hashes. The archive contains exactly four flat entries: that descriptor, `HOI4Admission.dll`, `AdmissionService.exe` and `mod-manifest.json`. No proprietary game files or private session credentials are distributed. Existing injector 0.4.0 supports this module; injector 0.4.1 updates the explanatory UI text.

## Build and test

Windows x64, PowerShell, **Zig 0.15.2** and the **.NET Framework 4.8** compiler are required. Standalone tests need no proprietary game files.

```powershell
.\build.ps1 -Zig C:\tools\zig\zig.exe
.\tests\Test.ps1 -Zig C:\tools\zig\zig.exe
```

Build output is `dist/HOI4-Admission-Mod-win-x64.zip` and `dist/module-release.json`. Read-only diagnostics `AdmissionProbe.exe` and `LobbyInspector.exe` are built under `work/bin` and excluded from the release archive. Release tags must match the module manifest version. See [TARGETS.md](TARGETS.md) for native boundaries and [PROVENANCE.md](PROVENANCE.md) for source origins.