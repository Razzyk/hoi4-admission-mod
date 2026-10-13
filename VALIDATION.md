# Validation — module v0.3.0

## Independent module release

The repository split changes packaging and build ownership, not the native admission behavior from the live test below. Its standalone build produces exactly four flat archive entries: `module-release.json`, `HOI4Admission.dll`, `AdmissionService.exe` and `mod-manifest.json`. The descriptor records the supported game identity, protocol, minimum injector version and all three payload SHA256 hashes. Diagnostic executables, runtime files and private credentials are excluded.

The independent `tests/Test.ps1` runs policy, ticket, cryptographic, vtable and native guard tests without requiring a game executable. Executable detection and loader rejection belong to the separate injector repository. The CI release workflow builds the module, runs this suite and publishes the ZIP and descriptor.

## Completed automated checks

The Windows x64 components compiled with warnings treated as errors. The following checks passed:

- **14 verification-policy checks:** valid authentication and rejection of incorrect protocol, session, permission, game/DLL/manifest identity, challenge and credential proof.
- **26 ticket-store checks:** random 256-bit tickets, exact packet/type binding, immutable issuer/lease snapshots, session isolation, replay refusal, ten-second monotonic expiry, bounded storage and exactly one success among twelve simultaneous consumers.
- **43 native gate cases, 1,466 assertions:** authorized trailer decoration and stripping, original callback ownership, pass-through messages and denial before original admission for missing, malformed, changed, unavailable or revoked authorization.
- **100 vtable publication cycles with 2,540,023 dispatch calls:** atomic pointer replacement, target/conflict refusal, checked rollback and restoration of page protections.
- Native BCrypt and managed HMAC-SHA256 agreement.
- The original combined injector test also refused a wrong executable hash before loading the DLL into a harmless `hoi4.exe` fixture. That fixture is now tested by the independent injector repository.

These are synthetic/native unit checks and local policy tests. They do not establish successful delivery through a real multiplayer transport.

## Target evidence and live inspection

Original analysis and installed executable bytes established the supported host callback, its registered virtual dispatch thunk, outgoing send slots and existing denial handlers. `TARGETS.md` documents their RVAs, fingerprints, ABI and packet boundaries.

`LobbyInspector.exe session.json <pid> --require-hooks` checks a real process read-only: PID/creation identity, pinned game hash/path, configured DLL hash, the three live slots, executable callback ranges, restored read-only page protection and service verification. It can distinguish an older loaded DLL whose slots remain original from this release's installed guards.

The new real HOI4 v0.3 test group completed this inspection. Both injected games mapped the pinned DLL, held current service leases and had all three guards active with page protections restored. The plain game had no admission DLL or replaced guard slots. All three games responded, and process-title reads confirmed their injected/verified or plain labels.

The runtime probe also checked the running protocol-2 service. External `VERIFY`, `JOIN_ISSUE` and `JOIN_CHECK` requests claiming a game's PID were rejected with `PEER_PID_MISMATCH`. A request reporting the probe's own correct PID was rejected with `CLIENT_NOT_VERIFIED`. These checks confirm that reported game identifiers do not substitute for the actual verified pipe peer.

At **20:43:32 Sydney time (09:43:32 UTC)**, a real plain-copy normal-join request reached the injected host and logged `LOBBY_JOIN_REJECTED`, type 8, reason `DLL_TICKET_INVALID`. The host wrapper took the native denial path without calling the original admission callback. The user confirmed that the plain copy could not join and its vanilla UI displayed **timed out**. That timeout does not establish receipt or display of the native denial response, nor does it tell the client why admission failed.

At **20:44:32 Sydney time (09:44:32 UTC)**, injected player-two's normal join produced all three matching events: the client DLL logged `LOBBY_REQUEST_TICKETED`; the service logged `LOBBY_JOIN_AUTHORIZED` identifying that live client and host; the host DLL logged `LOBBY_JOIN_ALLOWED` with `DLL_TICKET_VERIFIED`. The wrapper then invoked the original callback with the trailer removed. The user confirmed that player-two joined the host lobby. This establishes actual request delivery, authorization and the visible positive outcome for this local normal-join test.

**Slot inspection alone proves installation; these correlated native events and user-confirmed lobby outcomes establish local normal-join enforcement.** Hotjoin, reconnect and crossplay/Nakama coverage require their own live tests.

The separate injector manager displays the host's logged rejection reason. The plain client's unchanged game UI may still display only a timeout.

## Normal-join outcome and remaining tests

The injected host blocked the plain client before admission and accepted the verified injected client. Wrong, expired and replayed tickets, revoked eligibility and unavailable verification are covered by automated refusal cases and still warrant live scenario tests. A host game ID, GUI verification caption or standalone `ADMIT` response alone is not multiplayer enforcement evidence.

The current broker uses a local Windows named pipe. Injected remote clients cannot receive valid tickets from it. Remote positive testing needs a network broker before it can succeed. Stop leaves the guards installed and denies subsequent join requests; it does not continuously eject existing players.

## Earlier test context

The previous v0.2 test established loading and local handshake eligibility for two injected processes while a plain process lacked the DLL. It did not enforce native lobby admission and is not evidence of v0.3 join success.

Simultaneous copies attached to the same Steam client produced blank hosted game IDs in two instances. After the user authorized closing the plain copy and injected player-two, the remaining injected player-one produced an ID in a fresh hosted lobby. This suggests simultaneous-copy interference without establishing the precise cause. No joined match between those three copies was demonstrated.

Private configuration, credentials, raw game logs, profile paths and live identifiers are excluded from the distributable package. This implementation makes no remote attestation or tamper-proof claim.
