# Validation

## Development module v0.5.0: host command authorization

On 24 October 2026, the final Windows x64 module built with warnings treated as errors and the complete expanded standalone suite passed: 246 policy assertions, 8,530 provenance assertions, 17 policy/adapter helper assertions, 16,461 general native-wrapper assertions, 456 country/equipment/diagnostic assertions, 35 idea-wrapper assertions, 39 event-payload assertions, 24 factory-payload assertions, five event-wrapper assertions and eight factory-wrapper assertions.

The authored private-image fixtures exercise the real wrappers at the verified native return sites. They cover receive admission, AL-only native booleans, motivation arguments, full-pointer destructor/getter returns, controlled and foreign actors, native null-country refusal, capacity exhaustion, early history versus hotjoin/post-execution history, stale epochs, object reuse, load-task return/peer retention, host-local co-op approval by a remote leader, and multiple queued same-source script changes. Equipment fixtures check typed reference safety, unsigned level 255, unchanged inherited levels, native refusal of changed levels, new-key anti-bypass, duplicate/descending keys, signed counts, capacity, address overflow and full-width equipment-type pointers. Native game predicates are mocked in those fixtures; this does not establish a successful real equipment-designer operation.

Existing admission and stability regressions also passed: 16 lobby-wrapper cases/170 assertions, 1,153 peer protocol checks, delayed two-process UDP loopback, native/managed cryptographic agreement, concurrent vtable publication, 127 career regression assertions and the hook transaction/poisoned-transaction tests.

The expanded fixtures check direct national-spirit/hidden-idea refusal and cost flags, valid co-op factory assignments, canonical country aliases, negative and overflowing assignments, duplicate batch entries, reductions after a cap change, event definition/recipient/scope binding, negative option refusal, the native nonleader event exception, and a 300-node scope graph without an arbitrary depth limit. Guard and inspector targets were independently compared against the pinned executable: all 80 pointer slots for 25 command classes and lifecycle hooks matched their original targets and instruction fingerprints. Native predicates in authored fixtures remain mocked.

The published injector then automatically loaded the expanded DLL into a fresh isolated HOI4 process. Read-only inspection verified all 80 authorization slots, all four admission slots, the stability CALL/relay, restored table protections and a current verification lease. The loaded DLL matched the packaged DLL: SHA256 `ee107c03eae63f6cb813c732504f3dabbfd7fd37797189166226229014abc8d4`. The temporary game and its recorded helpers were closed after inspection. This establishes installation, not successful adversarial rejection or normal campaign compatibility for the expanded rules.

On 21 October 2026, the published injector automatically loaded the earlier candidate into an isolated real HOI4 process. Read-only inspection verified its 71 authorization slots and original code fingerprints, four lobby slots, the stability CALL/relay, restored page protections and a current local verification lease. That DLL matched its packaged build: SHA256 `a3377eca8f4470fdc933fb2ac280514baa7ac70f83e955126a02993ad9fcd5a2`.

In the same local two-process test, player-two completed the peer handshake and joined player-one's lobby. The user confirmed that starting the campaign with the native Enter shortcut made both copies playable, then confirmed that ordinary civilian construction and research worked. Read-only host counters increased from one to three policy allows after those two actions, with no policy denial or native-invalid result. These are positive local compatibility results for the DLL hash above, not adversarial rejection tests or a separate-account/network test. Co-op was disabled in this session and the in-game menu did not offer observer reassignment, so neither scenario was tested live.

**Separate-network joining, adversarial live command rejection, equipment design, co-op, scripted/capitulation transitions and campaign overhead remain unverified for v0.5.0.** The expanded guard covers 25 reviewed command classes and a narrow same-type upgrade-level subset. It does not validate all equipment prices/statistics, all event UI eligibility, unreviewed command families or arbitrary local memory edits. The previous live outcomes above apply only to the recorded earlier candidate. See [AUTHORIZATION.md](AUTHORIZATION.md).

## Module v0.4.0: direct peer admission and combined stability guard

The complete Windows module builds with warnings treated as errors. The suite passes 14 local verification policy checks, 26 retained legacy local-ticket store checks, native/managed HMAC agreement, concurrent atomic vtable publication, 15 current peer-wrapper cases with 155 assertions, and 1,153 peer protocol checks. Peer cases exercise exact original-packet forwarding only after a matching response, plain/build-mismatched refusal, fresh outgoing nonces, connection/object/type/payload binding, malformed/truncated input, monotonic expiry, replayed offers/responses, concurrency and bounded replay-state exhaustion with automatic recovery.

A two-process UDP loopback fixture also passed with separate host/client PIDs and context identities, 150 ms delay before each send, build-mismatch refusal, exact single original-packet admission, and offer/response replay refusal. It shares no live process or roster state. Loopback UDP is a transport fixture, not an internet or Steam lobby test.

The combined DLL was automatically loaded into an isolated real HOI4 process by the existing published injector 0.4.0. Read-only inspection found all four lobby hooks, including the new proxy receive callback, pointing into the configured DLL with vtable pages restored to read-only; the stability CALL pointed to the RX relay and DLL wrapper with code protections restored. The local service held a current verified lease. The isolated test game closed normally and its temporary injector/service stopped. This establishes combined loading and hook installation, not a multiplayer join or campaign outcome.

**A live join between different internet connections has not been tested.** Positive live hotjoin/reconnect, crossplay/Nakama, campaign stability/performance and continuous post-admission enforcement remain unverified. The direct protocol has no broker or shared local session. It checks cooperative peer compatibility rather than hostile-client remote attestation.

## Historical module v0.3.0 validation

The sections below record the earlier local-ticket release. Its visible join outcomes do not establish the new peer handshake's live multiplayer behavior. Local-ticket statements, the three-hook inspector and the proposed network broker describe v0.3.0 only; v0.4.0 replaces that data plane.
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

## Stability guard standalone fixtures

The ported stability fixtures were run with `tests/stability/Test-Stability.ps1`, Zig 0.15.2, a dedicated work directory, and the existing Zig cache. The career regression passed all 127 assertions: the duplicate-country fixture changed from three same-country overlaps to zero while preserving six entries and total weight 266. The hook transaction fixture passed 302 assertions in this run, including CALL/relay execution and restoration, refusal cases, input preservation, diagnostics, and RX protection checks. Its isolated poisoned-transaction runs passed 14, 14, and 16 assertions. The concurrent CALL/thread-creation stress run completed 9,416,773 calls and 76 created threads.

These authored fixtures run in disposable test processes and did not launch or inject into HOI4. They check the stability implementation and its test APIs; they do not compile or validate the admission worker integration, demonstrate a live campaign crash reduction, or establish multiplayer synchronization, hot-join behavior, or performance. The exact target remains the pinned 1.19.3.0 executable. The separate army modifier teardown crash remains unpatched, and this remains an experimental workaround. See [STABILITY-PROVENANCE.md](STABILITY-PROVENANCE.md) for source details.
