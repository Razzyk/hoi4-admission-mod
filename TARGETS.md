# Verified native lobby targets

Supported executable: **HOI4 1.19.3.0, Windows x64**, SHA256:

```text
7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5
```

Preferred image base is `0x140000000`. Every address below is an RVA unless explicitly labelled a preferred-image pointer. Runtime addresses are **loaded main-module base + RVA**. The executable hash, mapped PE64 bounds, original slot pointer and original target entry bytes must match before publication. After an update, refuse installation and repeat discovery.

Research references below are relative to the original read-only `hoi4-decompiled/` analysis tree. That tree is external research material, rather than a runtime or build dependency. Discovery also read the installed executable's PE sections and instruction bytes. No prior injectable was loaded or imported.

## Current peer admission (v0.4.0)

This release replaces the historical local-ticket data plane documented below. Local named pipes still verify each local process; admission between computers is a cooperative peer handshake over existing channel 1, with no broker or common local session credentials.

A fourth atomic vtable replacement handles `CProxyServer` slot 27: slot RVA `0x2b53670`, original target `0x236afe0`. Its ABI is the same five-argument packet callback as the host callback. Required 32-byte prefix:

```text
48 89 5c 24 10 48 89 74 24 18 4c 89 4c 24 20 57
41 54 41 55 41 56 41 57 b8 50 16 00 00 e8 9e fa
```

The base constructor registers thunk RVA `0x2363860`, which dynamically dispatches `[vtable+0xd8]`; the derived proxy constructor installs its own vtable. Late replacement therefore reaches already registered callbacks. Source references: `part_0089.c`, `FUN_142362fd0`, `FUN_1423690f0`, `FUN_14236afe0`. The native message-name switch `FUN_142365860` names IDs 0–35; custom types `0x48345043` and `0x48345052` are intercepted by both wrappers before original dispatch.

The 112-byte join offer consists of magic `H4PEER1\0`, peer version 1, original length, 32-byte client nonce, DLL SHA256 and manifest SHA256. The host keeps a private bounded copy of the original packet and sends a 152-byte challenge. Its fields are type, zero reserved, magic, version, native join type, client nonce, host nonce, original packet digest and a zero proof field. The client confirms only a pending local offer while locally eligible, and returns the public SHA256 confirmation with response type. Proof domain is `HOI4-PEER-PROOF-V1`, followed by the first 120 challenge bytes and the two build hashes. There is no embedded secret or claimed remote attestation.

State is bound to the callback object and the transport-owned connection. Responses arrive on later transport callbacks; no callback blocks waiting for a peer. Successful consumption invokes the original host callback once with the saved original bytes. Plain/invalid offers use existing native denial; stale responses are logged and dropped so they cannot send a refusal after an already completed join. All other messages and channels pass through. Bounds are 64 pending slots per role, 65,536 bytes including the offer, and ten seconds on a monotonic clock. See `native/peer_protocol.h` for exact wire layouts and replay bounds.

The original three targets, transport copy-ownership evidence and native denial ABI below still apply. The old 96-byte `H4ADMIT2` trailer and service-owned ticket lookup are historical v0.3 behavior, and are not accepted by peer v1.

## Three atomic pointer replacements

| Role | Class vtable | Slot | Slot RVA | Original target RVA | Preferred-image slot bytes |
| --- | --- | --- | --- | --- | --- |
| Host receives joining requests | `CNetworkServer`, `0x2b53020` | 27 (`+0xd8`) | `0x2b530f8` | `0x23663f0` | `f0 63 36 42 01 00 00 00` |
| Client sends joining requests | `CProxyServer`, `0x2b53598` | 4 (`+0x20`) | `0x2b535b8` | `0x2363e10` | `10 3e 36 42 01 00 00 00` |
| Server-role objects send joining requests | `CNetworkServer`, `0x2b53020` | 4 (`+0x20`) | `0x2b53040` | `0x2363e10` | `10 3e 36 42 01 00 00 00` |

The table pointers are ASLR-relocated in a live process, so compare each live slot to `module base + original target RVA`, rather than comparing its eight raw file bytes. Slots are naturally eight-byte aligned in read-only image data pages. Atomic compare-and-exchange replaces exactly one pointer at a time; all original callback pointers are published to the wrappers before installation. Instruction bytes are unchanged. Three slot updates form a checked transaction with conflict-aware rollback, but their publications are individually atomic rather than one simultaneous three-slot operation.

The helper restores page protections in reverse order, including when slots share a page. A foreign intervening replacement is never overwritten. An incomplete rollback marks the hook set poisoned and requires the DLL and wrappers to stay mapped. There is no thread suspension. The deployed admission guard keeps its callbacks resident until game exit; stopping verification denies subsequent joining requests rather than uninstalling the guard.

## Host callback and admission boundary

Original target `0x23663f0` has the Windows x64 ABI:

```c
void PackageCallback(void *server, const void *packet,
                     uint32_t length, uintptr_t connection, int channel);
```

Arguments occupy RCX, RDX, R8D and R9; the fifth argument is the stack channel integer. The instance pointer is the first argument. The wrapper preserves this contract and calls the original once only after authorization, using the original packet length after removing the admission trailer.

Required first **32 bytes**:

```text
48 8b c4 48 89 58 08 4c 89 48 20 44 89 40 18 55
56 57 41 54 41 55 41 56 41 57 48 8d a8 18 fa ff
```

Research: `code/part_0089.c`, `FUN_1423663f0`, around line 42675. Constructor `FUN_142362fd0` registers callback thunk `0x2363860` through `FUN_1423e6100`. The thunk's verified instructions are:

```text
4c 8b 11 49 ff a2 d8 00 00 00
mov r10, [rcx]
jmp qword ptr [r10+0xd8]
```

This establishes that transport dispatch reads slot 27. Replacing the slot therefore reaches the incoming host path even when the callback was registered before injection.

Packets have an eight-byte control header: little-endian message type, then little-endian argument/reserved value. On **channel 1**, the guarded admission types are:

| Type | Native request | Boundary protected |
| --- | --- | --- |
| 8 | `REQUEST_ID` | Before native name/password/version processing, machine-ID allocation and roster insertion |
| 9 | `RECONNECTED` | Before native reconnect processing |
| 14 | `REQUEST_HOTJOIN` | Before pending player/connection state and hotjoin event mutations |

Native acceptance helper `0x2366030` sends `MACHINE_ID`, registers the roster and connection identity, invokes the new-client callback and logs the new connection. Reconnect helper is `0x2368240`. The guard rejects before calling the original callback, so these admission side effects are skipped. Other message types and channels retain the original dispatch.

## Client send ABI and buffer ownership

Shared target `0x2363e10` has the virtual caller ABI:

```c
void SendPacket(void *server, const void *packet,
                uint32_t length, uintptr_t connection);
```

Arguments occupy RCX, RDX, R8D and R9. The transport result may remain in AL after the original implementation returns, but the verified virtual callers treat this wrapper as returning void. Required first **32 bytes**:

```text
48 83 ec 38 48 8b 49 48 49 8b c1 45 8b c8 c6 44
24 20 01 4c 8b c2 48 8b d0 e8 62 26 08 00 48 83
```

Research: `code/part_0089.c`, `FUN_142363e10`, around line 40696. It obtains the transport context at instance offset `+0x48` and calls generic send `0x23e6490` on channel 1. The generic send tail-calls transport vtable slot 8 (`+0x40`). No prologue copying or branch relocation is used.

Normal-join constructor `FUN_1423699f0`, `code/part_0089.c:44838`, builds type 8, serialized player name/password/version, then invokes proxy slot 4 around line 44977. Hotjoin constructor `FUN_142251120`, `code/part_0086.c:26034`, builds type 14 and invokes server slot 4 around line 26095. Hotjoin retry `FUN_1422513f0` uses the same path. NULL connection means broadcast through existing transport connections, rather than a player PID.

Steam send implementation `0x23ea470`, `code/part_0090.c:67020`, synchronously copies the caller's packet to a scoped game buffer before `ISteamNetworking::SendP2PPacket`. The constructors release their serialized buffers immediately after virtual send returns. This supports allocating an augmented packet, calling the original synchronously and releasing the separate allocation afterwards. The transport polls channels 0 and 1; the trailer stays on existing channel 1.

The exact client type-9 reconnect constructor was not identified in this export. The host guard blocks missing-ticket reconnect requests, but complete live reconnect coverage must be tested separately.

## Native denial handling

Helper `0x2363e80` has ABI:

```c
void SendControl(void *server, int responseType, uintptr_t connection);
```

Required first **32 bytes**:

```text
48 83 ec 38 48 8b 49 48 4d 8b d0 48 63 c2 4c 8d
44 24 40 49 8b d2 48 89 44 24 40 41 b9 08 00 00
```

It sends an eight-byte control response on channel 1 through instance context `+0x48`, without registering a player or mutating the roster. Denials follow existing client failure handling:

| Request | Response | Native client effect |
| --- | --- | --- |
| Normal join (8) | 33, `DECLINED_JOIN_DISABLED` | State `0x12`, join-disabled event |
| Reconnect (9) | 11, `RECONNECT_REFUSED` | Failure state 7 |
| Hotjoin (14) | 16, `HOTJOIN_DECLINED` | State `0xf`, acceptance cleared, native hotjoin event |

Research: client callback `0x236afe0`, `code/part_0089.c:45787`. Using existing failure responses avoids leaving a rejected client waiting for an acceptance that will never arrive.

## Admission trailer and authorization

An eligible injected client appends a fixed 96-byte trailer:

| Offset | Content |
| --- | --- |
| 0 | Eight-byte magic `H4ADMIT2` |
| 8 | Protocol uint32, currently 2 |
| 12 | Original packet length uint32 |
| 16 | 64 ASCII hexadecimal characters representing the opaque ticket |
| 80 | Original message type uint32 |
| 84 | Channel uint32, currently 1 |
| 88 | Eight zero reserved bytes |

The ticket issuer checks the actual named-pipe peer PID, creation identity, loaded DLL and live verification lease. Tickets bind session, issuer process identity, request type and original packet hash. The eligible host consumes a ticket once and binds its consumption to the host's process identity and native connection. Invalid, missing, expired, revoked or unavailable authorization takes the native denial path. Successful verification strips the trailer before native parsing.

Native Steam address resolver `0x23e60a0` dispatches context slot 14 (`+0x70`); Steam implementation `0x23e8a40` produces a 40-byte address with kind 1 at offset 0 and full Steam ID at offset `0x18`. The transport-owned connection also starts with the authenticated Steam sender ID. These identity facts informed discovery; the current local ticket is bearer authorization through a local service, rather than remote anti-cheat attestation or a hostile-client-resistant identity proof. Crossplay/Nakama transport coverage requires a live check.

## Validation scope

Synthetic tests establish atomic pointer publication, pass-through callback ownership, refusal of mismatches/foreign hooks, restoration and preserved page protections. `LobbyInspector.exe` reads actual game slots and verifies module range, pinned executable hash, PID/creation identity, restored page protection and service lease. It never executes remote exports or changes memory. A loaded/verified older DLL correctly reports all guard flags false.

Live CFG inspection on the tested process found CFG and strict mode disabled. The game has GuardFlags `0x100`, no guard-function table entries, and guard-check target `0x12a2c0` is `c2 00 00` (`ret 0`) followed by padding. The Zig DLL has no CFG load-config directory. No mitigation policy was modified. Recheck compatibility if the executable or process policy changes.

Runtime slot inspection proves that callbacks are installed. Actual lobby enforcement additionally requires an observed plain-client rejection and verified-client acceptance in the game's join path. Generating a lobby ID or displaying a service lease alone does not establish those outcomes.

## Stability guard target

The stability guard also requires the exact supported HOI4 1.19.3.0 Windows x64 executable hash listed above (`7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5`). It checks the five-byte CALL at RVA `0x1d6001` (`e8 fa 23 00 00`) and the expected scheduler and native-kernel instruction bytes before installing its relay. Target constants and fingerprints are in `native/stability/target_spec.h`.

When career-profile country tags contain duplicates, the wrapper invokes the native kernel synchronously across the full original list, retaining repeated entries, order, and weighting while preventing same-country workers from overlapping. Unique-tag lists use the original scheduler. The hook's code and relay remain resident until process exit. This section documents the target contract, not a live campaign test; the standalone authored fixtures and their limits are recorded in `VALIDATION.md`. The separate army modifier teardown path is not patched. See [STABILITY-PROVENANCE.md](STABILITY-PROVENANCE.md) for the port source and integration lifecycle.

## Development authorization target contracts

The 0.5.0 development guard uses the same pinned executable. Its reviewed class table in `native/authorization/authority_guard.c` records each vtable RVA, original target and instruction fingerprint. For each of 25 classes, slots 0, 9 and 12 wrap destruction, native validity and synchronization-history eligibility. Three country/co-op classes also wrap slot 10 execution. A unique world-load task slot and the native scripted target getter bring the total to 80 pointer hooks. `tests/LobbyInspector.cs` independently lists and checks all 80 targets, original code fingerprints and restored read-only table pages.

| Native call boundary | Return RVA | Additional behavior |
|---|---:|---|
| Host receive validity | `0x236795c` | Capture the exact accepted object and transport-resolved sender. |
| Ordered synchronous validity | `0x22530ef` | Apply current host authorization before canonical serialization/broadcast and execution. |
| Ordered asynchronous validity | `0x2250dbd` | Apply authorization before execution. |
| Motivation retry | `0x22536df` | Preserve a cached refusal and native invalidity. |
| Early reentrant history predicate | `0x225381d` | Suppress copying an unaccepted remote object into history. |
| Post-execution history predicate | `0x22534b7` | Preserve native history behavior. |
| Hotjoin eligibility predicate | `0x2252f6e` | Preserve the distinct native eligibility check. |
| Scripted change-tag target getter | `0x34f293` | Observe the existing result exactly once; preserve its return value and RNG behavior. |

The early-history predicate occurs earlier in control flow despite its numerically larger RVA. It must not be mistaken for the post-execution path.

Validity returns an unsigned byte in AL and accepts `(command, motivation)`. A deleting destructor accepts `(command, unsigned flags)` and returns a full pointer. The script getter accepts `(effect, int32_t *outputTag, scope)` and returns a full pointer; the destination tag is at `scope+8`. The unique world-load task at vtable RVA `0x2723ca0`, slot 1, is invoked by the TBB scheduler outside the main image; a game-image return-address filter would miss it.

UpdateEquipmentVariant stores an embedded two-word native reference at `command+0x28`, rather than a pointer. Resolver RVA `0x221f310` receives the reference's address; the resolved variant's actor tag is at `+0x1c`. Current human identity, canonical-country comparison and availability are queried only with the reviewed ABI and bounded tags. Host-local co-op uses the current local human helper at RVA `0x1db8e0`, rather than assuming the host always has machine ID 1.

These contracts establish specific hooks and validation boundaries. They do not establish complete payload validation, live multiplayer compatibility or protection against local memory edits. See [AUTHORIZATION.md](AUTHORIZATION.md).
