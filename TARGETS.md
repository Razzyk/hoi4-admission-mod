# Verified native lobby targets

Supported executable: **HOI4 1.19.3.0, Windows x64**, SHA256:

```text
7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5
```

Preferred image base is `0x140000000`. Every address below is an RVA unless explicitly labelled a preferred-image pointer. Runtime addresses are **loaded main-module base + RVA**. The executable hash, mapped PE64 bounds, original slot pointer and original target entry bytes must match before publication. After an update, refuse installation and repeat discovery.

Research references below are relative to the original read-only `hoi4-decompiled/` analysis tree. That tree is external research material, rather than a runtime or build dependency. Discovery also read the installed executable's PE sections and instruction bytes. No prior injectable was loaded or imported.

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
