#include "lobby_guard.h"
#include "vtable_hook.h"
#include "peer_protocol.h"
#include <stdlib.h>


typedef void (*PacketCallback)(void *, const void *, uint32_t, uintptr_t, int);
typedef void (*SendPacket)(void *, const void *, uint32_t, uintptr_t);
typedef void (*DenyPacket)(void *, int, uintptr_t);

static PeerClientState peer_client;
static PeerHostState peer_host;
static volatile LONG *client_eligible;
static volatile LONG stopped, installed;
static VtableHookSet hooks;
static PacketCallback original_receive, original_client_receive;
static SendPacket original_send;
static DenyPacket native_deny;
static LobbyLog guard_log;
static LobbyCommandReceiver command_receiver;

static volatile LONG64 rejected, accepted, decorated;


static int join_type(uint32_t type) { return type == 8u || type == 9u || type == 14u; }
static int currently_eligible(void) {
    return !InterlockedCompareExchange(&stopped, 0, 0) && client_eligible &&
        InterlockedCompareExchange(client_eligible, 0, 0) != 0;
}
static void event(const char *kind, uint32_t type, uintptr_t connection, const char *reason) {
    char text[256];
    int count = snprintf(text, sizeof(text), "%s type=%u connection=%llu reason=%.96s", kind, type,
        (unsigned long long)connection, reason);
    if (guard_log && count > 0 && count < (int)sizeof(text)) guard_log(text);
}

static uint32_t get32(const void *in) { uint32_t value; memcpy(&value, in, sizeof(value)); return value; }

static void reject(void *server, uint32_t type, uintptr_t connection, const char *reason) {
    InterlockedIncrement64(&rejected);
    event("LOBBY_JOIN_REJECTED", type, connection, reason);
    if (connection) native_deny(server, type == 9u ? 11 : type == 14u ? 16 : 33, connection);
}
static void guarded_send(void *server, const void *packet, uint32_t length, uintptr_t connection) {
    if (!packet || length < 4u || !join_type(get32(packet))) { original_send(server, packet, length, connection); return; }
    uint32_t type = get32(packet);
    if (!currently_eligible()) { event("LOBBY_SEND_BLOCKED", type, connection, "LOCAL_CLIENT_NOT_VERIFIED"); return; }
    if (length < 8 || length > PEER_MAX_PACKET - PEER_OFFER_BYTES) { event("LOBBY_SEND_BLOCKED", type, connection, "JOIN_SIZE_INVALID"); return; }
    unsigned char *offered = HeapAlloc(GetProcessHeap(), 0, length + PEER_OFFER_BYTES);
    if (!offered) { event("LOBBY_SEND_BLOCKED", type, connection, "ALLOCATION_FAILED"); return; }
    uint32_t offered_length = 0;
    if (PeerClientMakeOffer(&peer_client, (uintptr_t)server, type, packet, length, GetTickCount64(),
        offered, length + PEER_OFFER_BYTES, &offered_length)) {
        original_send(server, offered, offered_length, connection);
        InterlockedIncrement64(&decorated);
        event("LOBBY_REQUEST_OFFERED", type, connection, "PEER_HANDSHAKE_REQUIRED");
    } else event("LOBBY_SEND_BLOCKED", type, connection, "PEER_OFFER_UNAVAILABLE");
    HeapFree(GetProcessHeap(), 0, offered);
}
/* These extension messages never reach HOI4's message parser. The response
 * arrives on a later transport callback; no callback waits for a network peer. */
static int peer_message(void *server, const void *packet, uint32_t length, uintptr_t connection, int channel, int host) {
    if (channel != 1 || !packet || length < 4) return 0;
    uint32_t kind = get32(packet);
    if (kind != PEER_MESSAGE_CHALLENGE && kind != PEER_MESSAGE_RESPONSE) return 0;
    if (!currently_eligible()) { event("LOBBY_PEER_REFUSED", kind, connection, "LOCAL_CLIENT_NOT_VERIFIED"); return 1; }
    if (kind == PEER_MESSAGE_CHALLENGE) {
        unsigned char response[PEER_MESSAGE_BYTES];
        if (PeerClientAnswer(&peer_client, (uintptr_t)server, connection, GetTickCount64(), packet, length, response, sizeof(response))) {
            original_send(server, response, sizeof(response), connection);
            event("LOBBY_PEER_CONFIRMED", kind, connection, "LOCAL_BUILD_VERIFIED");
        } else event("LOBBY_PEER_REFUSED", kind, connection, "CHALLENGE_INVALID_OR_EXPIRED");
    } else if (host) {
        unsigned char *original = HeapAlloc(GetProcessHeap(), 0, PEER_MAX_PACKET);
        uint32_t original_length = 0;
        int ok = original && PeerHostAccept(&peer_host, (uintptr_t)server, connection, GetTickCount64(),
            packet, length, original, PEER_MAX_PACKET, &original_length);
        if (ok && currently_eligible()) {
            InterlockedIncrement64(&accepted);
            event("LOBBY_JOIN_ALLOWED", get32(original), connection, "PEER_HANDSHAKE_VERIFIED");
            original_receive(server, original, original_length, connection, channel);
        } else {
            uint32_t type = length >= 24 ? get32((const unsigned char *)packet + 20) : 0;
            InterlockedIncrement64(&rejected);
            // A delayed/replayed response must not send a native refusal after
            // a later handshake already admitted this transport connection.
            event("LOBBY_JOIN_REJECTED", type, connection, "PEER_RESPONSE_INVALID_OR_EXPIRED");
        }
        if (original) HeapFree(GetProcessHeap(), 0, original);
    }
    return 1;
}
static void guarded_client_receive(void *server, const void *packet, uint32_t length, uintptr_t connection, int channel) {
    if (!peer_message(server, packet, length, connection, channel, 0)) original_client_receive(server, packet, length, connection, channel);
}
static void guarded_receive(void *server, const void *packet, uint32_t length, uintptr_t connection, int channel) {
    if (channel == 0 && command_receiver) {
        command_receiver(original_receive, server, packet, length, connection, channel);
        return;
    }
    if (peer_message(server, packet, length, connection, channel, 1)) return;
    if (channel != 1 || !packet || length < 4 || !join_type(get32(packet))) {
        original_receive(server, packet, length, connection, channel); return;
    }
    uint32_t type = get32(packet);
    if (!currently_eligible()) { reject(server, type, connection, "HOST_NOT_VERIFIED"); return; }
    unsigned char challenge[PEER_MESSAGE_BYTES];
    if (!PeerHostChallenge(&peer_host, (uintptr_t)server, connection, GetTickCount64(), packet, length, challenge, sizeof(challenge))) {
        reject(server, type, connection, "MATCHING_ADMISSION_MOD_REQUIRED"); return;
    }
    original_send(server, challenge, sizeof(challenge), connection);
    event("LOBBY_PEER_CHALLENGED", type, connection, "AWAITING_PEER_CONFIRMATION");
}
int LobbyGuardSetCommandReceiver(LobbyCommandReceiver receiver) {
    if (!receiver || InterlockedCompareExchange(&installed, 0, 0)) return 0;
    command_receiver = receiver;
    MemoryBarrier();
    return 1;
}
int LobbyGuardStart(const AdmissionConfig *config, volatile LONG *eligible, LobbyLog logger, const char *dll_hash, const char *manifest_hash) {
    static const unsigned char callback_entry[32] = {0x48,0x8b,0xc4,0x48,0x89,0x58,0x08,0x4c,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0xa8,0x18,0xfa,0xff};
    static const unsigned char send_entry[32] = {0x48,0x83,0xec,0x38,0x48,0x8b,0x49,0x48,0x49,0x8b,0xc1,0x45,0x8b,0xc8,0xc6,0x44,0x24,0x20,0x01,0x4c,0x8b,0xc2,0x48,0x8b,0xd0,0xe8,0x62,0x26,0x08,0x00,0x48,0x83};
    static const unsigned char deny_entry[32] = {0x48,0x83,0xec,0x38,0x48,0x8b,0x49,0x48,0x4d,0x8b,0xd0,0x48,0x63,0xc2,0x4c,0x8d,0x44,0x24,0x40,0x49,0x8b,0xd2,0x48,0x89,0x44,0x24,0x40,0x41,0xb9,0x08,0x00,0x00};
    guard_log = logger;
    (void)config;
    unsigned char dll[32], manifest[32];
    if (!hex_decode(dll_hash, dll, 32) || !hex_decode(manifest_hash, manifest, 32)) return 0;
    PeerClientInit(&peer_client, dll, manifest);
    PeerHostInit(&peer_host, dll, manifest);
    client_eligible = eligible;
    unsigned char *image = (unsigned char *)GetModuleHandleW(NULL);
    unsigned char actual[32]; SIZE_T copied;
    if (!ReadProcessMemory(GetCurrentProcess(), image + 0x2363e80u, actual, sizeof(actual), &copied) ||
        copied != sizeof(actual) || memcmp(actual, deny_entry, sizeof(actual))) return 0;
    native_deny = (DenyPacket)(image + 0x2363e80u);
    VtableHookSpec specs[4]; memset(specs, 0, sizeof(specs));
    specs[0].slot_rva = 0x2b530f8u; specs[0].original_rva = 0x23663f0u;
    specs[0].wrapper = (void *)guarded_receive; specs[0].entry_length = 32; memcpy(specs[0].expected_entry, callback_entry, 32);
    for (size_t i = 1; i < 3; ++i) {
        specs[i].slot_rva = i == 1 ? 0x2b535b8u : 0x2b53040u; specs[i].original_rva = 0x2363e10u;
        specs[i].wrapper = (void *)guarded_send; specs[i].entry_length = 32; memcpy(specs[i].expected_entry, send_entry, 32);
    }
    static const unsigned char proxy_entry[32] = {0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x4c,0x89,0x4c,0x24,0x20,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0xb8,0x50,0x16,0x00,0x00,0xe8,0x9e,0xfa};
    specs[3].slot_rva = 0x2b53670u; specs[3].original_rva = 0x236afe0u;
    specs[3].wrapper = (void *)guarded_client_receive; specs[3].entry_length = 32; memcpy(specs[3].expected_entry, proxy_entry, 32);
    VtableHookResult result = VtableHookPrepare(&hooks, specs, 4);
    if (result != VTABLE_HOOK_OK) { if (logger) logger(VtableHookResultName(result)); return 0; }
    original_receive = (PacketCallback)VtableHookOriginal(&hooks, 0);
    original_send = (SendPacket)VtableHookOriginal(&hooks, 1);
    original_client_receive = (PacketCallback)VtableHookOriginal(&hooks, 3);
    MemoryBarrier();
    result = VtableHookInstall(&hooks);
    if (result != VTABLE_HOOK_OK) { if (logger) logger(VtableHookResultName(result)); return 0; }
    InterlockedExchange(&installed, 1);
    return 1;
}
void LobbyGuardStop(void) { InterlockedExchange(&stopped, 1); }
DWORD LobbyGuardState(void) { return InterlockedCompareExchange(&installed, 0, 0) ? 4u : 0u; }
