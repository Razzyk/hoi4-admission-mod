#include "lobby_guard.h"
#include "vtable_hook.h"
#include <stdlib.h>

#define JOIN_TRAILER_BYTES 96u
#define JOIN_MAX_PACKET 65536u
#define JOIN_IO_MS 1500u

typedef void (*PacketCallback)(void *, const void *, uint32_t, uintptr_t, int);
typedef void (*SendPacket)(void *, const void *, uint32_t, uintptr_t);
typedef void (*DenyPacket)(void *, int, uintptr_t);

static AdmissionConfig guard_config;
static volatile LONG *client_eligible;
static volatile LONG stopped, installed;
static VtableHookSet hooks;
static PacketCallback original_receive;
static SendPacket original_send;
static DenyPacket native_deny;
static LobbyLog guard_log;
static ULONGLONG creation_time;
static volatile LONG64 rejected, accepted, decorated;
static const unsigned char trailer_magic[8] = {'H','4','A','D','M','I','T','2'};

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

static int control_io(HANDLE pipe, char *data, DWORD length, int writing, DWORD *count, ULONGLONG deadline) {
    OVERLAPPED op;
    memset(&op, 0, sizeof(op));
    op.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!op.hEvent) return 0;
    BOOL ok = writing ? WriteFile(pipe, data, length, count, &op) : ReadFile(pipe, data, length, count, &op);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ULONGLONG now = GetTickCount64();
        DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
        if (WaitForSingleObject(op.hEvent, remaining) == WAIT_OBJECT_0) ok = GetOverlappedResult(pipe, &op, count, FALSE);
        else {
            CancelIoEx(pipe, &op);
            // Do not free the OVERLAPPED or buffer while Windows still owns it.
            WaitForSingleObject(op.hEvent, INFINITE);
            ok = FALSE;
        }
    }
    CloseHandle(op.hEvent);
    return ok != FALSE;
}
static int control(const char *command, char response[256]) {
#ifdef LOBBY_GUARD_TEST
    extern int (*lobby_guard_test_control)(const char *, char [256]);
    if (lobby_guard_test_control) return lobby_guard_test_control(command, response);
#endif
    WCHAR path[280];
    int count = swprintf(path, 280, L"%ls-control", guard_config.pipe_path);
    if (count <= 0 || count >= 280) return 0;
    ULONGLONG deadline = GetTickCount64() + JOIN_IO_MS;
    HANDLE pipe;
    for (;;) {
        pipe = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        DWORD error = GetLastError();
        ULONGLONG now = GetTickCount64();
        if ((error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) || now >= deadline) return 0;
        DWORD remaining = (DWORD)(deadline - now);
        if (error == ERROR_PIPE_BUSY) WaitNamedPipeW(path, remaining < 100 ? remaining : 100);
        else Sleep(5);
    }
    DWORD mode = PIPE_READMODE_MESSAGE, written = 0, read = 0;
    int ok = SetNamedPipeHandleState(pipe, &mode, NULL, NULL) &&
        control_io(pipe, (char *)command, (DWORD)strlen(command), 1, &written, deadline) && written == strlen(command) &&
        control_io(pipe, response, 255, 0, &read, deadline) && read > 0;
    if (ok) response[read] = 0;
    CloseHandle(pipe);
    return ok;
}
static int valid_token(const char *token) {
    for (size_t i = 0; i < 64; ++i)
        if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return 0;
    return token[64] == 0;
}
static void put32(unsigned char *out, uint32_t value) { memcpy(out, &value, sizeof(value)); }
static uint32_t get32(const unsigned char *in) { uint32_t value; memcpy(&value, in, sizeof(value)); return value; }

static void guarded_send(void *server, const void *packet, uint32_t length, uintptr_t connection) {
    if (!packet || length < 4u || !join_type(get32(packet))) { original_send(server, packet, length, connection); return; }
    uint32_t type = get32(packet);
    if (length < 8u) { event("LOBBY_SEND_BLOCKED", type, connection, "JOIN_HEADER_INVALID"); return; }
    if (!currently_eligible()) { event("LOBBY_SEND_BLOCKED", type, connection, "LOCAL_CLIENT_NOT_VERIFIED"); return; }
    if (length > JOIN_MAX_PACKET - JOIN_TRAILER_BYTES) { event("LOBBY_SEND_BLOCKED", type, connection, "PACKET_TOO_LARGE"); return; }
    char hash[65], command[512], response[256];
    if (!sha_bytes(packet, length, hash)) { event("LOBBY_SEND_BLOCKED", type, connection, "HASH_FAILED"); return; }
    int count = snprintf(command, sizeof(command), "JOIN_ISSUE|%u|%s|%lu|%llu|%u|%s", ADMISSION_PROTOCOL,
        guard_config.session, GetCurrentProcessId(), (unsigned long long)creation_time, type, hash);
    if (count <= 0 || count >= (int)sizeof(command) || !control(command, response) ||
        strncmp(response, "TICKET|", 7) != 0 || strlen(response + 7) != 64 || !valid_token(response + 7)) {
        event("LOBBY_SEND_BLOCKED", type, connection, "TICKET_UNAVAILABLE"); return;
    }
    unsigned char *augmented = HeapAlloc(GetProcessHeap(), 0, length + JOIN_TRAILER_BYTES);
    if (!augmented) { event("LOBBY_SEND_BLOCKED", type, connection, "ALLOCATION_FAILED"); return; }
    memcpy(augmented, packet, length);
    unsigned char *trailer = augmented + length;
    memset(trailer, 0, JOIN_TRAILER_BYTES);
    memcpy(trailer, trailer_magic, 8);
    put32(trailer + 8, ADMISSION_PROTOCOL);
    put32(trailer + 12, length);
    memcpy(trailer + 16, response + 7, 64);
    put32(trailer + 80, type);
    put32(trailer + 84, 1);
    // Verified synchronous copy ownership: original caller also releases its
    // serialized buffer immediately after this virtual send returns.
    original_send(server, augmented, length + JOIN_TRAILER_BYTES, connection);
    InterlockedIncrement64(&decorated);
    event("LOBBY_REQUEST_TICKETED", type, connection, "LOCAL_SERVICE_AUTHORIZED");
    SecureZeroMemory(augmented + length, JOIN_TRAILER_BYTES);
    HeapFree(GetProcessHeap(), 0, augmented);
    SecureZeroMemory(response, sizeof(response));
}

static void reject(void *server, uint32_t type, uintptr_t connection, const char *reason) {
    InterlockedIncrement64(&rejected);
    event("LOBBY_JOIN_REJECTED", type, connection, reason);
    native_deny(server, type == 9u ? 11 : type == 14u ? 16 : 33, connection);
}
static void guarded_receive(void *server, const void *packet, uint32_t length, uintptr_t connection, int channel) {
    if (channel != 1 || !packet || length < 4u || !join_type(get32(packet))) {
        original_receive(server, packet, length, connection, channel); return;
    }
    uint32_t type = get32(packet);
    if (length < 8u) { reject(server, type, connection, "JOIN_HEADER_INVALID"); return; }
    if (!currently_eligible()) { reject(server, type, connection, "HOST_NOT_VERIFIED"); return; }
    if (length < 8u + JOIN_TRAILER_BYTES || length > JOIN_MAX_PACKET) { reject(server, type, connection, "DLL_TICKET_MISSING"); return; }
    const unsigned char *trailer = (const unsigned char *)packet + length - JOIN_TRAILER_BYTES;
    uint32_t original_length = length - JOIN_TRAILER_BYTES;
    if (memcmp(trailer, trailer_magic, 8) || get32(trailer + 8) != ADMISSION_PROTOCOL ||
        get32(trailer + 12) != original_length || get32(trailer + 80) != type || get32(trailer + 84) != 1) {
        reject(server, type, connection, "DLL_TICKET_INVALID"); return;
    }
    for (size_t i = 88; i < JOIN_TRAILER_BYTES; ++i) if (trailer[i]) { reject(server, type, connection, "DLL_TICKET_INVALID"); return; }
    char token[65], hash[65], command[512], response[256];
    memcpy(token, trailer + 16, 64); token[64] = 0;
    if (!valid_token(token) || !sha_bytes(packet, original_length, hash)) { reject(server, type, connection, "DLL_TICKET_INVALID"); return; }
    int count = snprintf(command, sizeof(command), "JOIN_CHECK|%u|%s|%lu|%llu|%u|%s|%s|%llu", ADMISSION_PROTOCOL,
        guard_config.session, GetCurrentProcessId(), (unsigned long long)creation_time, type, hash, token, (unsigned long long)connection);
    int ok = count > 0 && count < (int)sizeof(command) && control(command, response);
    SecureZeroMemory(token, sizeof(token));
    SecureZeroMemory(command, sizeof(command));
    if (!ok) { reject(server, type, connection, "VERIFICATION_SERVICE_UNAVAILABLE"); return; }
    if (strcmp(response, "JOIN_ACCEPT")) {
        reject(server, type, connection, strncmp(response, "JOIN_REJECT|", 12) == 0 ? response + 12 : "SERVICE_RESPONSE_INVALID"); return;
    }
    InterlockedIncrement64(&accepted);
    event("LOBBY_JOIN_ALLOWED", type, connection, "DLL_TICKET_VERIFIED");
    original_receive(server, packet, original_length, connection, channel);
}

int LobbyGuardStart(const AdmissionConfig *config, volatile LONG *eligible, LobbyLog logger) {
    static const unsigned char callback_entry[32] = {0x48,0x8b,0xc4,0x48,0x89,0x58,0x08,0x4c,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0xa8,0x18,0xfa,0xff};
    static const unsigned char send_entry[32] = {0x48,0x83,0xec,0x38,0x48,0x8b,0x49,0x48,0x49,0x8b,0xc1,0x45,0x8b,0xc8,0xc6,0x44,0x24,0x20,0x01,0x4c,0x8b,0xc2,0x48,0x8b,0xd0,0xe8,0x62,0x26,0x08,0x00,0x48,0x83};
    static const unsigned char deny_entry[32] = {0x48,0x83,0xec,0x38,0x48,0x8b,0x49,0x48,0x4d,0x8b,0xd0,0x48,0x63,0xc2,0x4c,0x8d,0x44,0x24,0x40,0x49,0x8b,0xd2,0x48,0x89,0x44,0x24,0x40,0x41,0xb9,0x08,0x00,0x00};
    guard_log = logger;
    guard_config = *config;
    client_eligible = eligible;
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 0;
    ULARGE_INTEGER creation; creation.LowPart = created.dwLowDateTime; creation.HighPart = created.dwHighDateTime;
    creation_time = creation.QuadPart;
    unsigned char *image = (unsigned char *)GetModuleHandleW(NULL);
    unsigned char actual[32]; SIZE_T copied;
    if (!ReadProcessMemory(GetCurrentProcess(), image + 0x2363e80u, actual, sizeof(actual), &copied) ||
        copied != sizeof(actual) || memcmp(actual, deny_entry, sizeof(actual))) return 0;
    native_deny = (DenyPacket)(image + 0x2363e80u);
    VtableHookSpec specs[3]; memset(specs, 0, sizeof(specs));
    specs[0].slot_rva = 0x2b530f8u; specs[0].original_rva = 0x23663f0u;
    specs[0].wrapper = (void *)guarded_receive; specs[0].entry_length = 32; memcpy(specs[0].expected_entry, callback_entry, 32);
    for (size_t i = 1; i < 3; ++i) {
        specs[i].slot_rva = i == 1 ? 0x2b535b8u : 0x2b53040u; specs[i].original_rva = 0x2363e10u;
        specs[i].wrapper = (void *)guarded_send; specs[i].entry_length = 32; memcpy(specs[i].expected_entry, send_entry, 32);
    }
    VtableHookResult result = VtableHookPrepare(&hooks, specs, 3);
    if (result != VTABLE_HOOK_OK) { if (logger) logger(VtableHookResultName(result)); return 0; }
    original_receive = (PacketCallback)VtableHookOriginal(&hooks, 0);
    original_send = (SendPacket)VtableHookOriginal(&hooks, 1);
    MemoryBarrier();
    result = VtableHookInstall(&hooks);
    if (result != VTABLE_HOOK_OK) { if (logger) logger(VtableHookResultName(result)); return 0; }
    InterlockedExchange(&installed, 1);
    return 1;
}
void LobbyGuardStop(void) { InterlockedExchange(&stopped, 1); }
DWORD LobbyGuardState(void) { return InterlockedCompareExchange(&installed, 0, 0) ? 3u : 0u; }
