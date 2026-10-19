#include "protocol.h"
#include "lobby_guard.h"
#include "stability/stability_guard.h"

static HMODULE self_module;
static AdmissionConfig config;
static HANDLE stop_event;
static volatile LONG started, eligible;

static void log_event(const char *text) {
    HANDLE file = CreateFileW(config.log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME time;
    GetSystemTime(&time);
    char line[512];
    int count = snprintf(line, sizeof(line), "%04u-%02u-%02uT%02u:%02u:%02uZ pid=%lu %s\r\n", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, GetCurrentProcessId(), text);
    DWORD written;
    if (count > 0 && count < (int)sizeof(line)) WriteFile(file, line, (DWORD)count, &written, NULL);
    CloseHandle(file);
}

static int pipe_io(HANDLE pipe, char *buffer, DWORD length, int write, DWORD *count) {
    OVERLAPPED operation;
    memset(&operation, 0, sizeof(operation));
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return 0;
    BOOL ok = write ? WriteFile(pipe, buffer, length, count, &operation) : ReadFile(pipe, buffer, length, count, &operation);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        HANDLE handles[2] = { stop_event, operation.hEvent };
        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, 6000);
        if (wait == WAIT_OBJECT_0 + 1) ok = GetOverlappedResult(pipe, &operation, count, FALSE);
        else {
            CancelIoEx(pipe, &operation);
            // Completion owns the OVERLAPPED structure until cancellation settles.
            WaitForSingleObject(operation.hEvent, INFINITE);
            ok = FALSE;
        }
    }
    CloseHandle(operation.hEvent);
    return ok != FALSE;
}
static int send_message(HANDLE pipe, const char *text) {
    DWORD count = 0, length = (DWORD)strlen(text);
    return pipe_io(pipe, (char *)text, length, 1, &count) && count == length;
}
static int receive_message(HANDLE pipe, char *text, DWORD capacity) {
    DWORD count = 0;
    if (!pipe_io(pipe, text, capacity - 1, 0, &count) || count == 0) return 0;
    text[count] = 0;
    return 1;
}

static DWORD WINAPI worker(void *unused) {
    (void)unused;
    WCHAR game_path[32768], own_path[32768];
    char game_hash[65], dll_hash[65], manifest_hash[65];
    if (!GetModuleFileNameW(NULL, game_path, 32768) || !GetModuleFileNameW(self_module, own_path, 32768) ||
        !sha_file(game_path, game_hash) || strcmp(game_hash, GAME_SHA256) != 0 ||
        !sha_file(own_path, dll_hash) || !sha_file(config.manifest_path, manifest_hash)) {
        log_event("VALIDATION_FAILED");
        return 1;
    }
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 2;
    ULARGE_INTEGER creation;
    creation.LowPart = created.dwLowDateTime;
    creation.HighPart = created.dwHighDateTime;
    if (!LobbyGuardStart(&config, &eligible, log_event, dll_hash, manifest_hash)) {
        log_event("LOBBY_GUARD_INSTALL_FAILED");
        return 3;
    }
    log_event("LOBBY_GUARD_INSTALLED");
    DWORD stability_status = StabilityGuardStart(self_module, log_event);
    if (stability_status != ERROR_SUCCESS || !StabilityGuardInstalled() || StabilityGuardVerify() != ERROR_SUCCESS) {
        if (StabilityGuardSafeToLog()) {
            char failure[128];
            snprintf(failure, sizeof(failure), "STABILITY_GUARD_INSTALL_FAILED status=%lu", (unsigned long)stability_status);
            log_event(failure);
        }
        return 4;
    }
    log_event("STABILITY_GUARD_INSTALLED");
    log_event("WORKER_STARTED");
    while (WaitForSingleObject(stop_event, 0) != WAIT_OBJECT_0) {
        if (!StabilityGuardInstalled() || StabilityGuardVerify() != ERROR_SUCCESS) {
            InterlockedExchange(&eligible, 0);
            log_event("STABILITY_GUARD_LOST");
            break;
        }
        HANDLE pipe = CreateFileW(config.pipe_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (pipe == INVALID_HANDLE_VALUE) { WaitForSingleObject(stop_event, 2000); continue; }
        DWORD mode = PIPE_READMODE_MESSAGE;
        char message[4096], challenge[256], proof[65];
        int ok = SetNamedPipeHandleState(pipe, &mode, NULL, NULL) && receive_message(pipe, challenge, sizeof(challenge));
        if (!ok || strncmp(challenge, "CHALLENGE|", 10) != 0 || strlen(challenge + 10) != 64) { CloseHandle(pipe); WaitForSingleObject(stop_event, 2000); continue; }
        int length = snprintf(message, sizeof(message), "VERIFY|%u|%lu|%llu|%s|%s|1.19.3.0|%s|%s|%s|%s", config.protocol, GetCurrentProcessId(), (unsigned long long)creation.QuadPart, config.session, config.player, game_hash, manifest_hash, dll_hash, challenge + 10);
        ok = length > 0 && length < (int)sizeof(message) && hmac_message(config.secret, message, proof);
        if (ok) { strcat(message, "|"); strcat(message, proof); ok = send_message(pipe, message) && receive_message(pipe, message, sizeof(message)); }
        if (ok && strncmp(message, "ACCEPT|", 7) == 0) {
            if (!StabilityGuardInstalled() || StabilityGuardVerify() != ERROR_SUCCESS) {
                CloseHandle(pipe);
                log_event("STABILITY_GUARD_LOST");
                break;
            }
            char lease[128];
            strncpy(lease, message + 7, sizeof(lease) - 1);
            lease[sizeof(lease) - 1] = 0;
            InterlockedExchange(&eligible, 1);
            log_event("VERIFIED_ELIGIBLE");
            while (WaitForSingleObject(stop_event, config.heartbeat_ms) != WAIT_OBJECT_0) {
                if (!StabilityGuardInstalled() || StabilityGuardVerify() != ERROR_SUCCESS) {
                    InterlockedExchange(&eligible, 0);
                    log_event("STABILITY_GUARD_LOST");
                    break;
                }
                snprintf(message, sizeof(message), "HEARTBEAT|%s", lease);
                if (!send_message(pipe, message) || !receive_message(pipe, message, sizeof(message)) || strcmp(message, "ALIVE") != 0) break;
            }
        } else if (ok) log_event(message);
        InterlockedExchange(&eligible, 0);
        log_event("NOT_ELIGIBLE");
        CloseHandle(pipe);
        WaitForSingleObject(stop_event, 2000);
    }
    log_event("WORKER_STOPPED");
    return 0;
}

__declspec(dllexport) DWORD WINAPI AdmissionStart(void *pointer) {
    const AdmissionConfig *incoming = pointer;
    if (!incoming || incoming->magic != ADMISSION_MAGIC || incoming->bytes != sizeof(config) || incoming->protocol != ADMISSION_PROTOCOL ||
        incoming->heartbeat_ms < 500 || incoming->heartbeat_ms > 4000 || incoming->session[63] || incoming->player[63] ||
        incoming->pipe_path[255] || incoming->manifest_path[1023] || incoming->log_path[1023]) return ERROR_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&started, 1, 0) != 0) return ERROR_ALREADY_EXISTS;
    memcpy(&config, incoming, sizeof(config));
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE thread = stop_event ? CreateThread(NULL, 0, worker, NULL, 0, NULL) : NULL;
    if (!thread) {
        DWORD error = GetLastError();
        if (stop_event) CloseHandle(stop_event);
        stop_event = NULL;
        InterlockedExchange(&started, 0);
        return error;
    }
    CloseHandle(thread);
    return 0;
}
__declspec(dllexport) DWORD WINAPI AdmissionStop(void *unused) { (void)unused; InterlockedExchange(&eligible, 0); LobbyGuardStop(); if (stop_event) SetEvent(stop_event); return 0; }
__declspec(dllexport) DWORD WINAPI AdmissionEligible(void *unused) { (void)unused; return (DWORD)InterlockedCompareExchange(&eligible, 0, 0); }
__declspec(dllexport) DWORD WINAPI AdmissionLobbyState(void *unused) { (void)unused; return LobbyGuardState(); }
__declspec(dllexport) DWORD WINAPI AdmissionStabilityState(void *unused) { (void)unused; return StabilityGuardInstalled() && StabilityGuardVerify() == ERROR_SUCCESS ? 1u : 0u; }
__declspec(dllexport) DWORD WINAPI AdmissionStabilityStats(void *destination) { return StabilityGuardGetStats(destination); }

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) { self_module = module; DisableThreadLibraryCalls(module); }
    // No networking, hashing, threads, waits or hook installation under loader lock.
    return TRUE;
}
