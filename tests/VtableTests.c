#include "../native/vtable_hook.h"
#include <stdio.h>
#include <string.h>

typedef int (*Callback)(int);
static Callback original_one, original_two;
static volatile LONG stop_worker, worker_failure, worker_calls;
static int failures;

__attribute__((noinline)) static int target_one(int value) { return value + 7; }
__attribute__((noinline)) static int target_two(int value) { return value + 9; }
__attribute__((noinline)) static int wrapper_one(int value) { return original_one(value) + 100; }
__attribute__((noinline)) static int wrapper_two(int value) { return original_two(value) + 200; }
__attribute__((noinline)) static int foreign_wrapper(int value) { return value + 300; }

__attribute__((section(".rdata$hookfixture"), used)) static void *const fixture[2] = {
    (void *)target_one, (void *)target_two
};

static void check(int condition, const char *name) {
    if (!condition) { printf("FAIL %s\n", name); ++failures; }
}
static DWORD protection(const void *address) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery(address, &info, sizeof(info)) ? info.Protect : 0;
}
static int invoke(size_t slot, int value) {
    void *volatile *table = (void *volatile *)(uintptr_t)fixture;
    return ((Callback)table[slot])(value);
}
static DWORD WINAPI worker(LPVOID unused) {
    (void)unused;
    while (!InterlockedCompareExchange(&stop_worker, 0, 0)) {
        int result = invoke(0, 10);
        if (result != 17 && result != 117) InterlockedExchange(&worker_failure, 1);
        InterlockedIncrement(&worker_calls);
    }
    return 0;
}
static void replace_fixture(size_t slot, void *value) {
    DWORD old, discarded;
    void *volatile *table = (void *volatile *)(uintptr_t)fixture;
    check(VirtualProtect((void *)&table[slot], sizeof(void *), PAGE_READWRITE, &old), "fixture protection");
    InterlockedExchangePointer(&table[slot], value);
    check(VirtualProtect((void *)&table[slot], sizeof(void *), old, &discarded), "fixture restore");
}

int main(void) {
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    VtableHookSpec specs[2];
    memset(specs, 0, sizeof(specs));
    for (size_t i = 0; i < 2; ++i) {
        specs[i].slot_rva = (uint32_t)((uintptr_t)&fixture[i] - (uintptr_t)base);
        specs[i].original_rva = (uint32_t)((uintptr_t)fixture[i] - (uintptr_t)base);
        specs[i].entry_length = 8;
        memcpy(specs[i].expected_entry, fixture[i], specs[i].entry_length);
        specs[i].wrapper = i ? (void *)wrapper_two : (void *)wrapper_one;
    }
    DWORD before = protection(fixture);
    check((before & 0xffu) == PAGE_READONLY, "fixture initially read-only");
    check(invoke(0, 10) == 17 && invoke(1, 10) == 19, "baseline original callbacks");

    VtableHookSet bad = {0};
    VtableHookSpec mismatch = specs[0];
    mismatch.expected_entry[0] ^= 1;
    check(VtableHookPrepare(&bad, &mismatch, 1) == VTABLE_HOOK_BYTES_MISMATCH, "entry mismatch refused");
    check(invoke(0, 10) == 17 && protection(fixture) == before, "mismatch preserves callback and protection");
    VtableHookSet conflict = {0};
    VtableHookSpec wrong = specs[0];
    wrong.original_rva = specs[1].original_rva;
    memcpy(wrong.expected_entry, specs[1].expected_entry, wrong.entry_length);
    check(VtableHookPrepare(&conflict, &wrong, 1) == VTABLE_HOOK_SLOT_CONFLICT, "unexpected target refused");

    VtableHookSet set = {0};
    check(VtableHookPrepare(&set, specs, 2) == VTABLE_HOOK_OK, "prepare two shared-page slots");
    original_one = (Callback)VtableHookOriginal(&set, 0);
    original_two = (Callback)VtableHookOriginal(&set, 1);
    check(original_one(10) == 17 && original_two(10) == 19, "original callbacks exposed before publication");
    check(VtableHookInstall(&set) == VTABLE_HOOK_OK, "install");
    check(invoke(0, 10) == 117 && invoke(1, 10) == 219, "wrappers call originals once and alter output");
    check(protection(fixture) == before, "install preserves read-only page protection");

    replace_fixture(0, (void *)foreign_wrapper);
    check(VtableHookRemove(&set) == VTABLE_HOOK_SLOT_CONFLICT, "uninstall refuses foreign replacement");
    check(invoke(0, 10) == 310 && invoke(1, 10) == 219, "foreign replacement remains intact");
    replace_fixture(0, (void *)wrapper_one);
    check(VtableHookRemove(&set) == VTABLE_HOOK_OK, "remove");
    check(invoke(0, 10) == 17 && invoke(1, 10) == 19, "uninstall restores original pointers");
    check(protection(fixture) == before, "remove preserves page protection");

    /* Preparation is not permission to ignore bytes changed before Install. */
    set.slots[0].spec.expected_entry[0] ^= 1;
    check(VtableHookInstall(&set) == VTABLE_HOOK_BYTES_MISMATCH, "install rechecks original entry");
    set.slots[0].spec.expected_entry[0] ^= 1;
    check(invoke(0, 10) == 17 && protection(fixture) == before, "refused install leaves fixture intact");

    HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    check(thread != NULL, "start simultaneous callback reader");
    if (thread) {
        for (int i = 0; i < 100; ++i) {
            check(VtableHookInstall(&set) == VTABLE_HOOK_OK, "stress install");
            check(VtableHookRemove(&set) == VTABLE_HOOK_OK, "stress remove");
        }
        Sleep(10);
        InterlockedExchange(&stop_worker, 1);
        check(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "callback reader stops");
        CloseHandle(thread);
        check(!worker_failure && worker_calls > 0, "concurrent readers see only complete valid pointers");
    }
    VtableHookStatus status;
    VtableHookGetStatus(&set, &status);
    check(status.state == VTABLE_HOOK_PREPARED && status.installs == 101 && status.removals == 101,
        "status counts successful transactions");
    check(status.refusals == 2 && status.conflicts == 1, "status counts conflicts and mismatch refusal");
    check(protection(fixture) == before, "final page protection restored");
    printf("VTABLE HOOK: %s (%ld concurrent callback calls)\n", failures ? "FAILED" : "PASS", worker_calls);
    return failures ? 1 : 0;
}
