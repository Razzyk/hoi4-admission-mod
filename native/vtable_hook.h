#ifndef HOI4_VTABLE_HOOK_H
#define HOI4_VTABLE_HOOK_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define VTABLE_HOOK_MAX_SLOTS 16u
#define VTABLE_HOOK_MAX_ENTRY 32u

/* Verify the executable hash and callback ABI separately before use. Only
 * aligned pointer slots in non-executable main PE64 image pages are supported.
 * Run outside DllMain. Atomic pointer publication needs no thread suspension.
 * Wrappers and their original pointers must remain valid until process exit,
 * including after removal: a callback may already have fetched the wrapper. */
typedef struct VtableHookSpec {
    uint32_t slot_rva, original_rva;
    unsigned char expected_entry[VTABLE_HOOK_MAX_ENTRY];
    uint32_t entry_length;
    void *wrapper;
} VtableHookSpec;

typedef enum VtableHookResult {
    VTABLE_HOOK_OK = 0, VTABLE_HOOK_BUSY, VTABLE_HOOK_BAD_STATE,
    VTABLE_HOOK_BAD_SPEC, VTABLE_HOOK_BAD_IMAGE, VTABLE_HOOK_BYTES_MISMATCH,
    VTABLE_HOOK_SLOT_CONFLICT, VTABLE_HOOK_PROTECT_FAILED, VTABLE_HOOK_ROLLBACK_FAILED
} VtableHookResult;

typedef enum VtableHookState {
    VTABLE_HOOK_EMPTY = 0, VTABLE_HOOK_PREPARED, VTABLE_HOOK_INSTALLED, VTABLE_HOOK_POISONED
} VtableHookState;

typedef struct VtableHookSlot {
    VtableHookSpec spec;
    void *volatile *address;
    void *original;
    void *page;
    SIZE_T page_size;
} VtableHookSlot;

/* Zero-initialize once; do not copy/reset a prepared set or unload wrappers. */
typedef struct VtableHookSet {
    volatile LONG busy, state, last_result, last_windows_error;
    volatile LONG64 prepare_attempts, install_attempts, remove_attempts;
    volatile LONG64 installs, removals, refusals, rollbacks, conflicts;
    unsigned char *image;
    SIZE_T image_size;
    size_t count;
    VtableHookSlot slots[VTABLE_HOOK_MAX_SLOTS];
} VtableHookSet;

typedef struct VtableHookStatus {
    VtableHookState state;
    VtableHookResult result;
    DWORD windows_error;
    size_t slot_count;
    uint64_t prepare_attempts, install_attempts, remove_attempts;
    uint64_t installs, removals, refusals, rollbacks, conflicts;
} VtableHookStatus;

VtableHookResult VtableHookPrepare(VtableHookSet *set, const VtableHookSpec *specs, size_t count);
void *VtableHookOriginal(const VtableHookSet *set, size_t index);
VtableHookResult VtableHookInstall(VtableHookSet *set);
VtableHookResult VtableHookRemove(VtableHookSet *set);
void VtableHookGetStatus(const VtableHookSet *set, VtableHookStatus *status);
const char *VtableHookResultName(VtableHookResult result);
#endif
