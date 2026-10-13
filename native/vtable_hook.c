#include "vtable_hook.h"
#include <string.h>

#if !defined(_WIN64)
#error This hook engine requires Windows x64.
#endif

static VtableHookResult finish(VtableHookSet *set, VtableHookResult result, DWORD error) {
    InterlockedExchange(&set->last_result, (LONG)result);
    InterlockedExchange(&set->last_windows_error, (LONG)error);
    if (result != VTABLE_HOOK_OK) InterlockedIncrement64(&set->refusals);
    if (result == VTABLE_HOOK_SLOT_CONFLICT) InterlockedIncrement64(&set->conflicts);
    InterlockedExchange(&set->busy, 0);
    return result;
}

static int copy_memory(const void *source, void *out, SIZE_T size) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), source, out, size, &copied) && copied == size;
}

static int image_range(const unsigned char *base, SIZE_T size, SIZE_T offset, SIZE_T length, int executable) {
    if (!length || offset > size || length > size - offset) return 0;
    uintptr_t current = (uintptr_t)base + offset, end = current + length;
    while (current < end) {
        MEMORY_BASIC_INFORMATION region;
        if (!VirtualQuery((void *)current, &region, sizeof(region)) || region.State != MEM_COMMIT ||
                region.Type != MEM_IMAGE || region.AllocationBase != base || (region.Protect & PAGE_GUARD)) return 0;
        DWORD protection = region.Protect & 0xffu;
        int has_execute = protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (executable ? !has_execute : (has_execute || (protection != PAGE_READONLY &&
                protection != PAGE_READWRITE && protection != PAGE_WRITECOPY))) return 0;
        uintptr_t next = (uintptr_t)region.BaseAddress + region.RegionSize;
        if (next <= current) return 0;
        current = next < end ? next : end;
    }
    return 1;
}

static int main_image(unsigned char **base_out, SIZE_T *size_out) {
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    MEMORY_BASIC_INFORMATION region;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (!base || !VirtualQuery(base, &region, sizeof(region)) || region.Type != MEM_IMAGE ||
            region.State != MEM_COMMIT || region.AllocationBase != base ||
            !copy_memory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew > 1024 * 1024 ||
            !copy_memory(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
            nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt.OptionalHeader.SizeOfImage < nt.OptionalHeader.SizeOfHeaders ||
            nt.OptionalHeader.SizeOfHeaders < (DWORD)dos.e_lfanew + sizeof(nt)) return 0;
    *base_out = base;
    *size_out = nt.OptionalHeader.SizeOfImage;
    return image_range(base, *size_out, 0, nt.OptionalHeader.SizeOfHeaders, 0);
}

static int executable_address(const void *address) {
    MEMORY_BASIC_INFORMATION region;
    if (!address || !VirtualQuery(address, &region, sizeof(region)) || region.State != MEM_COMMIT ||
            (region.Protect & PAGE_GUARD)) return 0;
    DWORD protection = region.Protect & 0xffu;
    return protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
}

static int entry_matches(const VtableHookSet *set, const VtableHookSlot *slot) {
    unsigned char actual[VTABLE_HOOK_MAX_ENTRY];
    return image_range(set->image, set->image_size, slot->spec.original_rva, slot->spec.entry_length, 1) &&
        copy_memory(slot->original, actual, slot->spec.entry_length) &&
        memcmp(actual, slot->spec.expected_entry, slot->spec.entry_length) == 0;
}

/* A plain aligned volatile x64 pointer load is atomic and has acquire ordering.
 * CAS cannot be used just to read a read-only vtable: it requires write access. */
static void *read_slot(const VtableHookSlot *slot) {
    void *value = *slot->address;
    MemoryBarrier();
    return value;
}

VtableHookResult VtableHookPrepare(VtableHookSet *set, const VtableHookSpec *specs, size_t count) {
    if (!set) return VTABLE_HOOK_BAD_SPEC;
    if (InterlockedCompareExchange(&set->busy, 1, 0)) return VTABLE_HOOK_BUSY;
    InterlockedIncrement64(&set->prepare_attempts);
    if (set->state != VTABLE_HOOK_EMPTY) return finish(set, VTABLE_HOOK_BAD_STATE, 0);
    if (!specs || !count || count > VTABLE_HOOK_MAX_SLOTS) return finish(set, VTABLE_HOOK_BAD_SPEC, 0);
    if (!main_image(&set->image, &set->image_size)) return finish(set, VTABLE_HOOK_BAD_IMAGE, GetLastError());
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    for (size_t i = 0; i < count; ++i) {
        VtableHookSlot *slot = &set->slots[i];
        slot->spec = specs[i];
        if (!slot->spec.entry_length || slot->spec.entry_length > VTABLE_HOOK_MAX_ENTRY ||
                slot->spec.slot_rva % sizeof(void *) || !executable_address(slot->spec.wrapper) ||
                !image_range(set->image, set->image_size, slot->spec.slot_rva, sizeof(void *), 0) ||
                !image_range(set->image, set->image_size, slot->spec.original_rva, slot->spec.entry_length, 1))
            return finish(set, VTABLE_HOOK_BAD_SPEC, 0);
        for (size_t j = 0; j < i; ++j)
            if (slot->spec.slot_rva == set->slots[j].spec.slot_rva)
                return finish(set, VTABLE_HOOK_BAD_SPEC, 0);
        slot->address = (void *volatile *)(set->image + slot->spec.slot_rva);
        slot->original = set->image + slot->spec.original_rva;
        slot->page_size = info.dwPageSize;
        slot->page = (void *)((uintptr_t)slot->address & ~((uintptr_t)info.dwPageSize - 1u));
        if (read_slot(slot) != slot->original) return finish(set, VTABLE_HOOK_SLOT_CONFLICT, 0);
        if (!entry_matches(set, slot)) return finish(set, VTABLE_HOOK_BYTES_MISMATCH, 0);
    }
    set->count = count;
    InterlockedExchange(&set->state, VTABLE_HOOK_PREPARED);
    return finish(set, VTABLE_HOOK_OK, 0);
}

void *VtableHookOriginal(const VtableHookSet *set, size_t index) {
    return set && index < set->count ? set->slots[index].original : NULL;
}

static int restore_protections(const VtableHookSet *set, const DWORD *old, size_t count, DWORD *error) {
    int ok = 1;
    for (size_t i = count; i > 0; --i) {
        DWORD discarded;
        const VtableHookSlot *slot = &set->slots[i - 1];
        if (!VirtualProtect(slot->page, slot->page_size, old[i - 1], &discarded)) {
            if (!*error) *error = GetLastError();
            ok = 0;
        }
    }
    return ok;
}

static VtableHookResult mutate(VtableHookSet *set, int removing) {
    if (!set) return VTABLE_HOOK_BAD_SPEC;
    if (InterlockedCompareExchange(&set->busy, 1, 0)) return VTABLE_HOOK_BUSY;
    if (removing) InterlockedIncrement64(&set->remove_attempts);
    else InterlockedIncrement64(&set->install_attempts);
    if (set->state != (removing ? VTABLE_HOOK_INSTALLED : VTABLE_HOOK_PREPARED))
        return finish(set, VTABLE_HOOK_BAD_STATE, 0);
    DWORD old[VTABLE_HOOK_MAX_SLOTS] = {0}, error = 0;
    size_t protected_count = 0, changed_count = 0;
    VtableHookResult result = VTABLE_HOOK_OK;
    for (size_t i = 0; i < set->count; ++i) {
        const VtableHookSlot *slot = &set->slots[i];
        if (!image_range(set->image, set->image_size, slot->spec.slot_rva, sizeof(void *), 0) ||
                !entry_matches(set, slot)) {
            result = VTABLE_HOOK_BYTES_MISMATCH;
            break;
        }
        if (read_slot(slot) != (removing ? slot->spec.wrapper : slot->original)) {
            result = VTABLE_HOOK_SLOT_CONFLICT;
            break;
        }
    }
    if (result == VTABLE_HOOK_OK) {
        for (size_t i = 0; i < set->count; ++i) {
            const VtableHookSlot *slot = &set->slots[i];
            if (!VirtualProtect(slot->page, slot->page_size, PAGE_READWRITE, &old[i])) {
                error = GetLastError();
                result = VTABLE_HOOK_PROTECT_FAILED;
                break;
            }
            ++protected_count;
        }
    }
    /* Callers publish original callback pointers before invoking Install.
     * InterlockedCompareExchangePointer is the release publication barrier. */
    if (result == VTABLE_HOOK_OK) {
        for (size_t i = 0; i < set->count; ++i) {
            const VtableHookSlot *slot = &set->slots[i];
            void *before = removing ? slot->spec.wrapper : slot->original;
            void *after = removing ? slot->original : slot->spec.wrapper;
            if (InterlockedCompareExchangePointer(slot->address, after, before) != before) {
                result = VTABLE_HOOK_SLOT_CONFLICT;
                break;
            }
            ++changed_count;
        }
    }
    if (result == VTABLE_HOOK_OK && !restore_protections(set, old, protected_count, &error))
        result = VTABLE_HOOK_PROTECT_FAILED;
    if (result != VTABLE_HOOK_OK && protected_count) {
        int rollback_ok = 1;
        if (changed_count) {
            InterlockedIncrement64(&set->rollbacks);
            /* Some pages may already have been restored when protection
             * restoration failed. Make every changed slot writable again. */
            for (size_t i = 0; i < changed_count; ++i) {
                const VtableHookSlot *slot = &set->slots[i];
                DWORD discarded;
                if (!VirtualProtect(slot->page, slot->page_size, PAGE_READWRITE, &discarded)) {
                    if (!error) error = GetLastError();
                    rollback_ok = 0;
                }
            }
            if (rollback_ok) {
                for (size_t i = changed_count; i > 0; --i) {
                    const VtableHookSlot *slot = &set->slots[i - 1];
                    void *before = removing ? slot->spec.wrapper : slot->original;
                    void *after = removing ? slot->original : slot->spec.wrapper;
                    /* Never overwrite another module's intervening hook. */
                    if (InterlockedCompareExchangePointer(slot->address, before, after) != after)
                        rollback_ok = 0;
                }
            }
        }
        if (!restore_protections(set, old, protected_count, &error)) rollback_ok = 0;
        if (!rollback_ok) {
            InterlockedExchange(&set->state, VTABLE_HOOK_POISONED);
            result = VTABLE_HOOK_ROLLBACK_FAILED;
        }
    }
    if (result == VTABLE_HOOK_OK) {
        InterlockedExchange(&set->state, removing ? VTABLE_HOOK_PREPARED : VTABLE_HOOK_INSTALLED);
        if (removing) InterlockedIncrement64(&set->removals);
        else InterlockedIncrement64(&set->installs);
    }
    return finish(set, result, error);
}

VtableHookResult VtableHookInstall(VtableHookSet *set) { return mutate(set, 0); }
VtableHookResult VtableHookRemove(VtableHookSet *set) { return mutate(set, 1); }

void VtableHookGetStatus(const VtableHookSet *set, VtableHookStatus *status) {
    if (!set || !status) return;
    status->state = (VtableHookState)InterlockedCompareExchange((volatile LONG *)&set->state, 0, 0);
    status->result = (VtableHookResult)InterlockedCompareExchange((volatile LONG *)&set->last_result, 0, 0);
    status->windows_error = (DWORD)InterlockedCompareExchange((volatile LONG *)&set->last_windows_error, 0, 0);
    status->slot_count = set->count;
#define READ_COUNTER(name) status->name = (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)&set->name, 0, 0)
    READ_COUNTER(prepare_attempts); READ_COUNTER(install_attempts); READ_COUNTER(remove_attempts);
    READ_COUNTER(installs); READ_COUNTER(removals); READ_COUNTER(refusals); READ_COUNTER(rollbacks); READ_COUNTER(conflicts);
#undef READ_COUNTER
}

const char *VtableHookResultName(VtableHookResult result) {
    static const char *const names[] = { "OK", "BUSY", "BAD_STATE", "BAD_SPEC", "BAD_IMAGE",
        "BYTES_MISMATCH", "SLOT_CONFLICT", "PROTECT_FAILED", "ROLLBACK_FAILED" };
    return (unsigned)result < sizeof(names) / sizeof(names[0]) ? names[result] : "UNKNOWN";
}
