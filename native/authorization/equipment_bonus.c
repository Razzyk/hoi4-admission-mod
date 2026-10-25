#include "equipment_bonus.h"

#include <string.h>

typedef struct BonusList {
    uintptr_t entries;
    int32_t capacity;
    int32_t count;
} BonusList;

typedef struct BonusEntry {
    int32_t id;
    int64_t value;
} BonusEntry;

#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
static AuthorityEquipmentBonusResolveTestFn bonusTestResolveRef;
static AuthorityEquipmentBonusQueryTestFn bonusTestQuery;
static AuthorityEquipmentBonusCopyTestFn bonusTestCopy;
static AuthorityEquipmentBonusDestroyTestFn bonusTestDestroy;
void AuthorityEquipmentBonusTestSetResolvers(
    AuthorityEquipmentBonusResolveTestFn resolveRef,
    AuthorityEquipmentBonusQueryTestFn query,
    AuthorityEquipmentBonusCopyTestFn copy,
    AuthorityEquipmentBonusDestroyTestFn destroy) {
    bonusTestResolveRef = resolveRef;
    bonusTestQuery = query;
    bonusTestCopy = copy;
    bonusTestDestroy = destroy;
}
#endif

static AuthorityResult bonus_invalid(void) {
    AuthorityResult result = {AUTHORITY_DECISION_DENY,
        AUTHORITY_REASON_EQUIPMENT_LEVEL_INVALID, 0};
    return result;
}

static AuthorityResult bonus_allow(void) {
    AuthorityResult result = {AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE, 0};
    return result;
}

static int bonus_read(const void *source, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return source && destination && size &&
        ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) && copied == size;
}

static int bonus_write(void *destination, const void *source, SIZE_T size) {
    SIZE_T copied = 0;
    return destination && source && size &&
        WriteProcessMemory(GetCurrentProcess(), destination, source, size, &copied) && copied == size;
}

static int bonus_read_at(const void *base, uintptr_t offset, void *out, SIZE_T size) {
    uintptr_t address = (uintptr_t)base;
    if (!base || !out || !size || offset > UINTPTR_MAX - size ||
        address > UINTPTR_MAX - offset - size) return 0;
    return bonus_read((const void *)(address + offset), out, size);
}

static int bonus_span(uintptr_t base, size_t count, size_t stride) {
    if (!count) return 1;
    if (!base || count - 1 > SIZE_MAX / stride) return 0;
    size_t last = (count - 1) * stride;
    return base <= UINTPTR_MAX - last && base + last <= UINTPTR_MAX - (stride - 1);
}

static int bonus_read_list(const void *object, BonusList *out) {
    if (!object || !out ||
        !bonus_read_at(object, 8, &out->entries, sizeof(out->entries)) ||
        !bonus_read_at(object, 0x10, &out->capacity, sizeof(out->capacity)) ||
        !bonus_read_at(object, 0x14, &out->count, sizeof(out->count)) ||
        out->capacity < 0 || out->count < 0 || out->count > out->capacity ||
        (out->count && !out->entries) || !bonus_span(out->entries, (size_t)out->count, 0x10))
        return 0;
    return 1;
}

static int bonus_read_entries(const void *object, BonusEntry **outEntries, size_t *outCount) {
    BonusList list;
    BonusEntry *entries = NULL;
    if (!outEntries || !outCount || !bonus_read_list(object, &list)) return 0;
    if (list.count) {
        if ((size_t)list.count > SIZE_MAX / sizeof(*entries)) return 0;
        entries = (BonusEntry *)HeapAlloc(GetProcessHeap(), 0,
            (size_t)list.count * sizeof(*entries));
        if (!entries) return 0;
    }
    for (int32_t i = 0; i < list.count; ++i) {
        uintptr_t address = list.entries + (uintptr_t)i * 0x10;
        if (!bonus_read((void *)address, &entries[i].id, sizeof(entries[i].id)) ||
            !bonus_read((void *)(address + 8), &entries[i].value, sizeof(entries[i].value))) {
            if (entries) HeapFree(GetProcessHeap(), 0, entries);
            return 0;
        }
    }
    *outEntries = entries;
    *outCount = (size_t)list.count;
    return 1;
}

static int bonus_entries_equal(const BonusEntry *left, size_t leftCount,
    const BonusEntry *right, size_t rightCount) {
    if (leftCount != rightCount) return 0;
    for (size_t i = 0; i < leftCount; ++i)
        if (left[i].id != right[i].id || left[i].value != right[i].value) return 0;
    return 1;
}

static void *bonus_resolve_ref(unsigned char *imageBase, void *reference) {
    typedef void *(__fastcall *ResolveRefFn)(void *);
#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
    if (bonusTestResolveRef) return bonusTestResolveRef(reference);
#endif
    return ((ResolveRefFn)(imageBase + 0x221f310))(reference);
}

static void *bonus_query(unsigned char *imageBase, void *mio, void *output, void *type) {
    typedef void *(__fastcall *QueryFn)(void *, void *, void *);
#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
    if (bonusTestQuery) return bonusTestQuery(mio, output, type);
#endif
    return ((QueryFn)(imageBase + 0x0db7a10))(mio, output, type);
}

static void bonus_copy(unsigned char *imageBase, void *destination, void *source) {
    typedef void (__fastcall *CopyFn)(void *, void *);
#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
    if (bonusTestCopy) { bonusTestCopy(destination, source); return; }
#endif
    ((CopyFn)(imageBase + 0x0bd1e20))(destination, source);
}

static void bonus_destroy(unsigned char *imageBase, void *object) {
    typedef void (__fastcall *DestroyFn)(void *, uint32_t);
#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
    if (bonusTestDestroy) { bonusTestDestroy(object, 0); return; }
#endif
    ((DestroyFn)(imageBase + 0x15f7e0))(object, 0);
}

static int bonus_resolve_typed_variant(unsigned char *imageBase, void *reference,
    void **outVariant) {
    uintptr_t value = 0, vtable = 0;
    void *variant = NULL;
    if (!reference || !outVariant || !bonus_read(reference, &value, sizeof(value)) || !value)
        return 0;
    variant = bonus_resolve_ref(imageBase, reference);
    if (!variant || !bonus_read(variant, &vtable, sizeof(vtable)) ||
        vtable != (uintptr_t)(imageBase + 0x2951608)) return 0;
    *outVariant = variant;
    return 1;
}

static int bonus_resolve_mio(unsigned char *imageBase, void *reference,
    uint64_t referenceValue, void **outMio) {
    uintptr_t vtable = 0;
    void *mio = NULL;
    if (!outMio) return 0;
    *outMio = NULL;
    if (!referenceValue) return 1;
    mio = bonus_resolve_ref(imageBase, reference);
    if (!mio || !bonus_read(mio, &vtable, sizeof(vtable)) ||
        vtable != (uintptr_t)(imageBase + 0x2967a28)) return 0;
    *outMio = mio;
    return 1;
}

AuthorityResult AuthorityValidateEquipmentBonusReferences(unsigned char *imageBase,
    void *command) {
    uintptr_t commandVtable = 0;
    uint32_t bonusOffset = 0, mioOffset = 0;
    uint64_t mioReference = 0;
    void *mio = NULL;
    BonusEntry *entries = NULL;
    size_t count = 0;
    if (!imageBase || !command || !bonus_read(command, &commandVtable, sizeof(commandVtable)))
        return bonus_invalid();
    if (commandVtable == (uintptr_t)(imageBase + 0x2a240c0)) {
        bonusOffset = 0x168;
        mioOffset = 0x15c;
    } else if (commandVtable == (uintptr_t)(imageBase + 0x2a24188)) {
        bonusOffset = 0x158;
        mioOffset = 0x14c;
    } else return bonus_invalid();

    if (!bonus_read_at(command, mioOffset, &mioReference, sizeof(mioReference)) ||
        !bonus_resolve_mio(imageBase, (uint8_t *)command + mioOffset,
            mioReference, &mio) ||
        !bonus_read_entries((uint8_t *)command + bonusOffset, &entries, &count)) {
        if (entries) HeapFree(GetProcessHeap(), 0, entries);
        return bonus_invalid();
    }
    if (entries) HeapFree(GetProcessHeap(), 0, entries);
    return bonus_allow();
}

AuthorityResult AuthorityCanonicalizeEquipmentBonus(unsigned char *imageBase,
    void *command) {
    uintptr_t commandVtable = 0;
    uint32_t bonusOffset = 0, scalarOffset = 0, mioOffset = 0;
    void *type = NULL, *variant = NULL, *mio = NULL;
    uint64_t commandMioRef = 0, inheritedMioRef = 0;
    uint32_t commandScalar = 0, inheritedScalar = 0;
    BonusEntry *commandEntries = NULL, *inheritedEntries = NULL;
    size_t commandCount = 0, inheritedCount = 0;
    int hasInherited = 0;
    if (!imageBase || !command || !bonus_read(command, &commandVtable, sizeof(commandVtable)))
        return bonus_invalid();
    if (commandVtable == (uintptr_t)(imageBase + 0x2a240c0)) {
        bonusOffset = 0x168; scalarOffset = 0x188; mioOffset = 0x15c;
        if (!bonus_read_at(command, 0x28, &type, sizeof(type)) || !type) return bonus_invalid();
        uint8_t hasParent = 0;
        if (!bonus_read_at(command, 0x3c, &hasParent, sizeof(hasParent)) || hasParent > 1)
            return bonus_invalid();
        if (hasParent) {
            if (!bonus_resolve_typed_variant(imageBase, (uint8_t *)command + 0x34, &variant))
                return bonus_invalid();
            void *parentType = NULL;
            if (!bonus_read_at(variant, 0x3f0, &parentType, sizeof(parentType)) || parentType != type ||
                !bonus_read_at(variant, 0x488, &inheritedMioRef, sizeof(inheritedMioRef)) ||
                !bonus_read_at(variant, 0x4b0, &inheritedScalar, sizeof(inheritedScalar)))
                return bonus_invalid();
            hasInherited = 1;
        }
    } else if (commandVtable == (uintptr_t)(imageBase + 0x2a24188)) {
        bonusOffset = 0x158; scalarOffset = 0x178; mioOffset = 0x14c;
        if (!bonus_resolve_typed_variant(imageBase, (uint8_t *)command + 0x28, &variant) ||
            !bonus_read_at(command, 0x30, &type, sizeof(type)) || !type) return bonus_invalid();
        void *liveType = NULL;
        if (!bonus_read_at(variant, 0x3f0, &liveType, sizeof(liveType)) || liveType != type ||
            !bonus_read_at(variant, 0x488, &inheritedMioRef, sizeof(inheritedMioRef)) ||
            !bonus_read_at(variant, 0x4b0, &inheritedScalar, sizeof(inheritedScalar)))
            return bonus_invalid();
        hasInherited = 1;
    } else return bonus_invalid();

    if (!bonus_read_at(command, mioOffset, &commandMioRef, sizeof(commandMioRef)) ||
        !bonus_read_at(command, scalarOffset, &commandScalar, sizeof(commandScalar)) ||
        !bonus_read_entries((uint8_t *)command + bonusOffset, &commandEntries, &commandCount))
        goto invalid;
    if (hasInherited && inheritedMioRef == commandMioRef) {
        if (!bonus_read_entries((uint8_t *)variant + 0x490, &inheritedEntries, &inheritedCount))
            goto invalid;
        if (inheritedScalar == commandScalar && bonus_entries_equal(commandEntries,
            commandCount, inheritedEntries, inheritedCount)) {
            if (commandEntries) HeapFree(GetProcessHeap(), 0, commandEntries);
            if (inheritedEntries) HeapFree(GetProcessHeap(), 0, inheritedEntries);
            return bonus_allow();
        }
    }
    if (!bonus_resolve_mio(imageBase, (uint8_t *)command + mioOffset,
        commandMioRef, &mio)) goto invalid;
    if (!mio) {
        BonusList list;
        uint32_t zero = 0;
        if (!bonus_read_list((uint8_t *)command + bonusOffset, &list) ||
            !bonus_write((void *)((uintptr_t)command + bonusOffset + 0x14), &zero, sizeof(zero)) ||
            !bonus_write((void *)((uintptr_t)command + scalarOffset), &zero, sizeof(zero)))
            goto invalid;
    } else {
        _Alignas(16) unsigned char output[0x20] = {0};
        void *queryResult = bonus_query(imageBase, mio, output, type);
        BonusEntry *trustedEntries = NULL;
        size_t trustedCount = 0;
        uint32_t trustedScalar = 0;
        int queryValid = queryResult && bonus_read_entries(output, &trustedEntries, &trustedCount) &&
            bonus_read_at(mio, 0x148, &trustedScalar, sizeof(trustedScalar));
        if (queryValid) {
            BonusList destination;
            queryValid = bonus_read_list((uint8_t *)command + bonusOffset, &destination);
        }
        if (queryValid) {
            bonus_copy(imageBase, (uint8_t *)command + bonusOffset, output);
            queryValid = bonus_write((void *)((uintptr_t)command + scalarOffset),
                &trustedScalar, sizeof(trustedScalar));
        }
        if (trustedEntries) HeapFree(GetProcessHeap(), 0, trustedEntries);
        bonus_destroy(imageBase, output);
        if (!queryValid) goto invalid;
    }
    if (commandEntries) HeapFree(GetProcessHeap(), 0, commandEntries);
    if (inheritedEntries) HeapFree(GetProcessHeap(), 0, inheritedEntries);
    return bonus_allow();
invalid:
    if (commandEntries) HeapFree(GetProcessHeap(), 0, commandEntries);
    if (inheritedEntries) HeapFree(GetProcessHeap(), 0, inheritedEntries);
    return bonus_invalid();
}
