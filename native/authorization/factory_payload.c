#include "factory_payload.h"

typedef struct FactoryRow {
    uintptr_t line;
    int64_t requested;
    int64_t projected;
    int32_t maximum;
    int occupied;
} FactoryRow;

#ifdef AUTHORITY_FACTORY_PAYLOAD_TEST
static AuthorityFactoryResolveRefTestFn testResolveRef;
static AuthorityFactoryCanonicalEqualTestFn testCanonicalEqual;
static AuthorityFactoryMaxTestFn testMaxFactories;

void AuthorityFactoryPayloadTestSetResolvers(AuthorityFactoryResolveRefTestFn resolveRef,
    AuthorityFactoryCanonicalEqualTestFn canonicalEqual,
    AuthorityFactoryMaxTestFn maxFactories) {
    testResolveRef = resolveRef;
    testCanonicalEqual = canonicalEqual;
    testMaxFactories = maxFactories;
}
#endif

static AuthorityResult factory_result(AuthorityDecision decision, AuthorityReason reason) {
    AuthorityResult result = {decision, reason, 0};
    return result;
}

static AuthorityResult factory_malformed(void) {
    return factory_result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);
}

static int factory_read(const void *source, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return source && destination && size &&
        ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) && copied == size;
}

static void *factory_at(const void *base, uintptr_t offset) {
    uintptr_t address = (uintptr_t)base;
    if (!base || address > UINTPTR_MAX - offset) return NULL;
    return (void *)(address + offset);
}

static int factory_read_at(const void *base, uintptr_t offset, void *out, SIZE_T size) {
    void *address = factory_at(base, offset);
    return address && factory_read(address, out, size);
}

static int factory_indexed_address(uintptr_t base, size_t index, size_t stride,
    uintptr_t *out) {
    if (!base || !out || (index && stride > SIZE_MAX / index)) return 0;
    size_t offset = index * stride;
    if (base > UINTPTR_MAX - offset) return 0;
    *out = base + offset;
    return 1;
}

static int factory_country_valid(void *world, int32_t country) {
    uintptr_t tags = 0;
    int32_t count = -1;
    return country >= 0 &&
        factory_read_at(world, 0x340, &tags, sizeof(tags)) && tags &&
        factory_read_at(world, 0x34c, &count, sizeof(count)) &&
        count >= 0 && country < count;
}

static int factory_countries_equal(unsigned char *imageBase, void *world,
    int32_t left, int32_t right) {
    typedef unsigned char (__fastcall *CanonicalEqualFn)(const int32_t *, int32_t);
    if (!factory_country_valid(world, left) || !factory_country_valid(world, right)) return 0;
    if (left == right) return 1;
#ifdef AUTHORITY_FACTORY_PAYLOAD_TEST
    if (testCanonicalEqual) return testCanonicalEqual(&left, right) != 0;
#endif
    return ((CanonicalEqualFn)(imageBase + 0xbb52f0))(&left, right) != 0;
}

static int factory_sender_owns_country(unsigned char *imageBase, void *world,
    uint64_t senderMachineId, int32_t country) {
    uintptr_t roster = 0;
    int32_t count = -1;
    unsigned matches = 0;
    if (!senderMachineId || senderMachineId > INT32_MAX ||
        !factory_read_at(world, 0xf8, &roster, sizeof(roster)) || !roster ||
        !factory_read_at(world, 0x104, &count, sizeof(count)) || count < 0) return 0;
    for (int32_t i = 0; i < count; ++i) {
        uintptr_t record = 0;
        int32_t machineId = 0, recordCountry = -1;
        if (!factory_indexed_address(roster, (size_t)i, 0xa0, &record) ||
            !factory_read_at((void *)record, 0x98, &machineId, sizeof(machineId)) ||
            !factory_read_at((void *)record, 0x70, &recordCountry, sizeof(recordCountry))) return 0;
        if (machineId != (int32_t)senderMachineId) continue;
        ++matches;
        if (!factory_countries_equal(imageBase, world, recordCountry, country)) return 0;
    }
    return matches == 1;
}

static void *factory_resolve_ref(unsigned char *imageBase, void *reference) {
    typedef void *(__fastcall *ResolveRefFn)(void *);
#ifdef AUTHORITY_FACTORY_PAYLOAD_TEST
    if (testResolveRef) return testResolveRef(reference);
#endif
    return ((ResolveRefFn)(imageBase + 0x221f310))(reference);
}

static int factory_line_vtable_allowed(unsigned char *imageBase, uintptr_t vtable) {
    static const uint32_t allowed[] = {
        0x297bc80, /* military equipment production line */
        0x297be68, /* naval equipment production line */
        0x297bfc8, /* railway gun production line */
        0x297c488  /* ship refit production line */
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
        if (vtable == (uintptr_t)(imageBase + allowed[i])) return 1;
    return 0;
}

static int factory_getter_valid(unsigned char *imageBase, uintptr_t vtable) {
    static const struct { uint32_t vtableRva, getterRva; } getters[] = {
        {0x297bc80, 0x0f6eb40},
        {0x297be68, 0x0f6f430},
        {0x297bfc8, 0x0f70990},
        {0x297c488, 0x0f6f430}
    };
    uintptr_t function = 0;
    for (size_t i = 0; i < sizeof(getters) / sizeof(getters[0]); ++i) {
        if (vtable != (uintptr_t)(imageBase + getters[i].vtableRva)) continue;
        return factory_read((void *)(vtable + 0x58), &function, sizeof(function)) &&
            function == (uintptr_t)(imageBase + getters[i].getterRva);
    }
    return 0;
}

static int factory_line_valid(unsigned char *imageBase, void *line) {
    uintptr_t vtable = 0;
    /* Rocket line is intentionally omitted: it is a CReferenceObject, not a
       CProductionLine. Building/rail-repair lines are general, not equipment. */
    return line && factory_read(line, &vtable, sizeof(vtable)) &&
        factory_line_vtable_allowed(imageBase, vtable) && factory_getter_valid(imageBase, vtable);
}

static int factory_line_owner(unsigned char *imageBase, void *world, void *line,
    int32_t *outCountry) {
    void *status = NULL, *countryObject = NULL;
    int32_t country = -1;
    if (!factory_read_at(line, 0x20, &status, sizeof(status)) || !status ||
        !factory_read_at(status, 0x290, &countryObject, sizeof(countryObject)) || !countryObject ||
        !factory_read_at(countryObject, 8, &country, sizeof(country)) || country <= 0 ||
        !factory_country_valid(world, country)) return 0;
    *outCountry = country;
    (void)imageBase;
    return 1;
}

static int factory_vector_read(void *command, uintptr_t pointerOffset,
    uintptr_t capacityOffset, uintptr_t countOffset, size_t stride,
    uintptr_t *data, int32_t *count) {
    int32_t capacity = -1;
    if (!factory_read_at(command, pointerOffset, data, sizeof(*data)) ||
        !factory_read_at(command, capacityOffset, &capacity, sizeof(capacity)) ||
        !factory_read_at(command, countOffset, count, sizeof(*count)) ||
        *count < 0 || capacity < *count || (*count && !*data)) return 0;
    /* Prove the full element span can be represented before any indexed read. */
    if (*count > 0) {
        uintptr_t last = 0;
        if (!factory_indexed_address(*data, (size_t)(*count - 1), stride, &last) ||
            last > UINTPTR_MAX - (stride - 1)) return 0;
    }
    return 1;
}

static size_t factory_hash(uintptr_t value) {
    value ^= value >> 33;
    value *= (uintptr_t)0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= (uintptr_t)0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return (size_t)value;
}

static int factory_hash_capacity(size_t count, size_t *out) {
    size_t need;
    if (!out || count > SIZE_MAX / 2) return 0;
    need = count * 2;
    if (need < 8) need = 8;
    size_t capacity = 8;
    while (capacity < need) {
        if (capacity > SIZE_MAX / 2) return 0;
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(FactoryRow)) return 0;
    *out = capacity;
    return 1;
}

static int factory_resolve_max(unsigned char *imageBase, void *line, int32_t *outMax) {
    uintptr_t vtable = 0, function = 0;
    if (!factory_read(line, &vtable, sizeof(vtable)) ||
        !factory_line_vtable_allowed(imageBase, vtable) ||
        !factory_read((void *)(vtable + 0x58), &function, sizeof(function)) || !function)
        return 0;
    if (!factory_getter_valid(imageBase, vtable)) return 0;
#ifdef AUTHORITY_FACTORY_PAYLOAD_TEST
    if (testMaxFactories) { *outMax = testMaxFactories(line); return 1; }
#endif
    typedef int32_t (__fastcall *MaxFn)(void *);
    *outMax = ((MaxFn)function)(line);
    return 1;
}

AuthorityResult AuthorityValidateFactoryPayload(unsigned char *imageBase,
    void *world, void *command, uint64_t senderMachineId,
    uint32_t commandVtableRva, int safetyOnly) {
    uintptr_t commandVtable = 0;
    uintptr_t refs = 0, deltas = 0;
    int32_t refCount = 0, deltaCount = 0;
    int isMass = 0;
    FactoryRow *rows = NULL;
    size_t rowCapacity = 0;
    AuthorityResult result = factory_malformed();
    if (!imageBase || !world || !command || !senderMachineId ||
        !factory_read(command, &commandVtable, sizeof(commandVtable)) ||
        commandVtable != (uintptr_t)(imageBase + commandVtableRva)) return factory_malformed();

    /* The vtable RVA passed by the pinned adapter selects exactly one layout;
       only these two reviewed command classes are accepted. */
    if (commandVtableRva == 0x2994db0) {
        refs = (uintptr_t)factory_at(command, 0x28);
        deltas = (uintptr_t)factory_at(command, 0x30);
        refCount = deltaCount = 1;
    } else if (commandVtableRva == 0x2993a28) {
        isMass = 1;
        if (!factory_vector_read(command, 0x28, 0x30, 0x34, 8, &refs, &refCount) ||
            !factory_vector_read(command, 0x40, 0x48, 0x4c, 4, &deltas, &deltaCount) ||
            refCount != deltaCount) return factory_malformed();
    } else return factory_malformed();

    if (!isMass) {
        if (!refs || !deltas || refs > UINTPTR_MAX - 7) return factory_malformed();
    } else if (refCount > 0) {
        uintptr_t lastRef = 0, lastDelta = 0;
        if (!factory_indexed_address(refs, (size_t)(refCount - 1), 8, &lastRef) ||
            lastRef > UINTPTR_MAX - 7 ||
            !factory_indexed_address(deltas, (size_t)(refCount - 1), 4, &lastDelta) ||
            lastDelta > UINTPTR_MAX - 3) return factory_malformed();
    }

    if (!safetyOnly && isMass && refCount) {
        if (!factory_hash_capacity((size_t)refCount, &rowCapacity)) return factory_malformed();
        rows = (FactoryRow *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            rowCapacity * sizeof(FactoryRow));
        if (!rows) return factory_malformed();
    }

    for (int32_t i = 0; i < refCount; ++i) {
        uintptr_t refAddress = refs;
        uintptr_t deltaAddress = deltas;
        if (isMass && (!factory_indexed_address(refs, (size_t)i, 8, &refAddress) ||
            !factory_indexed_address(deltas, (size_t)i, 4, &deltaAddress))) goto done;
        void *line = factory_resolve_ref(imageBase, (void *)refAddress);
        int32_t delta = 0, owner = -1;
        if (!line || !factory_line_valid(imageBase, line) ||
            !factory_read((void *)deltaAddress, &delta, sizeof(delta))) goto done;
        if (!factory_line_owner(imageBase, world, line, &owner)) goto done;
        if (!safetyOnly && !factory_sender_owns_country(imageBase, world,
            senderMachineId, owner)) {
            result = factory_result(AUTHORITY_DECISION_DENY,
                AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);
            goto done;
        }
        if (!safetyOnly) {
            int32_t current = 0, maximum = 0;
            if (!factory_read_at(line, 0xe8, &current, sizeof(current)) || current < 0 ||
                !factory_resolve_max(imageBase, line, &maximum) || maximum < 0)
                goto done;
            if (isMass) {
                size_t slot = factory_hash((uintptr_t)line) & (rowCapacity - 1);
                while (rows[slot].occupied && rows[slot].line != (uintptr_t)line)
                    slot = (slot + 1) & (rowCapacity - 1);
                FactoryRow *row = &rows[slot];
                if (!row->occupied) {
                    row->occupied = 1;
                    row->line = (uintptr_t)line;
                    row->requested = current;
                    row->projected = current;
                    row->maximum = maximum;
                } else if (row->requested != current || row->maximum != maximum) goto done;
                row->projected += (int64_t)delta;
                if (row->projected < 0 || row->projected > (int64_t)row->maximum) goto done;
            } else {
                int64_t projected = (int64_t)current + (int64_t)delta;
                if (projected < 0 || projected > (int64_t)maximum) goto done;
            }
        }
    }
    result = factory_result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
done:
    if (rows) HeapFree(GetProcessHeap(), 0, rows);
    return result;
}
