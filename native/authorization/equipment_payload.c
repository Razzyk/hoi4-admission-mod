#include "equipment_payload.h"

#include <stdlib.h>

typedef struct EquipmentList {
    uintptr_t entries;
    uint32_t count;
    uint32_t capacity;
} EquipmentList;

typedef struct EquipmentDefinitionVector {
    uintptr_t entries;
    uint32_t count;
    uint32_t capacity;
} EquipmentDefinitionVector;

typedef struct TrustedDefinition {
    int32_t id;
    void *definition;
    uint32_t originalIndex;
} TrustedDefinition;

#ifdef AUTHORITY_EQUIPMENT_PAYLOAD_TEST
static AuthorityEquipmentResolveRefTestFn equipmentTestResolveRef;
static AuthorityEquipmentLevelAllowedTestFn equipmentTestLevelAllowed;
void AuthorityEquipmentPayloadTestSetResolvers(
    AuthorityEquipmentResolveRefTestFn resolveRef,
    AuthorityEquipmentLevelAllowedTestFn levelAllowed) {
    equipmentTestResolveRef = resolveRef;
    equipmentTestLevelAllowed = levelAllowed;
}
#endif

static AuthorityResult equipment_result(AuthorityDecision decision, AuthorityReason reason) {
    AuthorityResult result = {decision, reason, 0};
    return result;
}

static AuthorityResult equipment_invalid(void) {
    return equipment_result(AUTHORITY_DECISION_DENY,
        AUTHORITY_REASON_EQUIPMENT_LEVEL_INVALID);
}

static int equipment_read(const void *source, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return source && destination && size &&
        ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) && copied == size;
}

static int equipment_write(void *destination, const void *source, SIZE_T size) {
    SIZE_T copied = 0;
    return destination && source && size &&
        WriteProcessMemory(GetCurrentProcess(), destination, source, size, &copied) && copied == size;
}

static int equipment_read_at(const void *base, uintptr_t offset, void *out, SIZE_T size) {
    uintptr_t address = (uintptr_t)base;
    if (!base || !out || !size || offset > UINTPTR_MAX - size ||
        address > UINTPTR_MAX - offset - size) return 0;
    return equipment_read((const void *)(address + offset), out, size);
}

static int equipment_span(uintptr_t base, size_t count, size_t stride) {
    if (!count) return 1;
    if (!base || count - 1 > SIZE_MAX / stride) return 0;
    size_t last = (count - 1) * stride;
    return base <= UINTPTR_MAX - last && base + last <= UINTPTR_MAX - (stride - 1);
}

static int equipment_read_list(const void *object, EquipmentList *out) {
    int32_t capacity = -1, count = -1;
    if (!object || !out ||
        !equipment_read_at(object, 8, &out->entries, sizeof(out->entries)) ||
        !equipment_read_at(object, 0x10, &capacity, sizeof(capacity)) ||
        !equipment_read_at(object, 0x14, &count, sizeof(count)) ||
        capacity < 0 || count < 0 || count > capacity ||
        (count && !out->entries) || !equipment_span(out->entries, (size_t)count, 0x10)) return 0;
    out->capacity = (uint32_t)capacity;
    out->count = (uint32_t)count;
    return 1;
}

static int equipment_read_definitions(void *vectorObject, EquipmentDefinitionVector *out) {
    int32_t capacity = -1, count = -1;
    if (!vectorObject || !out ||
        !equipment_read_at(vectorObject, 0, &out->entries, sizeof(out->entries)) ||
        !equipment_read_at(vectorObject, 8, &capacity, sizeof(capacity)) ||
        !equipment_read_at(vectorObject, 0xc, &count, sizeof(count)) ||
        capacity < 0 || count < 0 || count > capacity ||
        (count && !out->entries) || !equipment_span(out->entries, (size_t)count, 8)) return 0;
    out->capacity = (uint32_t)capacity;
    out->count = (uint32_t)count;
    return 1;
}

static int equipment_definition_id(void *definition, int32_t *outId) {
    return definition && outId && equipment_read_at(definition, 8, outId, sizeof(*outId));
}

static void *equipment_resolve_ref(unsigned char *imageBase, void *reference) {
    typedef void *(__fastcall *ResolveRefFn)(void *);
#ifdef AUTHORITY_EQUIPMENT_PAYLOAD_TEST
    if (equipmentTestResolveRef) return equipmentTestResolveRef(reference);
#endif
    return ((ResolveRefFn)(imageBase + 0x221f310))(reference);
}

static int equipment_compare_definition(const void *left, const void *right) {
    const TrustedDefinition *a = (const TrustedDefinition *)left;
    const TrustedDefinition *b = (const TrustedDefinition *)right;
    if (a->id != b->id) return (a->id > b->id) - (a->id < b->id);
    return (a->originalIndex > b->originalIndex) - (a->originalIndex < b->originalIndex);
}

static int equipment_allocation_size(size_t count, size_t itemSize, size_t *out) {
    if (!out || count > SIZE_MAX / itemSize) return 0;
    *out = count * itemSize;
    return 1;
}

static int equipment_definition_ids(void *type, TrustedDefinition **outDefinitions, size_t *outCount) {
    EquipmentDefinitionVector vector;
    size_t bytes = 0;
    TrustedDefinition *definitions = NULL;
    if (!outDefinitions || !outCount ||
        !equipment_read_definitions((uint8_t *)type + 0x58, &vector) ||
        !equipment_allocation_size(vector.count, sizeof(*definitions), &bytes)) return 0;
    if (vector.count) {
        definitions = (TrustedDefinition *)HeapAlloc(GetProcessHeap(), 0, bytes);
        if (!definitions) return 0;
    }
    for (uint32_t i = 0; i < vector.count; ++i) {
        uintptr_t address = vector.entries + (uintptr_t)i * 8;
        void *definition = NULL;
        if (!equipment_read((void *)address, &definition, sizeof(definition)) ||
            !equipment_definition_id(definition, &definitions[i].id) || definitions[i].id < 0) {
            if (definitions) HeapFree(GetProcessHeap(), 0, definitions);
            return 0;
        }
        definitions[i].definition = definition;
        definitions[i].originalIndex = i;
    }
    if (vector.count > 1) qsort(definitions, vector.count, sizeof(*definitions), equipment_compare_definition);
    size_t uniqueCount = 0;
    for (uint32_t i = 0; i < vector.count; ++i) {
        if (uniqueCount && definitions[uniqueCount - 1].id == definitions[i].id) continue;
        definitions[uniqueCount++] = definitions[i];
    }
    *outDefinitions = definitions;
    *outCount = uniqueCount;
    return 1;
}

static void *equipment_find_trusted_definition(const TrustedDefinition *definitions,
    size_t count, int32_t id) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (definitions[mid].id < id) lo = mid + 1;
        else hi = mid;
    }
    return lo < count && definitions[lo].id == id ? definitions[lo].definition : NULL;
}

static int equipment_read_sorted_levels(const void *listObject,
    int32_t **outIds, uint8_t **outLevels, size_t *outCount) {
    EquipmentList list;
    size_t idBytes = 0, levelBytes = 0;
    int32_t *ids = NULL;
    uint8_t *levels = NULL;
    if (!outIds || !outLevels || !outCount || !equipment_read_list(listObject, &list) ||
        !equipment_allocation_size(list.count, sizeof(*ids), &idBytes) ||
        !equipment_allocation_size(list.count, sizeof(*levels), &levelBytes)) return 0;
    if (list.count) {
        ids = (int32_t *)HeapAlloc(GetProcessHeap(), 0, idBytes);
        levels = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, levelBytes);
        if (!ids || !levels) goto fail;
    }
    for (uint32_t i = 0; i < list.count; ++i) {
        uintptr_t address = list.entries + (uintptr_t)i * 0x10;
        void *definition = NULL;
        if (!equipment_read((void *)address, &definition, sizeof(definition)) ||
            !equipment_definition_id(definition, &ids[i]) || ids[i] < 0 ||
            !equipment_read((void *)(address + 8), &levels[i], sizeof(levels[i])) ||
            (i && ids[i] <= ids[i - 1])) goto fail;
    }
    *outIds = ids;
    *outLevels = levels;
    *outCount = list.count;
    return 1;
fail:
    if (ids) HeapFree(GetProcessHeap(), 0, ids);
    if (levels) HeapFree(GetProcessHeap(), 0, levels);
    return 0;
}

static int equipment_find_level(const int32_t *ids, const uint8_t *levels,
    size_t count, int32_t id, uint8_t *outLevel) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ids[mid] < id) lo = mid + 1;
        else hi = mid;
    }
    if (lo == count || ids[lo] != id) return 0;
    *outLevel = levels[lo];
    return 1;
}

static int equipment_validate(unsigned char *imageBase, void *command,
    uint32_t commandRva, int safetyOnly) {
    void *type = NULL;
    TrustedDefinition *trustedDefinitions = NULL;
    int32_t *baselineIds = NULL;
    uint8_t *baselineLevels = NULL;
    size_t trustedCount = 0, baselineCount = 0;
    EquipmentList payload;
    int32_t previousPayloadId = -1;
    int32_t *actorTag = NULL;
    void *variant = NULL;
    int result = 0;

    if (commandRva == 0x2a240c0) {
        if (!equipment_read_at(command, 0x28, &type, sizeof(type)) || !type) goto done;
        actorTag = (int32_t *)((uintptr_t)command + 0x30);
        uint8_t hasParent = 0;
        if (!equipment_read_at(command, 0x3c, &hasParent, sizeof(hasParent)) || hasParent > 1)
            goto done;
        if (hasParent) {
            uintptr_t referenceValue = 0;
            if (!equipment_read_at(command, 0x34, &referenceValue, sizeof(referenceValue)) ||
                !referenceValue)
                goto done;
            variant = equipment_resolve_ref(imageBase, (uint8_t *)command + 0x34);
            uintptr_t vtable = 0;
            void *parentType = NULL;
            if (!variant || !equipment_read(variant, &vtable, sizeof(vtable)) ||
                vtable != (uintptr_t)(imageBase + 0x2951608) ||
                !equipment_read_at(variant, 0x3f0, &parentType, sizeof(parentType)) ||
                parentType != type ||
                !equipment_read_sorted_levels((uint8_t *)variant + 0x68,
                    &baselineIds, &baselineLevels, &baselineCount)) goto done;
        }
        if (!equipment_read_list((uint8_t *)command + 0x60, &payload)) goto done;
    } else if (commandRva == 0x2a24188) {
        uintptr_t referenceValue = 0;
        void *serializedType = NULL;
        if (!equipment_read_at(command, 0x28, &referenceValue, sizeof(referenceValue)) || !referenceValue ||
            !equipment_read_at(command, 0x30, &serializedType, sizeof(serializedType)) ||
            !serializedType) goto done;
        variant = equipment_resolve_ref(imageBase, (uint8_t *)command + 0x28);
        uintptr_t vtable = 0;
        void *liveType = NULL;
        if (!variant || !equipment_read(variant, &vtable, sizeof(vtable)) ||
            vtable != (uintptr_t)(imageBase + 0x2951608) ||
            !equipment_read_at(variant, 0x3f0, &liveType, sizeof(liveType)) ||
            liveType != serializedType) goto done;
        type = liveType;
        actorTag = (int32_t *)((uintptr_t)variant + 0x1c);
        if (!equipment_read_sorted_levels((uint8_t *)variant + 0x68,
            &baselineIds, &baselineLevels, &baselineCount) ||
            !equipment_read_list((uint8_t *)command + 0x58, &payload)) goto done;
    } else goto done;

    if (!equipment_definition_ids(type, &trustedDefinitions, &trustedCount)) goto done;
    for (uint32_t i = 0; i < payload.count; ++i) {
        uintptr_t entry = payload.entries + (uintptr_t)i * 0x10;
        void *untrustedDefinition = NULL;
        int32_t id = -1;
        uint8_t requested = 0, oldLevel = 0;
        void *trustedDefinition = NULL;
        if (!equipment_read((void *)entry, &untrustedDefinition, sizeof(untrustedDefinition)) ||
            !equipment_definition_id(untrustedDefinition, &id) || id < 0 ||
            id <= previousPayloadId ||
            !equipment_read((void *)(entry + 8), &requested, sizeof(requested)) ||
            !(trustedDefinition = equipment_find_trusted_definition(trustedDefinitions,
                trustedCount, id))) goto done;
        previousPayloadId = id;
        int hasBaseline = equipment_find_level(baselineIds, baselineLevels,
            baselineCount, id, &oldLevel);
        if (!hasBaseline) oldLevel = 0;
        if (!safetyOnly && requested != oldLevel) {
            typedef unsigned char (__fastcall *LevelAllowedFn)(void *, int32_t *, uint8_t, void *, uint32_t);
            unsigned char allowed;
#ifdef AUTHORITY_EQUIPMENT_PAYLOAD_TEST
            if (equipmentTestLevelAllowed)
                allowed = equipmentTestLevelAllowed(trustedDefinition, actorTag, requested, NULL, 0);
            else
#endif
                allowed = ((LevelAllowedFn)(imageBase + 0x1537970))(
                    trustedDefinition, actorTag, requested, NULL, 0);
            if (!allowed) goto done;
        }
    }
    if (!safetyOnly) {
        for (uint32_t i = 0; i < payload.count; ++i) {
            uintptr_t entry = payload.entries + (uintptr_t)i * 0x10;
            void *serializedDefinition = NULL;
            int32_t id = -1;
            if (!equipment_read((void *)entry, &serializedDefinition, sizeof(serializedDefinition)) ||
                !equipment_definition_id(serializedDefinition, &id)) goto done;
            void *trustedDefinition = equipment_find_trusted_definition(trustedDefinitions,
                trustedCount, id);
            if (!trustedDefinition || (serializedDefinition != trustedDefinition &&
                !equipment_write((void *)entry, &trustedDefinition, sizeof(trustedDefinition))))
                goto done;
        }
    }
    result = 1;
done:
    if (trustedDefinitions) HeapFree(GetProcessHeap(), 0, trustedDefinitions);
    if (baselineIds) HeapFree(GetProcessHeap(), 0, baselineIds);
    if (baselineLevels) HeapFree(GetProcessHeap(), 0, baselineLevels);
    return result;
}

AuthorityResult AuthorityValidateEquipmentPayload(unsigned char *imageBase,
    void *command, int safetyOnly) {
    uintptr_t vtable = 0;
    if (!imageBase || !command || !equipment_read(command, &vtable, sizeof(vtable)))
        return equipment_invalid();
    uint32_t commandRva = 0;
    if (vtable == (uintptr_t)(imageBase + 0x2a240c0)) commandRva = 0x2a240c0;
    else if (vtable == (uintptr_t)(imageBase + 0x2a24188)) commandRva = 0x2a24188;
    else return equipment_invalid();
    return equipment_validate(imageBase, command, commandRva, safetyOnly)
        ? equipment_result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE)
        : equipment_invalid();
}
