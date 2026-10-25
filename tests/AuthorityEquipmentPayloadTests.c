/* Isolated fixtures for the pinned equipment payload validator. */
#define AUTHORITY_EQUIPMENT_PAYLOAD_TEST
#include "../native/authorization/equipment_payload.c"

#include <stdio.h>
#include <string.h>

static unsigned assertions;
static unsigned predicateCalls;
static unsigned char predicateResult;
static void *lastPredicateDefinition;
static int32_t *lastActorTag;
static uint8_t lastRequested;
static void *expectedReference;
static const char *caseName;
static unsigned char image[0x2b00000];
static unsigned char createCommand[0x200];
static unsigned char updateCommand[0x200];
static unsigned char typeObject[0x100];
static unsigned char variant[0x500];
static unsigned char definitionA[0x20], definitionB[0x20], definitionC[0x20];
static unsigned char foreignDefinition[0x20];
static unsigned char unknownDefinition[0x20];
static uintptr_t trustedDefinitions[4];
static unsigned char trustedVector[0x20];
static unsigned char createPayload[8][0x10];
static unsigned char updatePayload[8][0x10];
static unsigned char parentPayload[8][0x10];

#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    fprintf(stderr, "FAIL %s line %d: %s\n", caseName, __LINE__, #condition); ExitProcess(1); \
} } while (0)

static void put(void *base, size_t offset, const void *value, size_t size) {
    memcpy((unsigned char *)base + offset, value, size);
}

static void put_ptr(void *base, size_t offset, const void *value) {
    uintptr_t pointer = (uintptr_t)value;
    put(base, offset, &pointer, sizeof(pointer));
}

static void set_id(void *definition, int32_t id) { put(definition, 8, &id, sizeof(id)); }

static void set_list(void *object, void *entries, int32_t capacity, int32_t count) {
    put_ptr(object, 8, entries);
    put(object, 0x10, &capacity, sizeof(capacity));
    put(object, 0x14, &count, sizeof(count));
}

static void set_payload_entry(void *entry, void *definition, uint8_t level) {
    put_ptr(entry, 0, definition);
    put(entry, 8, &level, sizeof(level));
}

static void put_vtable(void *object, uint32_t rva) {
    uintptr_t vtable = (uintptr_t)(image + rva);
    put(object, 0, &vtable, sizeof(vtable));
}

static void * __fastcall resolve_ref(void *reference) {
    uintptr_t token = 0;
    CHECK(reference == expectedReference);
    if (!equipment_read(reference, &token, sizeof(token)) || token != 1) return NULL;
    return variant;
}

static unsigned char __fastcall level_allowed(void *definition, int32_t *actorTag,
    uint8_t requested, void *unused, uint32_t flags) {
    (void)unused;
    ++predicateCalls;
    lastPredicateDefinition = definition;
    lastActorTag = actorTag;
    lastRequested = requested;
    CHECK(flags == 0);
    return predicateResult;
}

static void setup_type(void) {
    memset(typeObject, 0, sizeof(typeObject));
    memset(trustedVector, 0, sizeof(trustedVector));
    trustedDefinitions[0] = (uintptr_t)definitionA;
    trustedDefinitions[1] = (uintptr_t)definitionB;
    trustedDefinitions[2] = (uintptr_t)definitionC;
    int32_t three = 3;
    put_ptr(typeObject, 0x58, trustedDefinitions);
    put(typeObject, 0x60, &three, sizeof(three));
    put(typeObject, 0x64, &three, sizeof(three));
}

static void setup(const char *name) {
    caseName = name;
    memset(image, 0, sizeof(image));
    memset(createCommand, 0, sizeof(createCommand));
    memset(updateCommand, 0, sizeof(updateCommand));
    memset(variant, 0, sizeof(variant));
    memset(createPayload, 0, sizeof(createPayload));
    memset(updatePayload, 0, sizeof(updatePayload));
    memset(parentPayload, 0, sizeof(parentPayload));
    set_id(definitionA, 10); set_id(definitionB, 20); set_id(definitionC, 30);
    set_id(foreignDefinition, 20);
    set_id(unknownDefinition, 5);
    setup_type();
    put_vtable(createCommand, 0x2a240c0);
    put_ptr(createCommand, 0x28, typeObject);
    int32_t actor = 4; put(createCommand, 0x30, &actor, sizeof(actor));
    set_list(createCommand + 0x60, createPayload, 8, 0);
    put_vtable(updateCommand, 0x2a24188);
    uintptr_t ref = 1;
    put(updateCommand, 0x28, &ref, sizeof(ref));
    put_ptr(updateCommand, 0x30, typeObject);
    set_list(updateCommand + 0x58, updatePayload, 8, 0);
    put_vtable(variant, 0x2951608);
    put_ptr(variant, 0x3f0, typeObject);
    actor = 4; put(variant, 0x1c, &actor, sizeof(actor));
    set_list(variant + 0x68, parentPayload, 8, 0);
    predicateCalls = 0;
    predicateResult = 1;
    lastPredicateDefinition = NULL;
    lastActorTag = NULL;
    lastRequested = 0;
    AuthorityEquipmentPayloadTestSetResolvers(resolve_ref, level_allowed);
}

static AuthorityResult run(void *command, int safetyOnly) {
    expectedReference = command == createCommand
        ? (void *)(createCommand + 0x34) : (void *)(updateCommand + 0x28);
    return AuthorityValidateEquipmentPayload(image, command, safetyOnly);
}

static void test_create_and_native_level_rule(void) {
    setup("Create changed level uses trusted type definition");
    set_payload_entry(createPayload[0], foreignDefinition, 2);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    EquipmentList debugPayload;
    TrustedDefinition *debugTrusted = NULL;
    size_t debugCount = 0;
    CHECK(equipment_read_list(createCommand + 0x60, &debugPayload));
    CHECK(equipment_definition_ids(typeObject, &debugTrusted, &debugCount));
    CHECK(debugCount == 3 && equipment_find_trusted_definition(debugTrusted, debugCount, 20) == definitionB);
    HeapFree(GetProcessHeap(), 0, debugTrusted);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 1);
    CHECK(lastPredicateDefinition == definitionB);
    CHECK(lastActorTag == (int32_t *)(createCommand + 0x30));
    CHECK(lastRequested == 2);

    setup("unsorted trusted type definitions remain valid");
    trustedDefinitions[0] = (uintptr_t)definitionC;
    trustedDefinitions[1] = (uintptr_t)definitionA;
    trustedDefinitions[2] = (uintptr_t)definitionB;
    set_payload_entry(createPayload[0], foreignDefinition, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(lastPredicateDefinition == definitionB);

    setup("identical trusted definition pointers deduplicate to first ID entry");
    trustedDefinitions[0] = (uintptr_t)definitionA;
    trustedDefinitions[1] = (uintptr_t)definitionA;
    trustedDefinitions[2] = (uintptr_t)definitionB;
    trustedDefinitions[3] = (uintptr_t)definitionC;
    int32_t four = 4;
    put(typeObject, 0x60, &four, sizeof(four));
    put(typeObject, 0x64, &four, sizeof(four));
    set_payload_entry(createPayload[0], definitionA, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(lastPredicateDefinition == definitionA);

    setup("duplicate trusted IDs use the first original type vector pointer");
    trustedDefinitions[0] = (uintptr_t)definitionA;
    trustedDefinitions[1] = (uintptr_t)foreignDefinition;
    trustedDefinitions[2] = (uintptr_t)definitionB;
    trustedDefinitions[3] = (uintptr_t)definitionC;
    put(typeObject, 0x60, &four, sizeof(four));
    put(typeObject, 0x64, &four, sizeof(four));
    set_payload_entry(createPayload[0], definitionB, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(lastPredicateDefinition == foreignDefinition);

    setup("payload aliases normalize to first trusted definition pointer");
    trustedDefinitions[0] = (uintptr_t)foreignDefinition;
    trustedDefinitions[1] = (uintptr_t)definitionB;
    trustedDefinitions[2] = (uintptr_t)definitionA;
    trustedDefinitions[3] = (uintptr_t)definitionC;
    put(typeObject, 0x60, &four, sizeof(four));
    put(typeObject, 0x64, &four, sizeof(four));
    set_payload_entry(createPayload[0], definitionB, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(lastPredicateDefinition == foreignDefinition);
    CHECK(*(uintptr_t *)createPayload[0] == (uintptr_t)foreignDefinition);

    setup("safety-only payload validation preserves serialized definition pointer");
    trustedDefinitions[0] = (uintptr_t)foreignDefinition;
    trustedDefinitions[1] = (uintptr_t)definitionB;
    trustedDefinitions[2] = (uintptr_t)definitionA;
    trustedDefinitions[3] = (uintptr_t)definitionC;
    put(typeObject, 0x60, &four, sizeof(four));
    put(typeObject, 0x64, &four, sizeof(four));
    set_payload_entry(createPayload[0], definitionB, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(*(uintptr_t *)createPayload[0] == (uintptr_t)definitionB);

    setup("native level predicate false denies");
    predicateResult = 0;
    set_payload_entry(createPayload[0], definitionA, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).reason == AUTHORITY_REASON_EQUIPMENT_LEVEL_INVALID);
}

static void test_grandfather_and_create_parent(void) {
    setup("no parent unchanged zero skips predicate");
    set_payload_entry(createPayload[0], definitionA, 0);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 0);

    setup("Create same-type foreign parent unchanged level is grandfathered");
    set_payload_entry(parentPayload[0], definitionA, 255);
    set_list(variant + 0x68, parentPayload, 1, 1);
    int32_t parentOwner = 6; put(variant, 0x1c, &parentOwner, sizeof(parentOwner));
    uintptr_t ref = 1;
    put(createCommand, 0x34, &ref, sizeof(ref));
    uint8_t present = 1; put(createCommand, 0x3c, &present, sizeof(present));
    set_payload_entry(createPayload[0], definitionA, 255);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 0);

    setup("Create changed inherited level checks cap");
    set_payload_entry(parentPayload[0], definitionA, 255);
    set_list(variant + 0x68, parentPayload, 1, 1);
    ref = 1; put(createCommand, 0x34, &ref, sizeof(ref));
    present = 1; put(createCommand, 0x3c, &present, sizeof(present));
    set_payload_entry(createPayload[0], definitionA, 254);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 1);
}

static void test_update_type_and_levels(void) {
    setup("Update exact type and unchanged 255 grandfather");
    set_payload_entry(parentPayload[0], definitionA, 255);
    set_list(variant + 0x68, parentPayload, 1, 1);
    set_payload_entry(updatePayload[0], definitionA, 255);
    set_list(updateCommand + 0x58, updatePayload, 1, 1);
    CHECK(run(updateCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 0);

    setup("Update type change denied");
    unsigned char otherType[0x100] = {0};
    put_ptr(updateCommand, 0x30, otherType);
    CHECK(run(updateCommand, 1).reason == AUTHORITY_REASON_EQUIPMENT_LEVEL_INVALID);

    setup("Update changed level checks native predicate");
    set_payload_entry(parentPayload[0], definitionB, 255);
    set_list(variant + 0x68, parentPayload, 1, 1);
    set_payload_entry(updatePayload[0], definitionB, 1);
    set_list(updateCommand + 0x58, updatePayload, 1, 1);
    CHECK(run(updateCommand, 0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 1 && lastRequested == 1 && lastActorTag == (int32_t *)(variant + 0x1c));
}

static void test_safety_only_and_payload_shape(void) {
    setup("safety preflight avoids predicate");
    set_payload_entry(createPayload[0], definitionA, 2);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(predicateCalls == 0);

    setup("unknown payload key denied");
    set_payload_entry(createPayload[0], foreignDefinition, 1);
    set_id(foreignDefinition, 99);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("duplicate or unsorted payload IDs denied");
    set_payload_entry(createPayload[0], definitionB, 1);
    set_payload_entry(createPayload[1], definitionA, 1);
    set_list(createCommand + 0x60, createPayload, 2, 2);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("duplicate payload IDs denied");
    set_payload_entry(createPayload[0], definitionA, 1);
    set_payload_entry(createPayload[1], definitionA, 2);
    set_list(createCommand + 0x60, createPayload, 2, 2);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("negative payload ID denied");
    int32_t negativeId = -1;
    set_id(foreignDefinition, negativeId);
    set_payload_entry(createPayload[0], foreignDefinition, 1);
    set_list(createCommand + 0x60, createPayload, 1, 1);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("unknown prefix cannot suppress a later known level check");
    set_payload_entry(createPayload[0], unknownDefinition, 1);
    set_payload_entry(createPayload[1], definitionB, 2);
    set_list(createCommand + 0x60, createPayload, 2, 2);
    CHECK(run(createCommand, 0).decision == AUTHORITY_DECISION_DENY);
    CHECK(predicateCalls == 0);

    setup("payload count above capacity denied");
    set_list(createCommand + 0x60, createPayload, 0, 1);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("malformed type vector rejected");
    uintptr_t bad = UINTPTR_MAX - 4;
    put_ptr(typeObject, 0x58, (void *)bad);
    int32_t one = 1; put(typeObject, 0x60, &one, sizeof(one)); put(typeObject, 0x64, &one, sizeof(one));
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);

    setup("invalid typed parent denied");
    uintptr_t ref = 1; put(createCommand, 0x34, &ref, sizeof(ref));
    uint8_t present = 1; put(createCommand, 0x3c, &present, sizeof(present));
    put_vtable(variant, 0x2951600);
    CHECK(run(createCommand, 1).decision == AUTHORITY_DECISION_DENY);
}

int main(void) {
    test_create_and_native_level_rule();
    test_grandfather_and_create_parent();
    test_update_type_and_levels();
    test_safety_only_and_payload_shape();
    printf("Authority equipment payload tests passed (%u assertions).\n", assertions);
    return 0;
}
