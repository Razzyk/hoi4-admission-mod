/* ABI and lifecycle fixtures for equipment MIO bonus canonicalization. */
#define AUTHORITY_EQUIPMENT_BONUS_TEST
#include "../native/authorization/equipment_bonus.c"

#include <stdio.h>
#include <string.h>

static unsigned assertions;
static unsigned queryCalls, copyCalls, destroyCalls;
static const char *caseName;
static unsigned char image[0x2b00000];
static unsigned char createCommand[0x200], updateCommand[0x200];
static unsigned char variant[0x500], typeObject[0x100], mio[0x200], wrongMio[0x200];
static unsigned char createEntries[8][0x10], updateEntries[8][0x10];
static unsigned char variantEntries[8][0x10], queryEntries[8][0x10];
static uintptr_t createEntryArray[8], updateEntryArray[8], variantEntryArray[8], queryEntryArray[8];
static unsigned char *currentCommand;
static void *expectedMioReference;
static uint32_t activeBonusOffset, activeScalarOffset;
static uint64_t initialMioScalar;

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

static void set_list(void *object, void *entries, int32_t capacity, int32_t count) {
    put_ptr(object, 8, entries);
    put(object, 0x10, &capacity, sizeof(capacity));
    put(object, 0x14, &count, sizeof(count));
}

static void set_entry(void *entry, int32_t id, int64_t value) {
    put(entry, 0, &id, sizeof(id));
    put(entry, 8, &value, sizeof(value));
}

static void set_vtable(void *object, uint32_t rva) {
    uintptr_t vtable = (uintptr_t)(image + rva);
    put(object, 0, &vtable, sizeof(vtable));
}

static void * __fastcall resolve_ref(void *reference) {
    uintptr_t token = 0;
    CHECK(bonus_read(reference, &token, sizeof(token)));
    if (token == 1) {
        CHECK(reference == (currentCommand == createCommand
            ? (void *)(createCommand + 0x34) : (void *)(updateCommand + 0x28)));
        return variant;
    }
    if (token == 2) {
        CHECK(reference == expectedMioReference);
        return mio;
    }
    if (token == 3) {
        CHECK(reference == expectedMioReference);
        return wrongMio;
    }
    return NULL;
}

static void * __fastcall query_bonus(void *mioObject, void *output, void *type) {
    CHECK(mioObject == mio);
    CHECK(type == typeObject);
    CHECK(output != NULL);
    ++queryCalls;
    set_list(output, queryEntries, 8, 2);
    set_entry(queryEntries[0], 21, 1234);
    set_entry(queryEntries[1], -9, -765);
    return output;
}

static void __fastcall copy_bonus(void *destination, void *source) {
    CHECK(destination == currentCommand + activeBonusOffset);
    CHECK(source != NULL);
    ++copyCalls;
    BonusList dst, src;
    CHECK(bonus_read_list(destination, &dst));
    CHECK(bonus_read_list(source, &src));
    CHECK(dst.capacity >= src.count);
    for (int32_t i = 0; i < src.count; ++i) {
        BonusEntry entry;
        uintptr_t srcAddress = src.entries + (uintptr_t)i * 0x10;
        uintptr_t dstAddress = dst.entries + (uintptr_t)i * 0x10;
        CHECK(bonus_read((void *)srcAddress, &entry.id, sizeof(entry.id)));
        CHECK(bonus_read((void *)(srcAddress + 8), &entry.value, sizeof(entry.value)));
        CHECK(bonus_write((void *)dstAddress, &entry.id, sizeof(entry.id)));
        CHECK(bonus_write((void *)(dstAddress + 8), &entry.value, sizeof(entry.value)));
    }
    CHECK(bonus_write((void *)((uintptr_t)destination + 0x14), &src.count, sizeof(src.count)));
}

static void __fastcall destroy_bonus(void *object, uint32_t flags) {
    CHECK(object != NULL);
    CHECK(flags == 0);
    ++destroyCalls;
}

static void setup(const char *name, int update) {
    caseName = name;
    memset(image, 0, sizeof(image));
    memset(createCommand, 0, sizeof(createCommand));
    memset(updateCommand, 0, sizeof(updateCommand));
    memset(variant, 0, sizeof(variant));
    memset(typeObject, 0, sizeof(typeObject));
    memset(mio, 0, sizeof(mio));
    memset(wrongMio, 0, sizeof(wrongMio));
    memset(createEntries, 0, sizeof(createEntries));
    memset(updateEntries, 0, sizeof(updateEntries));
    memset(variantEntries, 0, sizeof(variantEntries));
    memset(queryEntries, 0, sizeof(queryEntries));
    memset(createEntryArray, 0, sizeof(createEntryArray));
    memset(updateEntryArray, 0, sizeof(updateEntryArray));
    memset(variantEntryArray, 0, sizeof(variantEntryArray));
    memset(queryEntryArray, 0, sizeof(queryEntryArray));
    set_vtable(variant, 0x2951608);
    set_vtable(mio, 0x2967a28);
    set_vtable(wrongMio, 0x2967a20);
    uint64_t mioRef = 2;
    put_ptr(variant, 0x3f0, typeObject);
    put(variant, 0x488, &mioRef, sizeof(mioRef));
    set_list(variant + 0x490, variantEntries, 8, 1);
    set_entry(variantEntries[0], 11, 1234);
    uint32_t inheritedScalar = 99;
    put(variant, 0x4b0, &inheritedScalar, sizeof(inheritedScalar));
    uint32_t mioScalar = 456;
    put(mio, 0x148, &mioScalar, sizeof(mioScalar));
    initialMioScalar = mioScalar;
    uintptr_t ref = 1;
    uint64_t currentRef = 2;
    if (update) {
        set_vtable(updateCommand, 0x2a24188);
        put(updateCommand, 0x28, &ref, sizeof(ref));
        put_ptr(updateCommand, 0x30, typeObject);
        put(updateCommand, 0x14c, &currentRef, sizeof(currentRef));
        activeBonusOffset = 0x158; activeScalarOffset = 0x178;
        set_list(updateCommand + activeBonusOffset, updateEntries, 8, 1);
        set_entry(updateEntries[0], 11, 1234);
        put(updateCommand, activeScalarOffset, &inheritedScalar, sizeof(inheritedScalar));
        currentCommand = updateCommand;
        expectedMioReference = updateCommand + 0x14c;
    } else {
        set_vtable(createCommand, 0x2a240c0);
        put_ptr(createCommand, 0x28, typeObject);
        put(createCommand, 0x3c, &(uint8_t){0}, 1);
        put(createCommand, 0x15c, &currentRef, sizeof(currentRef));
        activeBonusOffset = 0x168; activeScalarOffset = 0x188;
        set_list(createCommand + activeBonusOffset, createEntries, 8, 1);
        set_entry(createEntries[0], 11, 1234);
        put(createCommand, activeScalarOffset, &inheritedScalar, sizeof(inheritedScalar));
        currentCommand = createCommand;
        expectedMioReference = createCommand + 0x15c;
    }
    queryCalls = copyCalls = destroyCalls = 0;
    AuthorityEquipmentBonusTestSetResolvers(resolve_ref, query_bonus, copy_bonus, destroy_bonus);
}

static AuthorityResult run(int update) {
    return AuthorityCanonicalizeEquipmentBonus(image, update ? updateCommand : createCommand);
}

static void test_query_and_copy_for_create_update(void) {
    setup("Create forged bonuses canonicalized from trusted MIO query", 0);
    set_entry(createEntries[0], 11, 9999);
    set_list(createCommand + activeBonusOffset, createEntries, 8, 1);
    CHECK(run(0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 1 && copyCalls == 1 && destroyCalls == 1);
    CHECK(*(int32_t *)createEntries[0] == 21);
    CHECK(*(int64_t *)(createEntries[0] + 8) == 1234);
    CHECK(*(int32_t *)createEntries[1] == -9);
    CHECK(*(int64_t *)(createEntries[1] + 8) == -765);
    CHECK(*(uint32_t *)(createCommand + activeScalarOffset) == initialMioScalar);

    setup("Update forged bonus scalar canonicalized", 1);
    uint32_t forgedScalar = 0; put(updateCommand, activeScalarOffset, &forgedScalar, sizeof(forgedScalar));
    CHECK(run(1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 1 && copyCalls == 1 && destroyCalls == 1);
    CHECK(*(uint32_t *)(updateCommand + activeScalarOffset) == initialMioScalar);
}

static void test_inherited_exact_bonus_and_mio_paths(void) {
    setup("Update exact inherited same-reference bonus is preserved", 1);
    set_entry(variantEntries[0], 30, 1234);
    set_entry(variantEntries[1], -7, 55);
    set_list(variant + 0x490, variantEntries, 8, 2);
    set_entry(updateEntries[0], 30, 1234);
    set_entry(updateEntries[1], -7, 55);
    set_list(updateCommand + activeBonusOffset, updateEntries, 8, 2);
    CHECK(run(1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Update exact inherited nonempty bonus with matching null MIO is preserved", 1);
    uint64_t inheritedNullRef = 0;
    put(updateCommand, 0x14c, &inheritedNullRef, sizeof(inheritedNullRef));
    put(variant, 0x488, &inheritedNullRef, sizeof(inheritedNullRef));
    CHECK(run(1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("changed bonus with matching null MIO is cleared", 1);
    put(updateCommand, 0x14c, &inheritedNullRef, sizeof(inheritedNullRef));
    put(variant, 0x488, &inheritedNullRef, sizeof(inheritedNullRef));
    set_entry(updateEntries[0], 11, 9999);
    CHECK(run(1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);
    CHECK(*(int32_t *)(updateCommand + activeBonusOffset + 0x14) == 0);
    CHECK(*(uint32_t *)(updateCommand + activeScalarOffset) == 0);

    setup("Updated MIO reference recomputes current bonuses", 1);
    uint64_t oldRef = 3;
    put(variant, 0x488, &oldRef, sizeof(oldRef));
    CHECK(run(1).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 1 && copyCalls == 1 && destroyCalls == 1);

    setup("Create exact same-type parent bonus is preserved", 0);
    uintptr_t nullParentRef = 1;
    uint8_t hasNullParent = 1;
    put(createCommand, 0x34, &nullParentRef, sizeof(nullParentRef));
    put(createCommand, 0x3c, &hasNullParent, sizeof(hasNullParent));
    CHECK(run(0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Null MIO clears count and scalar without a query", 0);
    uint64_t zeroRef = 0;
    put(createCommand, 0x15c, &zeroRef, sizeof(zeroRef));
    uintptr_t parentRef = 1;
    uint8_t hasParent = 1;
    put(createCommand, 0x34, &parentRef, sizeof(parentRef));
    put(createCommand, 0x3c, &hasParent, sizeof(hasParent));
    put(variant, 0x488, &zeroRef, sizeof(zeroRef));
    set_entry(createEntries[0], 11, 1234);
    uint32_t forged = 88; put(createCommand, activeScalarOffset, &forged, sizeof(forged));
    CHECK(run(0).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);
    CHECK(*(int32_t *)(createCommand + activeBonusOffset + 0x14) == 0);
    CHECK(*(uint32_t *)(createCommand + activeScalarOffset) == 0);
    CHECK(*(uintptr_t *)(createCommand + activeBonusOffset + 8) == (uintptr_t)createEntries);
}

static void test_invalid_refs_and_type(void) {
    setup("Wrong typed MIO denied", 0);
    uint64_t badRef = 3;
    put(createCommand, 0x15c, &badRef, sizeof(badRef));
    expectedMioReference = createCommand + 0x15c;
    CHECK(run(0).decision == AUTHORITY_DECISION_DENY);

    setup("Update serialized type mismatch denied", 1);
    unsigned char otherType[0x100] = {0};
    put_ptr(updateCommand, 0x30, otherType);
    CHECK(run(1).decision == AUTHORITY_DECISION_DENY);

    setup("Unreadable bonus entry span denied before query", 0);
    uintptr_t badEntries = UINTPTR_MAX - 4;
    put(createCommand, activeBonusOffset + 8, &badEntries, sizeof(badEntries));
    int32_t one = 1;
    put(createCommand, activeBonusOffset + 0x10, &one, sizeof(one));
    put(createCommand, activeBonusOffset + 0x14, &one, sizeof(one));
    CHECK(run(0).decision == AUTHORITY_DECISION_DENY);
    CHECK(queryCalls == 0 && copyCalls == 0);

    setup("Invalid typed Create parent denied", 0);
    uintptr_t parentRef = 1;
    uint8_t hasParent = 1;
    put(createCommand, 0x34, &parentRef, sizeof(parentRef));
    put(createCommand, 0x3c, &hasParent, sizeof(hasParent));
    set_vtable(variant, 0x2951600);
    CHECK(run(0).decision == AUTHORITY_DECISION_DENY);
}

static void test_reference_preflight(void) {
    setup("Create valid typed MIO and readable bonuses pass preflight", 0);
    CHECK(AuthorityValidateEquipmentBonusReferences(image, createCommand).decision ==
        AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Update valid typed MIO and readable bonuses pass preflight", 1);
    CHECK(AuthorityValidateEquipmentBonusReferences(image, updateCommand).decision ==
        AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Create null MIO and readable bonuses pass preflight", 0);
    uint64_t zero = 0;
    put(createCommand, 0x15c, &zero, sizeof(zero));
    CHECK(AuthorityValidateEquipmentBonusReferences(image, createCommand).decision ==
        AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Update null MIO and readable bonuses pass preflight", 1);
    put(updateCommand, 0x14c, &zero, sizeof(zero));
    CHECK(AuthorityValidateEquipmentBonusReferences(image, updateCommand).decision ==
        AUTHORITY_DECISION_ALLOW);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Create wrong typed MIO denied in preflight", 0);
    uint64_t wrong = 3;
    put(createCommand, 0x15c, &wrong, sizeof(wrong));
    CHECK(AuthorityValidateEquipmentBonusReferences(image, createCommand).decision ==
        AUTHORITY_DECISION_DENY);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Update wrong typed MIO denied in preflight", 1);
    put(updateCommand, 0x14c, &wrong, sizeof(wrong));
    CHECK(AuthorityValidateEquipmentBonusReferences(image, updateCommand).decision ==
        AUTHORITY_DECISION_DENY);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);

    setup("Unreadable bonuses denied during reference preflight", 0);
    uintptr_t badEntries = UINTPTR_MAX - 4;
    put(createCommand, activeBonusOffset + 8, &badEntries, sizeof(badEntries));
    int32_t one = 1;
    put(createCommand, activeBonusOffset + 0x10, &one, sizeof(one));
    put(createCommand, activeBonusOffset + 0x14, &one, sizeof(one));
    CHECK(AuthorityValidateEquipmentBonusReferences(image, createCommand).decision ==
        AUTHORITY_DECISION_DENY);
    CHECK(queryCalls == 0 && copyCalls == 0 && destroyCalls == 0);
}

int main(void) {
    test_query_and_copy_for_create_update();
    test_inherited_exact_bonus_and_mio_paths();
    test_invalid_refs_and_type();
    test_reference_preflight();
    printf("Authority equipment bonus tests passed (%u assertions).\n", assertions);
    return 0;
}
