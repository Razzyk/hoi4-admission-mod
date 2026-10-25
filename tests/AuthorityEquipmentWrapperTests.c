/* Ordered equipment MIO canonicalization through the native IsValid wrapper.
 * All objects and caller thunks live in a private test image. */
#define AUTHORITY_EQUIPMENT_PAYLOAD_TEST
#define AUTHORITY_EQUIPMENT_BONUS_TEST
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main

#include "../native/authorization/equipment_payload.c"
#include "../native/authorization/equipment_bonus.c"

typedef struct TestBonusEntry {
    int32_t id;
    uint32_t padding;
    int64_t value;
} TestBonusEntry;

static unsigned bonusAssertions;
static int resolverCalls, resolverErrors, queryCalls, queryErrors;
static int copyCalls, copyErrors, destroyCalls, destroyErrors;
static int equipmentNativeCalls, equipmentNativeErrors;
static int reenterNativeLoggable, reentrantLogCalls, reentrantLogResult;
static unsigned char equipmentCaptureAnswer;
static unsigned char equipmentCaptureServer[0x60];
static void *expectedRefAddresses[4];
static size_t expectedRefAddressCount;
static void *expectedMio, *expectedType;
static int expectCanonicalInNative;
static int32_t expectedBonusId = 7;
static int64_t expectedBonusValue = 0x123456;
static uint32_t expectedBonusScalar = 188;
static int32_t queryBonusId = 7;
static int64_t queryBonusValue = 0x123456;
static uint32_t queryBonusScalar = 188;
static TestBonusEntry queryEntries[2];
static unsigned char fixtureWorld[0xb40];
static unsigned char fixtureMap[0x100];
static unsigned char fixtureHuman[0xa0];
static unsigned char fixtureCountries[8][0x500];
static unsigned char fixtureType[0x100];
static unsigned char fixtureDefinition[0x20];
static unsigned char fixtureMio[0x180];
static unsigned char createCommand[0x220];
static unsigned char updateCommand[0x220];
static unsigned char fixtureVariant[0x520];
static TestBonusEntry commandBonusEntries[2];
static TestBonusEntry variantBonusEntries[2];
static TestBonusEntry commandUpgradeEntries[2];
static TestBonusEntry variantUpgradeEntries[2];
static void *definitionVectorEntries[1];

#define E_CHECK(c) do { ++bonusAssertions; if (!(c)) { \
    fprintf(stderr, "FAIL equipment wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static void write_at(void *base, size_t offset, const void *value, size_t size) {
    memcpy((unsigned char *)base + offset, value, size);
}

static void set_bonus_list(void *object, void *entries, int32_t capacity, int32_t count) {
    uintptr_t pointer = (uintptr_t)entries;
    write_at(object, 8, &pointer, sizeof(pointer));
    write_at(object, 0x10, &capacity, sizeof(capacity));
    write_at(object, 0x14, &count, sizeof(count));
}

static void set_bonus_entry(TestBonusEntry *entries, int32_t id, int64_t value) {
    entries->id = id;
    entries->padding = 0;
    entries->value = value;
}

static void set_upgrade_list(void *list, void *entries, int32_t capacity, int32_t count) {
    uintptr_t pointer = (uintptr_t)entries;
    write_at(list, 8, &pointer, sizeof(pointer));
    write_at(list, 0x10, &capacity, sizeof(capacity));
    write_at(list, 0x14, &count, sizeof(count));
}

static void set_upgrade_entry(TestBonusEntry *entries, void *definition, uint8_t level) {
    uintptr_t pointer = (uintptr_t)definition;
    memcpy(entries, &pointer, sizeof(pointer));
    memcpy((unsigned char *)entries + 8, &level, sizeof(level));
}

static void *test_resolve_ref(void *reference) {
    uintptr_t value = 0;
    ++resolverCalls;
    int recognized = 0;
    for (size_t i = 0; i < expectedRefAddressCount; ++i)
        if (reference == expectedRefAddresses[i]) recognized = 1;
    if (!recognized) ++resolverErrors;
    if (!reference) { ++resolverErrors; return NULL; }
    memcpy(&value, reference, sizeof(value));
    return (void *)value;
}

static void *test_query_bonus(void *mio, void *output, void *type) {
    uintptr_t pointer = (uintptr_t)queryEntries;
    int32_t capacity = 2, count = 1;
    ++queryCalls;
    if (mio != expectedMio || type != expectedType || !output) ++queryErrors;
    set_bonus_entry(&queryEntries[0], queryBonusId, queryBonusValue);
    memcpy((unsigned char *)output + 8, &pointer, sizeof(pointer));
    memcpy((unsigned char *)output + 0x10, &capacity, sizeof(capacity));
    memcpy((unsigned char *)output + 0x14, &count, sizeof(count));
    return output;
}

static void test_copy_bonus(void *destination, void *source) {
    uintptr_t sourceEntries = 0, destinationEntries = 0;
    int32_t count = 0, capacity = 0, destinationCapacity = 0;
    ++copyCalls;
    if (!destination || !source) { ++copyErrors; return; }
    memcpy(&sourceEntries, (unsigned char *)source + 8, sizeof(sourceEntries));
    memcpy(&destinationEntries, (unsigned char *)destination + 8, sizeof(destinationEntries));
    memcpy(&count, (unsigned char *)source + 0x14, sizeof(count));
    memcpy(&capacity, (unsigned char *)source + 0x10, sizeof(capacity));
    memcpy(&destinationCapacity, (unsigned char *)destination + 0x10, sizeof(destinationCapacity));
    if (count < 0 || count > destinationCapacity || capacity < count ||
        (count && (!sourceEntries || !destinationEntries))) { ++copyErrors; return; }
    if (count) memcpy((void *)destinationEntries, (void *)sourceEntries,
        (size_t)count * sizeof(TestBonusEntry));
    memcpy((unsigned char *)destination + 0x14, &count, sizeof(count));
}

static void test_destroy_bonus(void *object, uint32_t flags) {
    ++destroyCalls;
    if (!object || flags != 0) ++destroyErrors;
}

static unsigned char __fastcall equipment_native_valid(void *command, void *motivation) {
    uintptr_t vtable = 0, entries = 0;
    uint32_t scalar = 0;
    int32_t count = 0, id = -1;
    int64_t value = 0;
    size_t bonusOffset = 0, scalarOffset = 0;
    ++equipmentNativeCalls;
    if (command != expected_command || motivation != expected_motivation) ++equipmentNativeErrors;
    if (!command) { ++equipmentNativeErrors; return 0; }
    memcpy(&vtable, command, sizeof(vtable));
    if (vtable == (uintptr_t)(imageBase + 0x2a240c0)) {
        bonusOffset = 0x168; scalarOffset = 0x188;
    } else if (vtable == (uintptr_t)(imageBase + 0x2a24188)) {
        bonusOffset = 0x158; scalarOffset = 0x178;
    } else { ++equipmentNativeErrors; return 0; }
    memcpy(&entries, (unsigned char *)command + bonusOffset + 8, sizeof(entries));
    memcpy(&count, (unsigned char *)command + bonusOffset + 0x14, sizeof(count));
    memcpy(&scalar, (unsigned char *)command + scalarOffset, sizeof(scalar));
    if (count != 1 || !entries) ++equipmentNativeErrors;
    if (count > 0 && entries) {
        memcpy(&id, (void *)entries, sizeof(id));
        memcpy(&value, (unsigned char *)entries + 8, sizeof(value));
    }
    if (expectCanonicalInNative &&
        (id != expectedBonusId || value != expectedBonusValue || scalar != expectedBonusScalar))
        ++equipmentNativeErrors;
    if (!expectCanonicalInNative && (id != 99 || value != 0x7777 || scalar != 999))
        ++equipmentNativeErrors;
    if (reenterNativeLoggable) {
        ++reentrantLogCalls;
        reentrantLogResult = invoke_log(0x225381d, (void **)command);
    }
    return (unsigned char)expected_native_answer;
}

static void setup_fixture(void) {
    memset(fixtureWorld, 0, sizeof(fixtureWorld));
    memset(fixtureMap, 0, sizeof(fixtureMap));
    memset(fixtureHuman, 0, sizeof(fixtureHuman));
    memset(fixtureCountries, 0, sizeof(fixtureCountries));
    memset(fixtureType, 0, sizeof(fixtureType));
    memset(fixtureDefinition, 0, sizeof(fixtureDefinition));
    memset(fixtureMio, 0, sizeof(fixtureMio));
    memset(createCommand, 0, sizeof(createCommand));
    memset(updateCommand, 0, sizeof(updateCommand));
    memset(fixtureVariant, 0, sizeof(fixtureVariant));
    memset(commandBonusEntries, 0, sizeof(commandBonusEntries));
    memset(variantBonusEntries, 0, sizeof(variantBonusEntries));
    memset(commandUpgradeEntries, 0, sizeof(commandUpgradeEntries));
    memset(variantUpgradeEntries, 0, sizeof(variantUpgradeEntries));
    memset(definitionVectorEntries, 0, sizeof(definitionVectorEntries));
    resolverCalls = resolverErrors = queryCalls = queryErrors = 0;
    copyCalls = copyErrors = destroyCalls = destroyErrors = 0;
    equipmentNativeCalls = equipmentNativeErrors = 0;
    reenterNativeLoggable = reentrantLogCalls = reentrantLogResult = 0;
    expectedRefAddressCount = 0;
    expectedMio = fixtureMio; expectedType = fixtureType;
    expectCanonicalInNative = 0;
    expectedBonusId = queryBonusId = 7;
    expectedBonusValue = queryBonusValue = 0x123456;
    expectedBonusScalar = queryBonusScalar = 188;

    uintptr_t mapPointer = (uintptr_t)fixtureMap;
    uintptr_t humanPointer = (uintptr_t)fixtureHuman;
    int32_t countryCount = 8, humanCount = 1, one = 1, definitionId = 5;
    write_at(fixtureWorld, 0x340, &mapPointer, sizeof(mapPointer));
    write_at(fixtureWorld, 0x34c, &countryCount, sizeof(countryCount));
    write_at(fixtureWorld, 0xf8, &humanPointer, sizeof(humanPointer));
    write_at(fixtureWorld, 0x104, &humanCount, sizeof(humanCount));
    set_private_pointer(0x332f260, fixtureWorld);
    fake_humans[0] = fixtureHuman; fake_human_count = 1;
    for (int i = 0; i < 8; ++i) fake_countries[i] = fixtureCountries[i];
    set_fixture_human(fixtureHuman, 1001, 1);

    memcpy(fixtureDefinition + 8, &definitionId, sizeof(definitionId));
    definitionVectorEntries[0] = fixtureDefinition;
    uintptr_t definitionsPointer = (uintptr_t)definitionVectorEntries;
    write_at(fixtureType, 0x58, &definitionsPointer, sizeof(definitionsPointer));
    write_at(fixtureType, 0x60, &one, sizeof(one));
    write_at(fixtureType, 0x64, &one, sizeof(one));
    uintptr_t mioVtable = (uintptr_t)(imageBase + 0x2967a28);
    memcpy(fixtureMio, &mioVtable, sizeof(mioVtable));
    write_at(fixtureMio, 0x148, &queryBonusScalar, sizeof(queryBonusScalar));
    AuthorityEquipmentPayloadTestSetResolvers(test_resolve_ref, NULL);
    AuthorityEquipmentBonusTestSetResolvers(test_resolve_ref, test_query_bonus,
        test_copy_bonus, test_destroy_bonus);
    classes[11].originalValid = equipment_native_valid;
    classes[11].originalLoggable = mock_native_loggable;
    classes[12].originalValid = equipment_native_valid;
    classes[12].originalLoggable = mock_native_loggable;
}

static void set_command_bonus(void *command, size_t bonusOffset, size_t scalarOffset,
    size_t mioOffset, TestBonusEntry *entries) {
    set_bonus_entry(entries, 99, 0x7777);
    set_bonus_list((unsigned char *)command + bonusOffset, entries, 2, 1);
    uint32_t scalar = 999;
    uintptr_t mioRef = (uintptr_t)fixtureMio;
    write_at(command, scalarOffset, &scalar, sizeof(scalar));
    write_at(command, mioOffset, &mioRef, sizeof(mioRef));
    expectedRefAddresses[expectedRefAddressCount++] = (unsigned char *)command + mioOffset;
}

static void *make_create_command(int32_t actor) {
    void *vtable = imageBase + 0x2a240c0;
    uint32_t sender = 1001;
    uint8_t noParent = 0;
    uintptr_t type = (uintptr_t)fixtureType;
    memcpy(createCommand, &vtable, sizeof(vtable));
    write_at(createCommand, 0x0c, &sender, sizeof(sender));
    write_at(createCommand, 0x28, &type, sizeof(type));
    write_at(createCommand, 0x30, &actor, sizeof(actor));
    write_at(createCommand, 0x3c, &noParent, sizeof(noParent));
    set_upgrade_list(createCommand + 0x60, NULL, 0, 0);
    set_command_bonus(createCommand, 0x168, 0x188, 0x15c, commandBonusEntries);
    return createCommand;
}

static void *make_update_command(void) {
    void *commandVtable = imageBase + 0x2a24188;
    void *variantVtable = imageBase + 0x2951608;
    uint32_t sender = 1001;
    int32_t actor = 1, capacity = 1, count = 1;
    uint8_t requested = 2;
    uintptr_t variantRef = (uintptr_t)fixtureVariant;
    uintptr_t type = (uintptr_t)fixtureType;
    memcpy(updateCommand, &commandVtable, sizeof(commandVtable));
    memcpy(fixtureVariant, &variantVtable, sizeof(variantVtable));
    write_at(updateCommand, 0x0c, &sender, sizeof(sender));
    write_at(updateCommand, 0x28, &variantRef, sizeof(variantRef));
    write_at(updateCommand, 0x30, &type, sizeof(type));
    write_at(fixtureVariant, 0x1c, &actor, sizeof(actor));
    write_at(fixtureVariant, 0x3f0, &type, sizeof(type));
    set_upgrade_entry(variantUpgradeEntries, fixtureDefinition, requested);
    set_upgrade_list(fixtureVariant + 0x68, variantUpgradeEntries, capacity, count);
    set_upgrade_entry(commandUpgradeEntries, fixtureDefinition, requested);
    set_upgrade_list(updateCommand + 0x58, commandUpgradeEntries, capacity, count);
    uint32_t inheritedScalar = 44;
    uintptr_t mioRef = (uintptr_t)fixtureMio;
    set_bonus_entry(&variantBonusEntries[0], 7, 0x44);
    set_bonus_list(fixtureVariant + 0x490, variantBonusEntries, 2, 1);
    write_at(fixtureVariant, 0x4b0, &inheritedScalar, sizeof(inheritedScalar));
    write_at(fixtureVariant, 0x488, &mioRef, sizeof(mioRef));
    expectedRefAddresses[expectedRefAddressCount++] = updateCommand + 0x28;
    expectedRefAddresses[expectedRefAddressCount++] = updateCommand + 0x14c;
    set_command_bonus(updateCommand, 0x158, 0x178, 0x14c, commandBonusEntries);
    return updateCommand;
}

static void prepare_mio_query(uint32_t scalar, int32_t bonusId, int64_t bonusValue) {
    queryBonusScalar = scalar; queryBonusId = bonusId; queryBonusValue = bonusValue;
    write_at(fixtureMio, 0x148, &scalar, sizeof(scalar));
}

static void prepare_equipment_reference_site(void) {
    void *page = VirtualAlloc(imageBase + 0x221f000, 0x1000,
        MEM_COMMIT, PAGE_READWRITE);
    if (!page) { fprintf(stderr, "equipment resolver fixture page commit failed\n"); ExitProcess(2); }
    emit_absolute_jump(imageBase + 0x221f310, test_resolve_ref);
    DWORD oldProtection = 0;
    if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &oldProtection)) {
        fprintf(stderr, "equipment resolver fixture page seal failed\n"); ExitProcess(2);
    }
    FlushInstructionCache(GetCurrentProcess(), page, 0x1000);
}

static void __fastcall equipment_capture_callback(void *server, const void *packet,
    uint32_t length, uintptr_t connection, int channel) {
    (void)server; (void)packet; (void)length; (void)connection; (void)channel;
    ValidThunk thunk = (ValidThunk)(imageBase + 0x236795c - 16);
    expected_command = capture_command; expected_motivation = capture_motivation;
    equipmentCaptureAnswer = thunk(capture_command, capture_motivation);
}

static void capture_equipment(void *command, void *motivation) {
    uintptr_t context = 0x778899;
    memcpy(equipmentCaptureServer + 0x48, &context, sizeof(context));
    capture_command = (void **)command; capture_motivation = motivation;
    expected_command = command; expected_motivation = motivation;
    equipmentCaptureAnswer = 0;
    AuthorityGuardReceive(equipment_capture_callback, equipmentCaptureServer,
        NULL, 0, 0x9911, 0);
}

static unsigned char invoke_equipment(uint32_t returnRva, void *command, void *motivation) {
    expected_command = command; expected_motivation = motivation;
    expectCanonicalInNative = 1;
    unsigned char result = invoke_valid(returnRva, (void **)command, motivation);
    expectCanonicalInNative = 0;
    return result;
}

static void check_hook_health(void) {
    E_CHECK(resolverErrors == 0);
    E_CHECK(queryErrors == 0);
    E_CHECK(copyErrors == 0);
    E_CHECK(destroyErrors == 0);
    E_CHECK(equipmentNativeErrors == 0);
}

int main(void) {
    setup_private_image();
    prepare_equipment_reference_site();
    static unsigned char motivationStorage[16];
    void *motivation = motivationStorage;

    case_name = "Create canonicalizes only at first ordered primary after controlled actor";
    reset_fixture(151); setup_fixture();
    void *command = make_create_command(1);
    AuthorityResult createPreflight = AuthorityValidateEquipmentPayload(imageBase, command, 1);
    if (createPreflight.decision != AUTHORITY_DECISION_ALLOW)
        fprintf(stderr, "Create test payload rejected: %d\n", (int)createPreflight.reason);
    capture_equipment(command, motivation);
    if (equipmentCaptureAnswer != 1) {
        AuthorityGuardStats stats;
        AuthorityGuardGetStats(&stats);
        fprintf(stderr, "capture=%u native=%d nativeErrors=%d expectedNative=%d refs=%d queries=%d callbacks=%llu scopes=%llu denies=%llu\\n",
            (unsigned)equipmentCaptureAnswer, equipmentNativeCalls, equipmentNativeErrors,
            expected_native_answer, resolverCalls, queryCalls,
            (unsigned long long)stats.receiveCallbacks, (unsigned long long)stats.receiveScopes,
            (unsigned long long)stats.policyDenies);
    }
    E_CHECK(equipmentCaptureAnswer == 1);
    E_CHECK(queryCalls == 0 && resolverCalls == 1);
    E_CHECK(equipmentNativeCalls == 1);
    E_CHECK(invoke_equipment(0x22530ef, command, motivation) == 1);
    E_CHECK(queryCalls == 1 && copyCalls == 1 && destroyCalls == 1 && resolverCalls == 3);
    E_CHECK(equipmentNativeCalls == 2);
    E_CHECK(invoke_equipment(0x2250dbd, command, motivation) == 1);
    E_CHECK(queryCalls == 1 && equipmentNativeCalls == 3);
    prepare_mio_query(777, 8, 0xabcdef);
    E_CHECK(invoke_equipment(0x22536df, command, motivation) == 1);
    E_CHECK(queryCalls == 1 && equipmentNativeCalls == 4);
    E_CHECK(resolverCalls == 4);
    check_hook_health();

    case_name = "Update fresh async primary resolves embedded references and canonicalizes baseline variant";
    reset_fixture(152); setup_fixture();
    command = make_update_command();
    capture_equipment(command, motivation);
    E_CHECK(queryCalls == 0 && resolverCalls >= 2);
    E_CHECK(invoke_equipment(0x2250dbd, command, motivation) == 1);
    E_CHECK(queryCalls == 1 && copyCalls == 1 && destroyCalls == 1);
    E_CHECK(equipmentNativeCalls == 2);
    E_CHECK(resolverCalls >= 4);
    check_hook_health();

    case_name = "foreign actor is denied before MIO query";
    reset_fixture(153); setup_fixture();
    command = make_create_command(3);
    capture_equipment(command, motivation);
    E_CHECK(queryCalls == 0);
    E_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 0);
    E_CHECK(queryCalls == 0 && equipmentNativeCalls == 1);
    E_CHECK(invoke_log(0x225381d, (void **)command) == 0);
    E_CHECK(fixture_history_count == 0);
    check_hook_health();

    case_name = "wrong typed MIO reference is refused at receive before native dereference";
    reset_fixture(157); setup_fixture();
    static unsigned char wrongMio[0x180];
    command = make_create_command(1);
    uintptr_t wrongMioRef = (uintptr_t)wrongMio;
    write_at(command, 0x15c, &wrongMioRef, sizeof(wrongMioRef));
    expected_capture_answer = 0;
    capture_equipment(command, motivation);
    CommandProvenanceSnapshot wrongMioSnapshot;
    E_CHECK(equipmentCaptureAnswer == 0 && equipmentNativeCalls == 0);
    E_CHECK(queryCalls == 0 && resolverErrors == 0);
    E_CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[11].vtableRva), &wrongMioSnapshot));
    check_hook_health();

    case_name = "native reentrant history check cannot observe pending canonicalization as allowed";
    reset_fixture(156); setup_fixture();
    command = make_create_command(1);
    capture_equipment(command, motivation);
    expected_native_answer = 0;
    reenterNativeLoggable = 1;
    CHECK(invoke_equipment(0x22530ef, command, motivation) == 0);
    reenterNativeLoggable = 0;
    E_CHECK(queryCalls == 1 && reentrantLogCalls == 1 && reentrantLogResult == 0);
    CHECK(invoke_log(0x225381d, (void **)command) == 0);
    E_CHECK(fixture_history_count == 0);
    check_hook_health();

    case_name = "unscoped local call and motivation-only retry preserve native bonus payload";
    reset_fixture(154); setup_fixture();
    command = make_create_command(1);
    expected_command = command; expected_motivation = motivation;
    CHECK(guarded_is_valid(command, motivation) == 1);
    E_CHECK(queryCalls == 0 && resolverCalls == 0);
    capture_equipment(command, motivation);
    E_CHECK(queryCalls == 0 && resolverCalls == 1);
    expected_command = command; expected_motivation = motivation;
    CHECK(invoke_valid(0x22536df, (void **)command, motivation) == 1);
    E_CHECK(queryCalls == 0 && resolverCalls == 1);
    check_hook_health();

    case_name = "cached native rejection is not queried again or serialized to history";
    reset_fixture(155); setup_fixture();
    command = make_create_command(1);
    capture_equipment(command, motivation);
    expected_native_answer = 0;
    CHECK(invoke_equipment(0x22530ef, command, motivation) == 0);
    E_CHECK(queryCalls == 1);
    expected_native_answer = 1;
    CHECK(invoke_equipment(0x2250dbd, command, motivation) == 0);
    E_CHECK(queryCalls == 1);
    E_CHECK(invoke_log(0x225381d, (void **)command) == 0);
    E_CHECK(fixture_history_count == 0);
    check_hook_health();

    printf("PASS %u equipment wrapper assertions\n", bonusAssertions);
    return 0;
}
