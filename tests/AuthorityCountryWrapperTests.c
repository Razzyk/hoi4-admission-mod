/* Focused host adapter fixtures for native script, coop and variant paths.
 * Reuses the private-image wrapper harness; no real game process is touched. */
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main

static int scriptGetterCalls, scriptSource, resolveCalls, resolveRefErrors, executeCalls;
static int levelPredicateCalls, levelPredicateErrors, levelPredicateAnswer;
static uint8_t expectedUpgradeLevel;
static void *scriptReturn, *resolvedVariant, *expectedReference;
static void *expectedDefinition, *expectedOwnerTag;
static int32_t localHumanId;
static unsigned diagnosticCalls;
static char diagnosticLine[128];

static void diagnostic_probe(const char *line) {
    ++diagnosticCalls;
    snprintf(diagnosticLine, sizeof(diagnosticLine), "%s", line);
}

static uint64_t __fastcall noisy_sender_resolver(void *context, uintptr_t connection) {
    (void)context; (void)connection;
    return 0xfedcba9800000000ull | fixture_sender_id;
}

static void *__fastcall fake_script_getter(void *effect, int32_t *outTag, void *scope) {
    (void)effect; (void)scope;
    ++scriptGetterCalls;
    *outTag = scriptSource;
    return scriptReturn;
}

static void *__fastcall fake_resolve_variant(void *reference) {
    ++resolveCalls;
    if (reference != expectedReference) ++resolveRefErrors;
    return resolvedVariant;
}

static __attribute__((used)) unsigned char __fastcall level_predicate_probe(void *definition, int32_t *ownerTag,
    uint8_t level, void *tooltip, uint32_t mode) {
    ++levelPredicateCalls;
    if (definition != expectedDefinition || ownerTag != expectedOwnerTag ||
        level != expectedUpgradeLevel || tooltip != NULL || mode != 0) ++levelPredicateErrors;
    return (unsigned char)levelPredicateAnswer;
}

static unsigned char __fastcall fake_level_predicate(void *definition, int32_t *ownerTag,
    uint8_t level, void *tooltip, uint32_t mode) __attribute__((naked));
static unsigned char __fastcall fake_level_predicate(void *definition, int32_t *ownerTag,
    uint8_t level, void *tooltip, uint32_t mode) {
    __asm__ volatile(
        "sub $0x38, %rsp\n\t"
        "mov 0x60(%rsp), %rax\n\t"
        "mov %rax, 0x20(%rsp)\n\t"
        "movabs $level_predicate_probe, %rax\n\t"
        "call *%rax\n\t"
        "add $0x38, %rsp\n\t"
        "movb %al, %r11b\n\t"
        "movabs $0x1122334455667700, %rax\n\t"
        "movb %r11b, %al\n\t"
        "ret\n\t");
}

static void *__fastcall fake_local_human(void *world) {
    (void)world;
    for (int i = 0; i < fake_human_count; ++i) {
        int32_t id = -1;
        memcpy(&id, (unsigned char *)fake_humans[i] + 0x98, sizeof(id));
        if (id == localHumanId) return fake_humans[i];
    }
    return NULL;
}

static void __fastcall no_op_execute(void *command) { (void)command; ++executeCalls; }
static void __fastcall mutate_country_execute(void *command) {
    int32_t affected = 0, destination = 0;
    ++executeCalls;
    memcpy(&destination, (unsigned char *)command + 0x28, sizeof(destination));
    memcpy(&affected, (unsigned char *)command + 0x30, sizeof(affected));
    for (int i = 0; i < fake_human_count; ++i) {
        int32_t id = -1;
        memcpy(&id, (unsigned char *)fake_humans[i] + 0x98, sizeof(id));
        if (id == affected) memcpy((unsigned char *)fake_humans[i] + 0x70,
            &destination, sizeof(destination));
    }
}
static unsigned char fixtureServer[0x60];
static uintptr_t fixtureContext = 0x887766;

static void prepare_extra_image_sites(void) {
    const uint32_t pages[] = {0x1db000, 0x1537000, 0x221f000, 0x34f000};
    for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i) {
        if (!VirtualAlloc(imageBase + pages[i], 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
            fprintf(stderr, "extra fixture page commit failed\n"); ExitProcess(2);
        }
    }
    emit_absolute_jump(imageBase + 0x221f310, fake_resolve_variant);
    emit_absolute_jump(imageBase + 0x1537970, fake_level_predicate);
    emit_absolute_jump(imageBase + 0x1db8e0, fake_local_human);
    (void)emit_caller_thunk(0x34f293, guarded_script_getter);
    DWORD oldProtection = 0;
    for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i)
        if (!VirtualProtect(imageBase + pages[i], 0x1000, PAGE_EXECUTE_READ, &oldProtection)) {
            fprintf(stderr, "extra fixture page seal failed\n"); ExitProcess(2);
        }
    FlushInstructionCache(GetCurrentProcess(), imageBase, imageSize);
}

static void prepare_world(void *world, void *map, void *records, int32_t count) {
    void *mapPointer = map;
    uintptr_t recordsPointer = (uintptr_t)records;
    int32_t countryCount = 8;
    memcpy((unsigned char *)world + 0x340, &mapPointer, sizeof(mapPointer));
    memcpy((unsigned char *)world + 0x34c, &countryCount, sizeof(countryCount));
    memcpy((unsigned char *)world + 0xf8, &recordsPointer, sizeof(recordsPointer));
    memcpy((unsigned char *)world + 0x104, &count, sizeof(count));
    set_private_pointer(0x332f260, world);
}

static void *new_class_command(uint32_t vtableRva, int32_t sender) {
    unsigned char *command = (unsigned char *)VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!command) return NULL;
    void *vtable = imageBase + vtableRva;
    memcpy(command, &vtable, sizeof(vtable));
    memcpy(command + 0x0c, &sender, sizeof(sender));
    return command;
}

static void set_upgrade_list(void *list, void *entries, uint32_t count, uint32_t capacity) {
    uintptr_t pointer = (uintptr_t)entries;
    memcpy((unsigned char *)list + 8, &pointer, sizeof(pointer));
    memcpy((unsigned char *)list + 0x10, &capacity, sizeof(capacity));
    memcpy((unsigned char *)list + 0x14, &count, sizeof(count));
}

static void set_upgrade_entry(void *entries, uint32_t index, void *definition, uint8_t level) {
    unsigned char *entry = (unsigned char *)entries + (size_t)index * 0x10;
    memcpy(entry, &definition, sizeof(definition));
    memcpy(entry + 8, &level, sizeof(level));
}

static unsigned char invoke_primary(void *command, void *motivation) {
    expected_command = command; expected_motivation = motivation;
    ValidThunk thunk = (ValidThunk)(imageBase + 0x22530ef - 16);
    return thunk(command, motivation);
}

static void invoke_capture(void *command, void *motivation, uintptr_t connection) {
    memcpy(fixtureServer + 0x48, &fixtureContext, sizeof(fixtureContext));
    capture_command = (void **)command; capture_motivation = motivation;
    AuthorityGuardReceive(capture_callback, fixtureServer, NULL, 0, connection, 0);
}

static unsigned assertions_country;
#define C_CHECK(c) do { ++assertions_country; if (!(c)) { \
    fprintf(stderr, "FAIL country wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

int main(void) {
    setup_private_image();
    prepare_extra_image_sites();
    static unsigned char world[0xb40], map[0x100], countries[8][0x500];
    static unsigned char humans[2][0xa0], variant[0x500];
    for (int i = 0; i < 8; ++i) fake_countries[i] = countries[i];
    void *variantVtable = imageBase + 0x2951608;
    memcpy(variant, &variantVtable, sizeof(variantVtable));
    prepare_world(world, map, humans, 1);
    fake_humans[0] = humans[0]; fake_humans[1] = humans[1];
    void *motivation = (void *)(uintptr_t)0xabc123;

    case_name = "script getter preserves native return, invokes once, and batches same-source grants";
    reset_fixture(71); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1);
    fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    uint32_t peerGen = 0;
    C_CHECK(peer_generation(1001, (uintptr_t)fixtureServer, 0x9913,
        fixtureContext, &peerGen, 1));
    originalScriptGetter = fake_script_getter; scriptGetterCalls = 0; scriptSource = 1;
    scriptReturn = (void *)(uintptr_t)0x123456789abcdef0ull;
    unsigned char scope[0x20] = {0};
    int32_t target = 3; memcpy(scope + 8, &target, sizeof(target));
    int32_t outTag = -1;
    ScriptGetterFn getterThunk = (ScriptGetterFn)(imageBase + 0x34f293 - 16);
    C_CHECK(getterThunk((void *)(uintptr_t)0x111, &outTag, scope) == scriptReturn);
    C_CHECK(outTag == 1 && scriptGetterCalls == 1 && policy.highestGrantId == 1);
    AuthorityGrantSlot firstGrant = {0};
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i)
        if (policy.grants[i].occupied && policy.grants[i].grant.destinationCountry == 3)
            firstGrant = policy.grants[i];
    C_CHECK(firstGrant.occupied && firstGrant.grant.kind == AUTHORITY_GRANT_SCRIPT &&
        firstGrant.grant.peer.machineId == 1001 && firstGrant.grant.peer.generation == peerGen &&
        firstGrant.grant.sourceCountry == 1 && firstGrant.grant.allowOccupiedDestination == 1);
    target = 4; memcpy(scope + 8, &target, sizeof(target));
    C_CHECK(getterThunk((void *)(uintptr_t)0x222, &outTag, scope) == scriptReturn);
    C_CHECK(outTag == 1 && scriptGetterCalls == 2 && policy.highestGrantId == 2);
    classes[14].originalValid = mock_native_valid;
    classes[14].originalExecute = mutate_country_execute;
    for (int32_t move = 0; move < 2; ++move) {
        void *scriptCommand = new_class_command(classes[14].vtableRva, 1001);
        C_CHECK(scriptCommand != NULL);
        int32_t source = move == 0 ? 0 : 1, affected = 1001;
        int32_t destination = move == 0 ? 3 : 4;
        memcpy((unsigned char *)scriptCommand + 0x28, &destination, sizeof(destination));
        memcpy((unsigned char *)scriptCommand + 0x2c, &source, sizeof(source));
        memcpy((unsigned char *)scriptCommand + 0x30, &affected, sizeof(affected));
        invoke_capture(scriptCommand, motivation, 0x9913);
        C_CHECK(invoke_primary(scriptCommand, motivation) == 1);
        guarded_execute(scriptCommand);
        int32_t assigned = -1;
        memcpy(&assigned, humans[0] + 0x70, sizeof(assigned));
        C_CHECK(assigned == destination);
    }
    C_CHECK(scriptGetterCalls == 2 && executeCalls == 2);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i)
        C_CHECK(!policy.grants[i].occupied || policy.grants[i].grant.peer.machineId != 1001);

    case_name = "native country wrapper locks an active-game self-switch but retains observer country selection";
    reset_fixture(711); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    classes[14].originalValid = mock_native_valid;
    { unsigned char started = 1; memcpy(world + 0xa39, &started, sizeof(started)); }
    void *countryChange = new_class_command(classes[14].vtableRva, 1001); C_CHECK(countryChange != NULL);
    int32_t lockSource = 1, lockAffected = 1001, lockDestination = 3;
    memcpy((unsigned char *)countryChange + 0x28, &lockDestination, sizeof(lockDestination));
    memcpy((unsigned char *)countryChange + 0x2c, &lockSource, sizeof(lockSource));
    memcpy((unsigned char *)countryChange + 0x30, &lockAffected, sizeof(lockAffected));
    invoke_capture(countryChange, motivation, 0x9913);
    C_CHECK(invoke_primary(countryChange, motivation) == 0);
    C_CHECK(fake_country_lookup_calls == 1 && fake_observer_predicate_calls == 1);
    set_fixture_human(humans[0], 1001, 0);
    void *observerSelection = new_class_command(classes[14].vtableRva, 1001); C_CHECK(observerSelection != NULL);
    memcpy((unsigned char *)observerSelection + 0x28, &lockDestination, sizeof(lockDestination));
    memcpy((unsigned char *)observerSelection + 0x2c, &lockSource, sizeof(lockSource));
    memcpy((unsigned char *)observerSelection + 0x30, &lockAffected, sizeof(lockAffected));
    invoke_capture(observerSelection, motivation, 0x9913);
    C_CHECK(invoke_primary(observerSelection, motivation) == 1);

    case_name = "observer transition uses the native country predicate and unknown source is denied";
    reset_fixture(712); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    classes[14].originalValid = mock_native_valid;
    { unsigned char started = 1; memcpy(world + 0xa39, &started, sizeof(started)); }
    countryChange = new_class_command(classes[14].vtableRva, 1001); C_CHECK(countryChange != NULL);
    lockSource = 1; lockDestination = 0;
    memcpy((unsigned char *)countryChange + 0x28, &lockDestination, sizeof(lockDestination));
    memcpy((unsigned char *)countryChange + 0x2c, &lockSource, sizeof(lockSource));
    memcpy((unsigned char *)countryChange + 0x30, &lockAffected, sizeof(lockAffected));
    { int32_t living = 2; memcpy((unsigned char *)fake_countries[1] + 0x41c, &living, sizeof(living)); }
    invoke_capture(countryChange, motivation, 0x9913);
    C_CHECK(invoke_primary(countryChange, motivation) == 0);
    { int32_t eligible = 0; memcpy((unsigned char *)fake_countries[1] + 0x41c, &eligible, sizeof(eligible)); }
    countryChange = new_class_command(classes[14].vtableRva, 1001); C_CHECK(countryChange != NULL);
    memcpy((unsigned char *)countryChange + 0x28, &lockDestination, sizeof(lockDestination));
    memcpy((unsigned char *)countryChange + 0x2c, &lockSource, sizeof(lockSource));
    memcpy((unsigned char *)countryChange + 0x30, &lockAffected, sizeof(lockAffected));
    invoke_capture(countryChange, motivation, 0x9913);
    C_CHECK(invoke_primary(countryChange, motivation) == 1);
    fake_country_lookup_missing = 1;
    countryChange = new_class_command(classes[14].vtableRva, 1001); C_CHECK(countryChange != NULL);
    memcpy((unsigned char *)countryChange + 0x28, &lockDestination, sizeof(lockDestination));
    memcpy((unsigned char *)countryChange + 0x2c, &lockSource, sizeof(lockSource));
    memcpy((unsigned char *)countryChange + 0x30, &lockAffected, sizeof(lockAffected));
    invoke_capture(countryChange, motivation, 0x9913);
    C_CHECK(invoke_primary(countryChange, motivation) == 0);
    C_CHECK(fake_country_lookup_calls == 3 && fake_observer_predicate_calls == 2);

    case_name = "UpdateEquipmentVariant resolves embedded native ref exactly once before actor authorization";
    reset_fixture(72); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    classes[12].originalValid = mock_native_valid;
    void *update = new_class_command(classes[12].vtableRva, 1001); C_CHECK(update != NULL);
    uint32_t refWord0 = 0x1268, refWord1 = 7;
    void *equipmentType = (void *)(uintptr_t)0x7000;
    memcpy((unsigned char *)update + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)update + 0x2c, &refWord1, sizeof(refWord1));
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));
    memcpy(variant + 0x3f0, &equipmentType, sizeof(equipmentType));
    set_upgrade_list(variant + 0x68, NULL, 0, 0);
    set_upgrade_list((unsigned char *)update + 0x58, NULL, 0, 0);
    expectedReference = (unsigned char *)update + 0x28;
    resolvedVariant = variant; int32_t variantActor = 1;
    memcpy(variant + 0x1c, &variantActor, sizeof(variantActor));
    resolveCalls = resolveRefErrors = 0; expected_native_answer = 1;
    invoke_capture(update, motivation, 0x9912);
    C_CHECK(valid_arg_errors == 0 && CommandProvenanceFindAny(&provenance, update,
        (void *)(imageBase + classes[12].vtableRva), &(CommandProvenanceSnapshot){0}));
    C_CHECK(invoke_primary(update, motivation) == 1 && resolveCalls == 3 && resolveRefErrors == 0);
    void *badUpdate = new_class_command(classes[12].vtableRva, 1001); C_CHECK(badUpdate != NULL);
    memcpy((unsigned char *)badUpdate + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)badUpdate + 0x2c, &refWord1, sizeof(refWord1));
    int32_t foreignActor = 3; memcpy(variant + 0x1c, &foreignActor, sizeof(foreignActor));
    expectedReference = (unsigned char *)badUpdate + 0x28;
    expected_capture_answer = 1;
    resolveCalls = resolveRefErrors = 0;
    invoke_capture(badUpdate, motivation, 0x9912);
    int badUpdateAnswer = invoke_primary(badUpdate, motivation);
    C_CHECK(badUpdateAnswer == 0 && resolveCalls == 3 && resolveRefErrors == 0);

    case_name = "same-type upgrade checks changed known levels and preserves unchanged inherited levels";
    reset_fixture(721); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    classes[12].originalValid = mock_native_valid;
    update = new_class_command(classes[12].vtableRva, 1001); C_CHECK(update != NULL);
    memcpy(variant, &variantVtable, sizeof(variantVtable));
    memcpy(variant + 0x1c, &(int32_t){1}, sizeof(int32_t));
    memcpy(variant + 0x3f0, &equipmentType, sizeof(equipmentType));
    refWord0 = 0x1268; refWord1 = 7;
    memcpy((unsigned char *)update + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)update + 0x2c, &refWord1, sizeof(refWord1));
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));
    expectedReference = (unsigned char *)update + 0x28; resolvedVariant = variant;
    static unsigned char definitionA[0x20], definitionB[0x20], payloadEntries[2][0x10], liveEntries[2][0x10];
    memcpy(definitionA + 8, &(int32_t){100}, sizeof(int32_t));
    memcpy(definitionB + 8, &(int32_t){200}, sizeof(int32_t));
    set_upgrade_entry(liveEntries, 0, definitionA, 255);
    set_upgrade_entry(liveEntries, 1, definitionB, 1);
    set_upgrade_entry(payloadEntries, 0, definitionA, 255);
    set_upgrade_entry(payloadEntries, 1, definitionB, 2);
    set_upgrade_list(variant + 0x68, liveEntries, 2, 2);
    set_upgrade_list((unsigned char *)update + 0x58, payloadEntries, 2, 2);
    expectedDefinition = definitionB; expectedOwnerTag = variant + 0x1c;
    expectedUpgradeLevel = 2; levelPredicateAnswer = 1;
    resolveCalls = resolveRefErrors = levelPredicateCalls = levelPredicateErrors = 0;
    invoke_capture(update, motivation, 0x9914);
    C_CHECK(invoke_primary(update, motivation) == 1);
    C_CHECK(resolveCalls == 3 && resolveRefErrors == 0 && levelPredicateCalls == 1 && levelPredicateErrors == 0);

    case_name = "changed downgrade and unsigned 255 levels use native AL";
    reset_fixture(722); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    update = new_class_command(classes[12].vtableRva, 1001); C_CHECK(update != NULL);
    memcpy((unsigned char *)update + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)update + 0x2c, &refWord1, sizeof(refWord1));
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));
    set_upgrade_entry(liveEntries, 0, definitionA, 5);
    set_upgrade_entry(liveEntries, 1, definitionB, 4);
    set_upgrade_entry(payloadEntries, 0, definitionA, 5);
    set_upgrade_entry(payloadEntries, 1, definitionB, 3);
    set_upgrade_list(variant + 0x68, liveEntries, 2, 2);
    set_upgrade_list((unsigned char *)update + 0x58, payloadEntries, 2, 2);
    expectedDefinition = definitionB; expectedOwnerTag = variant + 0x1c;
    expectedUpgradeLevel = 3; levelPredicateAnswer = 1;
    resolveCalls = levelPredicateCalls = levelPredicateErrors = 0;
    invoke_capture(update, motivation, 0x9915);
    C_CHECK(invoke_primary(update, motivation) == 1 && levelPredicateCalls == 1 && levelPredicateErrors == 0);
    set_upgrade_entry(payloadEntries, 1, definitionB, 255);
    expectedUpgradeLevel = 255; levelPredicateAnswer = 0;
    void *overflowLevel = new_class_command(classes[12].vtableRva, 1001); C_CHECK(overflowLevel != NULL);
    memcpy((unsigned char *)overflowLevel + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)overflowLevel + 0x2c, &refWord1, sizeof(refWord1));
    memcpy((unsigned char *)overflowLevel + 0x30, &equipmentType, sizeof(equipmentType));
    set_upgrade_list((unsigned char *)overflowLevel + 0x58, payloadEntries, 2, 2);
    expectedReference = (unsigned char *)overflowLevel + 0x28;
    invoke_capture(overflowLevel, motivation, 0x9915);
    C_CHECK(invoke_primary(overflowLevel, motivation) == 0 && levelPredicateCalls == 2 && levelPredicateErrors == 0);

    case_name = "unknown key cannot bypass a rejected known change; type change stays native-only";
    reset_fixture(723); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    static unsigned char unknownDefinition[0x20], mixedPayload[2][0x10];
    memcpy(unknownDefinition + 8, &(int32_t){150}, sizeof(int32_t));
    set_upgrade_entry(mixedPayload, 0, unknownDefinition, 1);
    set_upgrade_entry(mixedPayload, 1, definitionB, 255);
    update = new_class_command(classes[12].vtableRva, 1001); C_CHECK(update != NULL);
    memcpy((unsigned char *)update + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)update + 0x2c, &refWord1, sizeof(refWord1));
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 2, 2);
    expectedReference = (unsigned char *)update + 0x28;
    expectedUpgradeLevel = 255; levelPredicateAnswer = 0;
    resolveCalls = levelPredicateCalls = levelPredicateErrors = 0;
    invoke_capture(update, motivation, 0x9916);
    C_CHECK(invoke_primary(update, motivation) == 0 && levelPredicateCalls == 1 && levelPredicateErrors == 0);
    void *typeChanged = new_class_command(classes[12].vtableRva, 1001); C_CHECK(typeChanged != NULL);
    memcpy((unsigned char *)typeChanged + 0x28, &refWord0, sizeof(refWord0));
    memcpy((unsigned char *)typeChanged + 0x2c, &refWord1, sizeof(refWord1));
    void *otherType = (void *)(uintptr_t)0x8000;
    memcpy((unsigned char *)typeChanged + 0x30, &otherType, sizeof(otherType));
    expectedReference = (unsigned char *)typeChanged + 0x28;
    levelPredicateAnswer = 0;
    invoke_capture(typeChanged, motivation, 0x9916);
    int previousCalls = levelPredicateCalls;
    C_CHECK(invoke_primary(typeChanged, motivation) == 1 && levelPredicateCalls == previousCalls);

    case_name = "malformed upgrade arrays cannot reach the native level predicate";
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));
    int callsBeforeMalformed = levelPredicateCalls;
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, UINT32_MAX, UINT32_MAX);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 0, UINT32_MAX);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 2, 1);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_list((unsigned char *)update + 0x58, NULL, 1, 1);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_list((unsigned char *)update + 0x58, (void *)(UINTPTR_MAX - 8), 1, 1);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_entry(mixedPayload, 0, (void *)(UINTPTR_MAX - 4), 1);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 1, 1);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    C_CHECK(levelPredicateCalls == callsBeforeMalformed);

    case_name = "a full equipment-type pointer distinguishes identical low halves";
    void *sameLowHalfType = (void *)(uintptr_t)0x100007000ull;
    memcpy((unsigned char *)update + 0x30, &sameLowHalfType, sizeof(sameLowHalfType));
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, UINT32_MAX, UINT32_MAX);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_ALLOW);
    C_CHECK(levelPredicateCalls == callsBeforeMalformed);
    memcpy((unsigned char *)update + 0x30, &equipmentType, sizeof(equipmentType));

    case_name = "duplicate and descending serialized upgrade keys are refused";
    levelPredicateAnswer = 1;
    set_upgrade_entry(mixedPayload, 0, definitionA, 5);
    set_upgrade_entry(mixedPayload, 1, definitionA, 5);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 2, 2);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    set_upgrade_entry(mixedPayload, 0, definitionB, 4);
    set_upgrade_entry(mixedPayload, 1, definitionA, 5);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);

    case_name = "a different payload pointer with a known ID still uses the trusted level rule";
    static unsigned char aliasDefinition[0x20];
    memcpy(aliasDefinition + 8, &(int32_t){200}, sizeof(int32_t));
    set_upgrade_entry(mixedPayload, 0, aliasDefinition, 3);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 1, 1);
    expectedDefinition = definitionB; expectedOwnerTag = variant + 0x1c;
    expectedUpgradeLevel = 3; levelPredicateAnswer = 0;
    levelPredicateCalls = levelPredicateErrors = 0;
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_DENY);
    C_CHECK(levelPredicateCalls == 1 && levelPredicateErrors == 0);
    levelPredicateAnswer = 1;
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_ALLOW);
    C_CHECK(levelPredicateCalls == 2 && levelPredicateErrors == 0);

    case_name = "an ordinary new key does not suppress an allowed known change";
    set_upgrade_entry(mixedPayload, 0, unknownDefinition, 1);
    set_upgrade_entry(mixedPayload, 1, definitionB, 3);
    set_upgrade_list((unsigned char *)update + 0x58, mixedPayload, 2, 2);
    C_CHECK(validate_update_equipment_levels(update, variant).decision == AUTHORITY_DECISION_ALLOW);
    C_CHECK(levelPredicateCalls == 3 && levelPredicateErrors == 0);

    case_name = "a foreign native object reference is refused before the game casts it";
    reset_fixture(724); set_fixture_human(humans[0], 1001, 1); fake_human_count = 1;
    prepare_world(world, map, humans, 1); fixture_sender_id = 1001; senderResolver = noisy_sender_resolver;
    void *foreignVtable = imageBase + classes[0].vtableRva;
    memcpy(variant, &foreignVtable, sizeof(foreignVtable));
    expectedReference = (unsigned char *)update + 0x28; expected_capture_answer = 0;
    invoke_capture(update, motivation, 0x9917);
    C_CHECK(valid_calls == 0);
    C_CHECK(!CommandProvenanceFindAny(&provenance, update,
        imageBase + classes[12].vtableRva, &(CommandProvenanceSnapshot){0}));
    memcpy(variant, &variantVtable, sizeof(variantVtable));

    case_name = "host-local coop request authorizes the current remote leader's first approval";
    reset_fixture(73); set_fixture_human(humans[0], 1001, 1); set_fixture_human(humans[1], 500, 4);
    { uint32_t leaderFlags = 1; memcpy(humans[1] + 0x94, &leaderFlags, sizeof(leaderFlags)); }
    fake_human_count = 2; localHumanId = 1001; prepare_world(world, map, humans, 2);
    classes[15].originalExecute = no_op_execute;
    classes[14].originalExecute = no_op_execute;
    classes[14].originalValid = mock_native_valid;
    void *ask = new_class_command(classes[15].vtableRva, 0); C_CHECK(ask != NULL);
    int32_t requester = 1001, destination = 4;
    memcpy((unsigned char *)ask + 0x2c, &requester, sizeof(requester));
    memcpy((unsigned char *)ask + 0x28, &destination, sizeof(destination));
    executeCalls = 0; guarded_execute(ask);
    C_CHECK(executeCalls == 1 && policy.highestGrantId > 0);
    AuthorityGrantSlot *coopGrant = NULL;
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i)
        if (policy.grants[i].occupied && policy.grants[i].grant.kind == AUTHORITY_GRANT_COOP)
            coopGrant = &policy.grants[i];
    C_CHECK(coopGrant && coopGrant->grant.peer.machineId == 1001 &&
        coopGrant->grant.peer.generation == AUTH_HOST_LOCAL_GENERATION &&
        coopGrant->grant.sourceCountry == 1 && coopGrant->grant.destinationCountry == 4);
    fixture_sender_id = 500; senderResolver = noisy_sender_resolver;
    uint32_t leaderGeneration = 0;
    C_CHECK(peer_generation(500, 0x50, 0x60, 0x70, &leaderGeneration, 1));
    void *approval = new_class_command(classes[14].vtableRva, 500); C_CHECK(approval != NULL);
    int32_t affected = 1001, oldSerializedSource = 0;
    memcpy((unsigned char *)approval + 0x28, &destination, sizeof(destination));
    memcpy((unsigned char *)approval + 0x2c, &oldSerializedSource, sizeof(oldSerializedSource));
    memcpy((unsigned char *)approval + 0x30, &affected, sizeof(affected));
    invoke_capture(approval, motivation, 0x60);
    C_CHECK(invoke_primary(approval, motivation) == 1);
    C_CHECK(coopGrant && !coopGrant->occupied);

    case_name = "missing pre-execution assignment cannot retain a script permission";
    AuthorityGrant uncertainGrant; memset(&uncertainGrant, 0, sizeof(uncertainGrant));
    uncertainGrant.grantId = (uint64_t)InterlockedIncrement64(&nextGrantId);
    uncertainGrant.sessionEpoch = current_epoch();
    uncertainGrant.peer.machineId = 1001;
    uncertainGrant.peer.generation = AUTH_HOST_LOCAL_GENERATION;
    uncertainGrant.sourceCountry = 1; uncertainGrant.destinationCountry = 3;
    uncertainGrant.kind = AUTHORITY_GRANT_SCRIPT; uncertainGrant.allowOccupiedDestination = 1;
    C_CHECK(AuthorityPolicyGrantTrusted(&policy, &uncertainGrant, GetTickCount64(),
        current_epoch()) == AUTHORITY_REASON_NONE);
    CommandProvenanceSnapshot uncertainSnapshot; memset(&uncertainSnapshot, 0, sizeof(uncertainSnapshot));
    uncertainSnapshot.authenticatedMachineId = 1001;
    uncertainSnapshot.authenticatedPeerGeneration = AUTH_HOST_LOCAL_GENERATION;
    uncertainSnapshot.cachedGrantKind = AUTHORITY_GRANT_SCRIPT;
    revoke_changed_assignment(&classes[14], approval, 0, -1, &uncertainSnapshot);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i)
        C_CHECK(!policy.grants[i].occupied || policy.grants[i].grant.peer.machineId != 1001);

    case_name = "unreadable post-execution world revokes pending permissions";
    uncertainGrant.grantId = (uint64_t)InterlockedIncrement64(&nextGrantId);
    C_CHECK(AuthorityPolicyGrantTrusted(&policy, &uncertainGrant, GetTickCount64(),
        current_epoch()) == AUTHORITY_REASON_NONE);
    set_private_pointer(0x332f260, NULL);
    revoke_changed_assignment(&classes[14], approval, 1, 1, &uncertainSnapshot);
    set_private_pointer(0x332f260, world);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i)
        C_CHECK(!policy.grants[i].occupied || policy.grants[i].grant.peer.machineId != 1001);

    case_name = "every rejection reason is bounded and drained by worker diagnostics";
    memset((void *)rejectionReasons, 0, sizeof(rejectionReasons));
    diagnosticCalls = 0; logCallback = diagnostic_probe;
    for (int reason = AUTHORITY_REASON_NATIVE_INVALID; reason <= AUTHORITY_REASON_IDEA_MUTATION_INVALID; ++reason)
        count_reason((AuthorityReason)reason);
    AuthorityGuardFlushDiagnostics();
    C_CHECK(diagnosticCalls == AUTHORITY_REASON_IDEA_MUTATION_INVALID);
    C_CHECK(strcmp(diagnosticLine, "AUTHORIZATION_REJECTED reason=idea_mutation_invalid count=1") == 0);
    AuthorityGuardFlushDiagnostics();
    C_CHECK(diagnosticCalls == AUTHORITY_REASON_IDEA_MUTATION_INVALID);
    logCallback = NULL;

    printf("PASS %u native country wrapper assertions\n", assertions_country);
    return 0;
}
