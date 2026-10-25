/* Isolated fixtures for the pinned factory payload validator. */
#define AUTHORITY_FACTORY_PAYLOAD_TEST
#include "../native/authorization/factory_payload.c"

static unsigned assertions;
static unsigned maxGetterCalls;
static const char *caseName;
static unsigned char image[0x2a00000];
static unsigned char world[0x360];
static unsigned char command[0x80];
static unsigned char line[3][0x100];
static unsigned char status[3][0x298];
static unsigned char countryObject[3][0x10];
static unsigned char roster[0xa0];
static uintptr_t tagMapToken;
static uintptr_t refs[8];
static int32_t deltas[8];

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

static void *__fastcall resolve_ref(void *reference) {
    uintptr_t token = 0;
    if (!factory_read(reference, &token, sizeof(token))) return NULL;
    if (token >= 1 && token <= 3) return line[token - 1];
    return NULL;
}

static unsigned char __fastcall countries_equal(const int32_t *left, int32_t right) {
    return (unsigned char)(left && (*left == right ||
        ((*left == 1 || *left == 2) && (right == 1 || right == 2))));
}

static int32_t __fastcall max_factories(void *object) {
    int32_t value = -1;
    ++maxGetterCalls;
    memcpy(&value, (unsigned char *)object + 0xec, sizeof(value));
    return value;
}

static void set_line_type(unsigned index, uint32_t vtableRva, uint32_t getterRva) {
    uintptr_t vtable = (uintptr_t)(image + vtableRva);
    uintptr_t getter = (uintptr_t)(image + getterRva);
    put(line[index], 0, &vtable, sizeof(vtable));
    put(image + vtableRva, 0x58, &getter, sizeof(getter));
}

static void begin(const char *name, uint32_t commandRva) {
    uintptr_t pointer;
    int32_t value;
    caseName = name;
    maxGetterCalls = 0;
    memset(world, 0, sizeof(world));
    memset(command, 0, sizeof(command));
    memset(line, 0, sizeof(line));
    memset(status, 0, sizeof(status));
    memset(countryObject, 0, sizeof(countryObject));
    memset(roster, 0, sizeof(roster));
    memset(refs, 0, sizeof(refs));
    memset(deltas, 0, sizeof(deltas));
    tagMapToken = 1;
    put_ptr(world, 0x340, &tagMapToken);
    value = 8; put(world, 0x34c, &value, sizeof(value));
    put_ptr(world, 0xf8, roster);
    value = 1; put(world, 0x104, &value, sizeof(value));
    value = 1001; put(roster, 0x98, &value, sizeof(value));
    value = 1; put(roster, 0x70, &value, sizeof(value));
    value = 1; put(roster, 0x94, &value, sizeof(value));
    pointer = (uintptr_t)(image + commandRva); put(command, 0, &pointer, sizeof(pointer));
    /* There is no actor field in these commands. This adjacent field is
       deliberately poison to catch accidental reliance on +0x20. */
    value = INT32_MIN; put(command, 0x20, &value, sizeof(value));
    for (int i = 0; i < 3; ++i) {
        pointer = (uintptr_t)line[i] + 0x1000;
        put_ptr(line[i], 0x20, status[i]);
        put_ptr(status[i], 0x290, countryObject[i]);
        value = 1; put(countryObject[i], 8, &value, sizeof(value));
        value = 5; put(line[i], 0xe8, &value, sizeof(value));
        value = 10; put(line[i], 0xec, &value, sizeof(value));
        /* The production getter pointer is still structurally readable; the
           test getter callback supplies its result without executing it. */
        set_line_type((unsigned)i, 0x297bc80, 0xf6eb40);
        refs[i] = (uintptr_t)i + 1;
    }
    AuthorityFactoryPayloadTestSetResolvers(resolve_ref, countries_equal, max_factories);
}

static AuthorityResult run(uint32_t commandRva, int safetyOnly) {
    return AuthorityValidateFactoryPayload(image, world, command, 1001,
        commandRva, safetyOnly);
}

static void test_single_negative_delta(void) {
    begin("single valid negative delta", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    int32_t delta = -5; put(command, 0x30, &delta, sizeof(delta));
    AuthorityResult result = run(0x2994db0, 0);
    CHECK(result.decision == AUTHORITY_DECISION_ALLOW);
    CHECK(result.reason == AUTHORITY_REASON_NONE);
}

static void test_single_out_of_range_and_unknown_type(void) {
    int32_t delta;
    begin("single underflow rejected", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    delta = -6; put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2994db0, 0).decision == AUTHORITY_DECISION_DENY);

    begin("unknown production line type rejected in preflight", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    delta = 1; put(command, 0x30, &delta, sizeof(delta));
    uintptr_t rocket = (uintptr_t)(image + 0x297c260);
    put(line[0], 0, &rocket, sizeof(rocket));
    CHECK(run(0x2994db0, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);

    begin("getter pointer tampering rejected in preflight", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    delta = 1; put(command, 0x30, &delta, sizeof(delta));
    uintptr_t wrongGetter = (uintptr_t)(image + 0xf6f430);
    put(image + 0x297bc80, 0x58, &wrongGetter, sizeof(wrongGetter));
    CHECK(run(0x2994db0, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);
    CHECK(maxGetterCalls == 0);
}

static void test_owner_and_command_type(void) {
    int32_t delta = 1;
    begin("foreign line denied", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    put(command, 0x30, &delta, sizeof(delta));
    int32_t foreign = 3; put(countryObject[0], 8, &foreign, sizeof(foreign));
    CHECK(run(0x2994db0, 0).reason == AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    begin("wrong command vtable rejected", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2993a28, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);
}

static void test_mass_vectors_and_duplicate_lines(void) {
    begin("mass duplicate line valid sequence", 0x2993a28);
    refs[0] = 1; refs[1] = 1; deltas[0] = 4; deltas[1] = -3;
    put_ptr(command, 0x28, refs); int32_t n = 2;
    put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas);
    put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 0).decision == AUTHORITY_DECISION_ALLOW);

    begin("mass duplicate line prefix overflow rejected", 0x2993a28);
    refs[0] = 1; refs[1] = 1; deltas[0] = 4; deltas[1] = 4;
    put_ptr(command, 0x28, refs); n = 2;
    put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas);
    put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 0).decision == AUTHORITY_DECISION_DENY);

    begin("mass valid sequence may cross original-bound intermediate", 0x2993a28);
    refs[0] = 1; refs[1] = 1; deltas[0] = -5; deltas[1] = 10;
    put_ptr(command, 0x28, refs); n = 2;
    put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas);
    put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 0).decision == AUTHORITY_DECISION_ALLOW);
}

static void test_malformed_mass_vectors(void) {
    begin("negative mass count rejected", 0x2993a28);
    put_ptr(command, 0x28, refs); int32_t n = -1;
    put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas); put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);

    begin("unequal mass counts rejected", 0x2993a28);
    n = 1; int32_t other = 2;
    put_ptr(command, 0x28, refs); put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas); put(command, 0x48, &other, sizeof(other)); put(command, 0x4c, &other, sizeof(other));
    CHECK(run(0x2993a28, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);

    begin("mass capacity below count rejected", 0x2993a28);
    n = 1; int32_t zero = 0;
    put_ptr(command, 0x28, refs); put(command, 0x30, &zero, sizeof(zero)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas); put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 1).reason == AUTHORITY_REASON_FACTORY_PAYLOAD_INVALID);
}

static void test_unreadable_and_pointer_overflow(void) {
    begin("unreadable ref rejected", 0x2994db0);
    uintptr_t invalid = UINTPTR_MAX - 3;
    put(command, 0x28, &invalid, sizeof(invalid)); int32_t delta = 1;
    put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2994db0, 1).decision == AUTHORITY_DECISION_DENY);

    begin("mass address overflow rejected", 0x2993a28);
    uintptr_t bad = UINTPTR_MAX - 3; int32_t n = 2;
    put(command, 0x28, &bad, sizeof(bad));
    put(command, 0x30, &n, sizeof(n)); put(command, 0x34, &n, sizeof(n));
    put_ptr(command, 0x40, deltas);
    put(command, 0x48, &n, sizeof(n)); put(command, 0x4c, &n, sizeof(n));
    CHECK(run(0x2993a28, 1).decision == AUTHORITY_DECISION_DENY);

    begin("unreadable resolved line rejected", 0x2994db0);
    uintptr_t unknownToken = 99; put(command, 0x28, &unknownToken, sizeof(unknownToken));
    delta = 1; put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2994db0, 1).decision == AUTHORITY_DECISION_DENY);
}

static void test_country_alias_coop_and_line_types(void) {
    const uint32_t vtables[] = {0x297bc80, 0x297be68, 0x297bfc8, 0x297c488};
    const uint32_t getters[] = {0xf6eb40, 0xf6f430, 0xf70990, 0xf6f430};
    for (unsigned i = 0; i < 4; ++i) {
        begin("each reviewed production-line type accepted", 0x2994db0);
        set_line_type(0, vtables[i], getters[i]);
        int32_t aliasCountry = 2, delta = 1;
        put(countryObject[0], 8, &aliasCountry, sizeof(aliasCountry));
        int32_t coopFlags = 0; put(roster, 0x94, &coopFlags, sizeof(coopFlags));
        put(command, 0x28, &refs[0], sizeof(refs[0]));
        put(command, 0x30, &delta, sizeof(delta));
        /* Fixture canonical equality maps country 1 and 2 together. Roster
           flags are zero, modeling a coop controller rather than a leader. */
        CHECK(run(0x2994db0, 0).decision == AUTHORITY_DECISION_ALLOW);
    }
}

static void test_max_normalization_overflow_and_zero_entries(void) {
    begin("reduction normalizes a line above its reduced cap", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    int32_t current = 15, maximum = 10, delta = -5;
    put(line[0], 0xe8, &current, sizeof(current));
    put(line[0], 0xec, &maximum, sizeof(maximum));
    put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2994db0, 0).decision == AUTHORITY_DECISION_ALLOW);

    begin("int32 upper overflow rejected", 0x2994db0);
    put(command, 0x28, &refs[0], sizeof(refs[0]));
    current = INT32_MAX; maximum = INT32_MAX; delta = 1;
    put(line[0], 0xe8, &current, sizeof(current));
    put(line[0], 0xec, &maximum, sizeof(maximum));
    put(command, 0x30, &delta, sizeof(delta));
    CHECK(run(0x2994db0, 0).decision == AUTHORITY_DECISION_DENY);

    begin("empty mass batch is a safe no-op", 0x2993a28);
    int32_t zero = 0;
    put(command, 0x30, &zero, sizeof(zero)); put(command, 0x34, &zero, sizeof(zero));
    put(command, 0x48, &zero, sizeof(zero)); put(command, 0x4c, &zero, sizeof(zero));
    CHECK(run(0x2993a28, 1).decision == AUTHORITY_DECISION_ALLOW);
}

int main(void) {
    test_single_negative_delta();
    test_single_out_of_range_and_unknown_type();
    test_owner_and_command_type();
    test_mass_vectors_and_duplicate_lines();
    test_malformed_mass_vectors();
    test_unreadable_and_pointer_overflow();
    test_country_alias_coop_and_line_types();
    test_max_normalization_overflow_and_zero_entries();
    printf("Authority factory payload tests passed (%u assertions).\n", assertions);
    return 0;
}
