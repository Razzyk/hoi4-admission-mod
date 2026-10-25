/* Authenticated native-boundary tests for AddProductionLineFactories. */
#define AUTHORITY_FACTORY_PAYLOAD_TEST
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main
#include "../native/authorization/event_payload.c"
#include "../native/authorization/factory_payload.c"

static unsigned factory_assertions;
#define F_CHECK(c) do { ++factory_assertions; if (!(c)) { \
    fprintf(stderr, "FAIL factory wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static unsigned char factoryWorld[0xb40];
static unsigned char factoryCommand[0x80];
static unsigned char factoryLine[0x100];
static unsigned char factoryStatus[0x298];
static unsigned char factoryCountry[0x10];
static unsigned char factoryHuman[0xa0];
static unsigned char factoryTagMap;
static void *factoryResolvedLine;

static void *__fastcall factory_ref_resolver(void *reference) {
    return reference == factoryCommand + 0x28 ? factoryResolvedLine : NULL;
}

static unsigned char __fastcall factory_country_equal(const int32_t *left, int32_t right) {
    return (unsigned char)(left && *left == right);
}

static int32_t __fastcall factory_maximum(void *line) {
    (void)line;
    return 10;
}

static void factory_put(void *base, size_t offset, const void *value, size_t size) {
    memcpy((unsigned char *)base + offset, value, size);
}

static void prepare_factory_fixture(uint64_t epoch) {
    reset_fixture(epoch);
    if (!VirtualAlloc(imageBase + 0x297b000, 0x1000, MEM_COMMIT, PAGE_READWRITE))
        ExitProcess(3);
    memset(factoryWorld, 0, sizeof(factoryWorld));
    memset(factoryCommand, 0, sizeof(factoryCommand));
    memset(factoryLine, 0, sizeof(factoryLine));
    memset(factoryStatus, 0, sizeof(factoryStatus));
    memset(factoryCountry, 0, sizeof(factoryCountry));
    set_fixture_human(factoryHuman, 1001, 1);
    fake_humans[0] = factoryHuman;
    fake_human_count = 1;
    factoryTagMap = 0;
    uintptr_t pointer = (uintptr_t)&factoryTagMap;
    int32_t value = 8;
    factory_put(factoryWorld, 0x340, &pointer, sizeof(pointer));
    factory_put(factoryWorld, 0x34c, &value, sizeof(value));
    pointer = (uintptr_t)factoryHuman;
    factory_put(factoryWorld, 0xf8, &pointer, sizeof(pointer));
    value = 1; factory_put(factoryWorld, 0x104, &value, sizeof(value));
    pointer = (uintptr_t)(imageBase + classes[23].vtableRva);
    factory_put(factoryCommand, 0, &pointer, sizeof(pointer));
    uint32_t claimed = (uint32_t)fixture_sender_id;
    factory_put(factoryCommand, 0x0c, &claimed, sizeof(claimed));
    value = 5; factory_put(factoryCommand, 0x30, &value, sizeof(value));
    pointer = (uintptr_t)(imageBase + 0x297bc80);
    factory_put(factoryLine, 0, &pointer, sizeof(pointer));
    set_private_pointer(0x297bc80 + 0x58, imageBase + 0xf6eb40);
    pointer = (uintptr_t)factoryStatus; factory_put(factoryLine, 0x20, &pointer, sizeof(pointer));
    pointer = (uintptr_t)factoryCountry; factory_put(factoryStatus, 0x290, &pointer, sizeof(pointer));
    value = 1; factory_put(factoryCountry, 8, &value, sizeof(value));
    value = 5; factory_put(factoryLine, 0xe8, &value, sizeof(value));
    factoryResolvedLine = factoryLine;
    set_private_pointer(0x332f260, factoryWorld);
    AuthorityFactoryPayloadTestSetResolvers(factory_ref_resolver,
        factory_country_equal, factory_maximum);
    classes[23].originalValid = mock_native_valid;
    classes[23].originalLoggable = mock_native_loggable;
}

int main(void) {
    setup_private_image();
    void *motivation = (void *)(uintptr_t)0x12345678;

    case_name = "wrong line type is refused before native predicate";
    prepare_factory_fixture(1101);
    uintptr_t badVtable = (uintptr_t)(imageBase + 0x297c260);
    factory_put(factoryLine, 0, &badVtable, sizeof(badVtable));
    capture_command = (void **)factoryCommand;
    capture_motivation = motivation;
    expected_capture_answer = 0;
    valid_calls = 0;
    capture_from_receive(capture_command, motivation);
    F_CHECK(valid_calls == 0);
    F_CHECK(!CommandProvenanceFindAny(&provenance, factoryCommand,
        (void *)(imageBase + classes[23].vtableRva), &(CommandProvenanceSnapshot){0}));

    case_name = "controlled production line accepts a within-capacity increase";
    prepare_factory_fixture(1102);
    capture_command = (void **)factoryCommand;
    capture_motivation = motivation;
    expected_capture_answer = 1;
    expected_native_answer = 1;
    valid_calls = 0;
    capture_from_receive(capture_command, motivation);
    F_CHECK(valid_calls == 1);
    F_CHECK(invoke_valid(0x22530ef, capture_command, motivation) == 1);
    F_CHECK(invoke_log(0x225381d, capture_command) == 1);

    case_name = "projected count above native maximum is denied and not loggable";
    prepare_factory_fixture(1103);
    int32_t delta = 6;
    factory_put(factoryCommand, 0x30, &delta, sizeof(delta));
    capture_command = (void **)factoryCommand;
    capture_motivation = motivation;
    expected_capture_answer = 1;
    expected_native_answer = 1;
    capture_from_receive(capture_command, motivation);
    F_CHECK(invoke_valid(0x22530ef, capture_command, motivation) == 0);
    F_CHECK(invoke_log(0x225381d, capture_command) == 0);

    case_name = "foreign line owner is denied";
    prepare_factory_fixture(1104);
    int32_t foreignCountry = 2;
    factory_put(factoryCountry, 8, &foreignCountry, sizeof(foreignCountry));
    capture_command = (void **)factoryCommand;
    capture_motivation = motivation;
    expected_capture_answer = 1;
    expected_native_answer = 1;
    capture_from_receive(capture_command, motivation);
    F_CHECK(invoke_valid(0x22530ef, capture_command, motivation) == 0);

    printf("Authority factory wrapper tests passed (%u assertions).\n", factory_assertions);
    return 0;
}
