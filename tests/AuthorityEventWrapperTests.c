/* Authenticated native-boundary tests for SelectEventOption. */
#define AUTHORITY_EVENT_PAYLOAD_TEST
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main
#include "../native/authorization/event_payload.c"
#include "../native/authorization/factory_payload.c"

static unsigned event_assertions;
#define E_CHECK(c) do { ++event_assertions; if (!(c)) { \
    fprintf(stderr, "FAIL event wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static unsigned char eventWorld[0x600];
static unsigned char eventObjectFixture[0x380];
static unsigned char pendingEntry[0x38];
static unsigned char eventScopeFixture[0xb0];
static unsigned char eventCommandFixture[0xf0];
static unsigned char eventHumanFixture[0xa0];
static uintptr_t eventTagMap;
static void *eventResolved;

static void *__fastcall event_resolver(void *reference) {
    return reference == eventCommandFixture + 0x2c ? eventResolved : NULL;
}

static unsigned char __fastcall event_canonical_equal(const int32_t *left, int32_t right) {
    return (unsigned char)(left && *left == right);
}

static void set_event_bytes(void *base, size_t offset, const void *value, size_t size) {
    memcpy((unsigned char *)base + offset, value, size);
}

static void prepare_event_fixture(uint64_t epoch) {
    reset_fixture(epoch);
    memset(eventWorld, 0, sizeof(eventWorld));
    memset(eventObjectFixture, 0, sizeof(eventObjectFixture));
    memset(pendingEntry, 0, sizeof(pendingEntry));
    memset(eventScopeFixture, 0, sizeof(eventScopeFixture));
    memset(eventCommandFixture, 0, sizeof(eventCommandFixture));
    set_fixture_human(eventHumanFixture, 1001, 1);
    int32_t leaderFlag = 1;
    set_event_bytes(eventHumanFixture, 0x94, &leaderFlag, sizeof(leaderFlag));
    fake_humans[0] = eventHumanFixture;
    fake_human_count = 1;
    eventTagMap = 1;
    uintptr_t pointer = (uintptr_t)&eventTagMap;
    int32_t value = 4;
    set_event_bytes(eventWorld, 0x340, &pointer, sizeof(pointer));
    set_event_bytes(eventWorld, 0x34c, &value, sizeof(value));
    pointer = (uintptr_t)eventHumanFixture;
    set_event_bytes(eventWorld, 0xf8, &pointer, sizeof(pointer));
    value = 1; set_event_bytes(eventWorld, 0x104, &value, sizeof(value));
    pointer = (uintptr_t)pendingEntry;
    set_event_bytes(eventWorld, 0x560, &pointer, sizeof(pointer));
    value = 1; set_event_bytes(eventWorld, 0x568, &value, sizeof(value));
    set_event_bytes(eventWorld, 0x56c, &value, sizeof(value));
    value = 42; set_event_bytes(pendingEntry, 0, &value, sizeof(value));
    pointer = (uintptr_t)eventObjectFixture;
    set_event_bytes(pendingEntry, 8, &pointer, sizeof(pointer));
    pointer = (uintptr_t)eventScopeFixture;
    set_event_bytes(pendingEntry, 0x10, &pointer, sizeof(pointer));
    pointer = (uintptr_t)(imageBase + 0x2999be8);
    set_event_bytes(eventObjectFixture, 0, &pointer, sizeof(pointer));
    value = 2; set_event_bytes(eventObjectFixture, 0x374, &value, sizeof(value));
    value = 1; set_event_bytes(eventScopeFixture, 8, &value, sizeof(value));
    set_event_bytes(eventCommandFixture, 0x40, &value, sizeof(value));
    pointer = (uintptr_t)(imageBase + classes[22].vtableRva);
    set_event_bytes(eventCommandFixture, 0, &pointer, sizeof(pointer));
    uint32_t claimedMachine = (uint32_t)fixture_sender_id;
    set_event_bytes(eventCommandFixture, 0x0c, &claimedMachine, sizeof(claimedMachine));
    value = 42; set_event_bytes(eventCommandFixture, 0x28, &value, sizeof(value));
    value = 1; set_event_bytes(eventCommandFixture, 0x34, &value, sizeof(value));
    value = 0; set_event_bytes(eventCommandFixture, 0xe8, &value, sizeof(value));
    eventResolved = eventObjectFixture;
    set_private_pointer(0x332f260, eventWorld);
    AuthorityEventPayloadTestSetResolvers(event_resolver, NULL, event_canonical_equal);
    classes[22].originalValid = mock_native_valid;
    classes[22].originalLoggable = mock_native_loggable;
}

int main(void) {
    setup_private_image();
    void *motivation = (void *)(uintptr_t)0x12345678;
    case_name = "malformed option is rejected before native predicate or queue history";
    prepare_event_fixture(990);
    int32_t badOption = 2;
    set_event_bytes(eventCommandFixture, 0xe8, &badOption, sizeof(badOption));
    capture_command = (void **)eventCommandFixture;
    capture_motivation = motivation;
    expected_capture_answer = 0;
    valid_calls = 0;
    capture_from_receive(capture_command, motivation);
    E_CHECK(valid_calls == 0);
    E_CHECK(!CommandProvenanceFindAny(&provenance, eventCommandFixture,
        (void *)(imageBase + classes[22].vtableRva), &(CommandProvenanceSnapshot){0}));

    case_name = "valid event is authorized at ordered boundary and remains loggable";
    prepare_event_fixture(991);
    capture_command = (void **)eventCommandFixture;
    capture_motivation = motivation;
    expected_capture_answer = 1;
    expected_native_answer = 1;
    valid_calls = 0;
    capture_from_receive(capture_command, motivation);
    E_CHECK(valid_calls == 1);
    AuthorityResult eventResult = AuthorityValidateEventPayload(imageBase, eventWorld,
        eventCommandFixture, fixture_sender_id, 0);
    if (eventResult.decision != AUTHORITY_DECISION_ALLOW)
        fprintf(stderr, "event result decision=%d reason=%d\n", eventResult.decision, eventResult.reason);
    E_CHECK(invoke_valid(0x22530ef, capture_command, motivation) == 1);
    E_CHECK(invoke_log(0x225381d, capture_command) == 1);

    printf("Authority event wrapper tests passed (%u assertions).\n", event_assertions);
    return 0;
}
