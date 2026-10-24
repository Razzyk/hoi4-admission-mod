/* Isolated fixtures for the pinned native event payload validator. */
#define AUTHORITY_EVENT_PAYLOAD_TEST
#include "../native/authorization/event_payload.c"

static unsigned assertions;
static const char *caseName;
static unsigned char image[0x2221000];
static unsigned char world[0x600];
static unsigned char eventObject[0x430];
static unsigned char pending[0x38];
static unsigned char command[0xf0];
static unsigned char pendingScope[0xb0];
static unsigned char *commandScope;
static unsigned char childPending[0xb0];
static unsigned char childCommand[0xb0];
static unsigned char rosterRecord[0xa0];
static unsigned char eventOptions[2][0x1a0];
static uintptr_t eventOptionPointers[2];
static unsigned char stateObject[0x208];
static uintptr_t tagMapToken, stateMap[2];
static void *resolvedEvent;
static void *resolvedEntity;

#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    fprintf(stderr, "FAIL %s line %d: %s\n", caseName, __LINE__, #condition); ExitProcess(1); \
} } while (0)

static void *__fastcall event_resolver(void *reference) {
    if (reference != command + 0x2c) return NULL;
    return resolvedEvent;
}

static void *__fastcall entity_resolver(void *scope) {
    (void)scope;
    return resolvedEntity;
}

static unsigned char __fastcall canonical_equal(const int32_t *left, int32_t right) {
    return (unsigned char)(left && (*left == right ||
        ((*left == 1 || *left == 2) && (right == 1 || right == 2))));
}

static void put(void *base, size_t offset, const void *value, size_t size) {
    memcpy((unsigned char *)base + offset, value, size);
}

static void begin(const char *name) {
    uintptr_t pointer;
    int32_t value;
    caseName = name;
    memset(image, 0, sizeof(image));
    memset(world, 0, sizeof(world));
    memset(eventObject, 0, sizeof(eventObject));
    memset(pending, 0, sizeof(pending));
    memset(command, 0, sizeof(command));
    commandScope = command + 0x38;
    memset(pendingScope, 0, sizeof(pendingScope));
    memset(childPending, 0, sizeof(childPending));
    memset(childCommand, 0, sizeof(childCommand));
    memset(rosterRecord, 0, sizeof(rosterRecord));
    memset(eventOptions, 0, sizeof(eventOptions));
    memset(stateObject, 0, sizeof(stateObject));
    tagMapToken = 1;
    stateMap[0] = 0;
    stateMap[1] = (uintptr_t)stateObject;
    pointer = (uintptr_t)&tagMapToken; put(world, 0x340, &pointer, sizeof(pointer));
    value = 4; put(world, 0x34c, &value, sizeof(value));
    pointer = (uintptr_t)rosterRecord; put(world, 0xf8, &pointer, sizeof(pointer));
    value = 1; put(world, 0x104, &value, sizeof(value));
    value = 1001; put(rosterRecord, 0x98, &value, sizeof(value));
    value = 1; put(rosterRecord, 0x70, &value, sizeof(value));
    value = 1; put(rosterRecord, 0x94, &value, sizeof(value));
    pointer = (uintptr_t)pending; put(world, 0x560, &pointer, sizeof(pointer));
    value = 1; put(world, 0x568, &value, sizeof(value));
    put(world, 0x56c, &value, sizeof(value));
    value = 42; put(pending, 0, &value, sizeof(value));
    pointer = (uintptr_t)eventObject; put(pending, 8, &pointer, sizeof(pointer));
    pointer = (uintptr_t)pendingScope; put(pending, 0x10, &pointer, sizeof(pointer));
    pointer = (uintptr_t)(image + 0x2999be8); put(eventObject, 0, &pointer, sizeof(pointer));
    value = 2; put(eventObject, 0x374, &value, sizeof(value));
    eventOptionPointers[0] = (uintptr_t)eventOptions[0];
    eventOptionPointers[1] = (uintptr_t)eventOptions[1];
    pointer = (uintptr_t)eventOptionPointers; put(eventObject, 0x368, &pointer, sizeof(pointer));
    pointer = (uintptr_t)(image + 0x2999b48); put(eventOptions[0], 0, &pointer, sizeof(pointer));
    pointer = (uintptr_t)(image + 0x2999b48); put(eventOptions[1], 0, &pointer, sizeof(pointer));
    value = 42; put(command, 0x28, &value, sizeof(value));
    value = 1; put(command, 0x34, &value, sizeof(value));
    value = 0; put(command, 0xe8, &value, sizeof(value));
    value = 1; put(pendingScope, 8, &value, sizeof(value));
    value = 1; put(commandScope, 8, &value, sizeof(value));
    resolvedEvent = eventObject;
    resolvedEntity = NULL;
    AuthorityEventPayloadTestSetResolvers(event_resolver, entity_resolver, canonical_equal);
}

static AuthorityResult validate(void) {
    return AuthorityValidateEventPayload(image, world, command, 1001, 0);
}

static AuthorityResult preflight(void) {
    return AuthorityValidateEventPayload(image, world, command, 1001, 1);
}

static void expect_allow(void) {
    AuthorityResult result = validate();
    if (result.decision != AUTHORITY_DECISION_ALLOW)
        fprintf(stderr, "unexpected decision=%d reason=%d\n", result.decision, result.reason);
    CHECK(result.decision == AUTHORITY_DECISION_ALLOW);
    CHECK(result.reason == AUTHORITY_REASON_NONE);
}

static void expect_deny(AuthorityReason reason) {
    AuthorityResult result = validate();
    CHECK(result.decision == AUTHORITY_DECISION_DENY);
    CHECK(result.reason == reason);
}

int main(void) {
    uintptr_t pointer;
    int32_t value;

    begin("country recipient");
    expect_allow();

    begin("safety preflight does not depend on ordered pending ownership state");
    value = 0; put(world, 0x56c, &value, sizeof(value));
    CHECK(preflight().decision == AUTHORITY_DECISION_ALLOW);

    begin("safety preflight checks option bounds before native predicate");
    value = 2; put(command, 0xe8, &value, sizeof(value));
    CHECK(preflight().decision == AUTHORITY_DECISION_DENY);

    begin("state recipient");
    value = 0; put(pendingScope, 8, &value, sizeof(value));
    value = 1; put(pendingScope, 0xa8, &value, sizeof(value));
    pointer = (uintptr_t)stateMap; put(world, 0x2c8, &pointer, sizeof(pointer));
    value = 2; put(world, 0x2d4, &value, sizeof(value));
    value = 1; put(stateObject, 0xc8, &value, sizeof(value));
    value = 0; put(commandScope, 8, &value, sizeof(value));
    value = 1;
    put(commandScope, 0xa8, &value, sizeof(value));
    expect_allow();

    begin("entity recipient");
    value = 0; put(pendingScope, 8, &value, sizeof(value));
    value = 0; put(pendingScope, 0xa8, &value, sizeof(value));
    value = 0; put(commandScope, 8, &value, sizeof(value));
    resolvedEntity = stateObject;
    value = 1; put(stateObject, 0x120, &value, sizeof(value));
    expect_allow();

    begin("pending id absent");
    value = 43; put(command, 0x28, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("event reference mismatch");
    resolvedEvent = pendingScope;
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("wrong event recipient");
    value = 3; put(pendingScope, 8, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    begin("sender is not leader");
    value = 0; put(rosterRecord, 0x94, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    begin("nonleader can choose only native event-window option path");
    value = 0; put(rosterRecord, 0x94, &value, sizeof(value));
    value = 1; put(eventObject, 0x420, &value, sizeof(value));
    expect_allow();

    begin("nonleader event-window path refuses restricted option");
    value = 0; put(rosterRecord, 0x94, &value, sizeof(value));
    value = 1; put(eventObject, 0x420, &value, sizeof(value));
    value = 1; put(eventOptions[1], 0x134, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    begin("negative option invokes immediate effects");
    value = -1; put(command, 0xe8, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("option index at end");
    value = 2; put(command, 0xe8, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("consumed pending event replay");
    value = 0; put(world, 0x56c, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("nested scope field mismatch");
    pointer = (uintptr_t)childPending; put(pendingScope, 0x18, &pointer, sizeof(pointer));
    pointer = (uintptr_t)childCommand; put(commandScope, 0x18, &pointer, sizeof(pointer));
    value = 1; put(childPending, 8, &value, sizeof(value));
    value = 3; put(childCommand, 8, &value, sizeof(value));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("matching nested self cycle");
    pointer = (uintptr_t)pendingScope; put(pendingScope, 0x18, &pointer, sizeof(pointer));
    pointer = (uintptr_t)commandScope; put(commandScope, 0x18, &pointer, sizeof(pointer));
    expect_allow();

    begin("large valid pending capacity");
    value = 50000; put(world, 0x568, &value, sizeof(value));
    expect_allow();

    begin("trusted scope chain exceeds former fixed limit");
    {
        enum { CHAIN = 300 };
        unsigned char (*left)[0xb0] = calloc(CHAIN, 0xb0);
        unsigned char (*right)[0xb0] = calloc(CHAIN, 0xb0);
        CHECK(left && right);
        pointer = (uintptr_t)left[0]; put(pendingScope, 0x18, &pointer, sizeof(pointer));
        pointer = (uintptr_t)right[0]; put(commandScope, 0x18, &pointer, sizeof(pointer));
        for (int i = 0; i < CHAIN; ++i) {
            value = 1; put(left[i], 8, &value, sizeof(value)); put(right[i], 8, &value, sizeof(value));
            if (i + 1 < CHAIN) {
                pointer = (uintptr_t)left[i + 1]; put(left[i], 0x18, &pointer, sizeof(pointer));
                pointer = (uintptr_t)right[i + 1]; put(right[i], 0x18, &pointer, sizeof(pointer));
            }
        }
        expect_allow();
        free(left); free(right);
    }

    begin("non-self pending scope cycle");
    pointer = (uintptr_t)childPending; put(pendingScope, 0x18, &pointer, sizeof(pointer));
    pointer = (uintptr_t)pendingScope; put(childPending, 0x18, &pointer, sizeof(pointer));
    pointer = (uintptr_t)childCommand; put(commandScope, 0x18, &pointer, sizeof(pointer));
    pointer = (uintptr_t)commandScope; put(childCommand, 0x18, &pointer, sizeof(pointer));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    begin("unreadable pending vector");
    pointer = 1; put(world, 0x560, &pointer, sizeof(pointer));
    expect_deny(AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);

    printf("Authority event payload tests passed (%u assertions).\n", assertions);
    return 0;
}
