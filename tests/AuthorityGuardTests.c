#define AUTHORITY_GUARD_TEST
#include "../native/authorization/authority_policy.c"
#include "../native/authorization/command_provenance.c"
#include "../native/vtable_hook.c"
#include "../native/authorization/authority_guard.c"

static unsigned assertions;
static const char *case_name;
static int native_calls, destroy_calls, native_answer;
static AuthorityPolicy policy_fixture;
static CommandProvenanceStore store_fixture;
#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    fprintf(stderr, "FAIL %s line %d: %s\n", case_name, __LINE__, #condition); ExitProcess(1); \
} } while (0)

static int fake_native_valid(void *command) { (void)command; ++native_calls; return native_answer; }
static void fake_destroy(void *command) { (void)command; ++destroy_calls; }
static void *fake_pointer(uintptr_t value) { return (void *)value; }

static CommandProvenanceSnapshot capture(uint64_t epoch, uintptr_t command) {
    CommandProvenanceSnapshot snapshot;
    CHECK(CommandProvenanceCapture(&store_fixture, fake_pointer(command), fake_pointer(0x5000),
        epoch, 1001, 1001, 3, 0x6000, 0x7000, 0x8000, 1, &snapshot) == COMMAND_PROVENANCE_CAPTURED);
    return snapshot;
}

static AuthorityFacts actor_facts(uint64_t epoch) {
    AuthorityFacts facts;
    memset(&facts, 0, sizeof(facts));
    facts.origin = AUTHORITY_ORIGIN_REMOTE;
    facts.command = AUTHORITY_COMMAND_COUNTRY_ACTOR;
    facts.sessionEpoch = epoch;
    facts.peerStatus = AUTHORITY_PEER_VALID;
    facts.sender.machineId = 1001; facts.sender.generation = 3;
    facts.actorControlledBySender = AUTHORITY_TRUTH_TRUE;
    facts.nativeValid = 1;
    return facts;
}

int main(void) {
    AuthorityFacts facts;
    CommandProvenanceSnapshot snapshot;
    int result;

    case_name = "native predicate runs exactly once and cached allow survives motivation recheck";
    AuthorityPolicyInit(&policy_fixture, 41); CommandProvenanceInit(&store_fixture, 41);
    snapshot = capture(41, 0x1000); facts = actor_facts(41);
    native_calls = 0; native_answer = 1;
    result = AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x1000), 100, 1);
    CHECK(result == 1 && native_calls == 1);
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    result = AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x1000), 100, 0);
    CHECK(result == 1 && native_calls == 2);

    case_name = "native false always denies before cached allow";
    native_answer = 0;
    result = AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x1000), 100, 0);
    CHECK(result == 0 && native_calls == 3);

    case_name = "foreign actor denial is cached and remains stable";
    AuthorityPolicyInit(&policy_fixture, 42); CommandProvenanceInit(&store_fixture, 42);
    snapshot = capture(42, 0x2000); facts = actor_facts(42);
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    native_answer = 1; native_calls = 0;
    CHECK(AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x2000), 100, 1) == 0);
    facts.actorControlledBySender = AUTHORITY_TRUTH_TRUE;
    CHECK(AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x2000), 100, 0) == 0);
    CHECK(native_calls == 2);

    case_name = "old epoch with retained metadata cannot reuse cached authorization";
    AuthorityPolicyInit(&policy_fixture, 43); CommandProvenanceInit(&store_fixture, 43);
    snapshot = capture(43, 0x3000); facts = actor_facts(43);
    CHECK(AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x3000), 100, 1) == 1);
    CHECK(CommandProvenanceAdvanceSession(&store_fixture, 44));
    facts.sessionEpoch = 44;
    CHECK(AuthorityGuardTestEvaluate(&policy_fixture, &store_fixture, &snapshot, &facts,
        fake_native_valid, fake_pointer(0x3000), 100, 0) == 0);
    CHECK(CommandProvenanceFindAny(&store_fixture, snapshot.command, snapshot.vtable, &snapshot));

    case_name = "destructor removes provenance before calling original";
    AuthorityPolicyInit(&policy_fixture, 45); CommandProvenanceInit(&store_fixture, 45);
    snapshot = capture(45, 0x4000); destroy_calls = 0;
    CHECK(AuthorityGuardTestDestroy(&store_fixture, &snapshot, fake_destroy, fake_pointer(0x4000)) == 1);
    CHECK(destroy_calls == 1);
    CHECK(!CommandProvenanceFindAny(&store_fixture, snapshot.command, snapshot.vtable, &snapshot));

    printf("PASS %u authority guard assertions\n", assertions);
    return 0;
}
