#include "../native/authorization/authority_policy.c"

static unsigned assertions;
static const char *case_name;
#define CHECK(condition) do { \
    ++assertions; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s line %d: %s\n", case_name, __LINE__, #condition); \
        ExitProcess(1); \
    } \
} while (0)

static AuthorityPolicy policy;
static const uint64_t epoch = 77;
static uint64_t nextGrantId;

static void begin(const char *name) {
    case_name = name;
    nextGrantId = 1;
    AuthorityPolicyInit(&policy, epoch);
}

static AuthorityFacts remote_facts(void) {
    AuthorityFacts facts;
    memset(&facts, 0, sizeof(facts));
    facts.origin = AUTHORITY_ORIGIN_REMOTE;
    facts.command = AUTHORITY_COMMAND_COUNTRY_CHANGE;
    facts.sessionEpoch = epoch;
    facts.peerStatus = AUTHORITY_PEER_VALID;
    facts.sender.machineId = 1001;
    facts.sender.generation = 9;
    facts.requester = facts.sender;
    facts.nativeValid = 1;
    facts.commit = 1;
    facts.actorControlledBySender = AUTHORITY_TRUTH_TRUE;
    facts.affectedPeerControlsSource = AUTHORITY_TRUTH_TRUE;
    facts.sourceCountry = 10;
    facts.destinationCountry = 20;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_TRUE;
    facts.destinationNativeAvailable = AUTHORITY_TRUTH_FALSE;
    facts.destinationUnoccupied = AUTHORITY_TRUTH_FALSE;
    facts.destinationHumanControlled = AUTHORITY_TRUTH_FALSE;
    facts.nativeClassKnown = AUTHORITY_TRUTH_TRUE;
    facts.nativeClassHostOnly = AUTHORITY_TRUTH_FALSE;
    facts.currentAuthorityKnown = AUTHORITY_TRUTH_TRUE;
    facts.currentAuthority.machineId = 500;
    facts.currentAuthority.generation = 3;
    facts.currentAuthorityCountry = 20;
    facts.currentAuthorityAuthorizedForGrant = AUTHORITY_TRUTH_TRUE;
    return facts;
}

static AuthorityGrant grant_for(AuthorityGrantKind kind) {
    AuthorityGrant grant;
    memset(&grant, 0, sizeof(grant));
    grant.grantId = nextGrantId++;
    grant.sessionEpoch = epoch;
    grant.peer.machineId = 1001;
    grant.peer.generation = 9;
    grant.sourceCountry = 10;
    grant.destinationCountry = 20;
    grant.kind = kind;
    grant.approver.machineId = 500;
    grant.approver.generation = 3;
    grant.authorityCountry = AUTHORITY_COUNTRY_UNKNOWN;
    return grant;
}

static void use_coop_executor(AuthorityFacts *facts) {
    facts->sender.machineId = 500;
    facts->sender.generation = 3;
    facts->requester.machineId = 1001;
    facts->requester.generation = 9;
    facts->actorControlledBySender = AUTHORITY_TRUTH_FALSE;
}

static AuthorityResult evaluate(AuthorityFacts facts, uint64_t now) {
    return AuthorityPolicyEvaluate(&policy, &facts, now);
}

typedef struct ConsumerArgs {
    AuthorityFacts facts;
    AuthorityResult result;
} ConsumerArgs;

static DWORD WINAPI consume_thread(void *context) {
    ConsumerArgs *args = (ConsumerArgs *)context;
    args->result = AuthorityPolicyEvaluate(&policy, &args->facts, 100);
    return 0;
}

int main(void) {
    AuthorityFacts facts;
    AuthorityResult result;
    AuthorityGrant grant;

    begin("coop request is bound to its authenticated requester");
    facts = remote_facts(); facts.command = AUTHORITY_COMMAND_COOP_REQUEST;
    facts.requester.machineId = facts.sender.machineId;
    facts.requester.generation = facts.sender.generation;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.requester.machineId++;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("country actor refuses a foreign actor and follows host role transfer facts");
    facts = remote_facts(); facts.command = AUTHORITY_COMMAND_COUNTRY_ACTOR;
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts.actorControlledBySender = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE; /* Country was transferred since last request. */
    CHECK(evaluate(facts, 100).reason == AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    begin("host local and AI callbacks retain normal native permission behavior");
    facts = remote_facts(); facts.origin = AUTHORITY_ORIGIN_AI;
    facts.command = AUTHORITY_COMMAND_UNREVIEWED;
    facts.peerStatus = AUTHORITY_PEER_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.origin = AUTHORITY_ORIGIN_HOST_LOCAL;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.nativeValid = 0;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    CHECK(evaluate(facts, 100).reason == AUTHORITY_REASON_NATIVE_INVALID);

    begin("raw country change cannot assign another human's country");
    facts = remote_facts();
    facts.sender.machineId = 500;
    facts.sender.generation = 3;
    facts.requester.machineId = 1001;
    facts.requester.generation = 9;
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("observer selection preserves native transition rules during a running game");
    facts = remote_facts(); facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_TRUE;
    facts.destinationNativeAvailable = AUTHORITY_TRUTH_TRUE;
    facts.destinationUnoccupied = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts = remote_facts(); facts.destinationCountry = AUTHORITY_COUNTRY_OBSERVER;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_TRUE;
    facts.sourceObserverEligible = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts.sourceObserverEligible = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.sourceObserverEligible = AUTHORITY_TRUTH_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DEFER);

    facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.sourceObserverEligible = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("prematch free country selection remains available and active-game self switch is locked");
    facts = remote_facts(); facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.destinationNativeAvailable = AUTHORITY_TRUTH_TRUE;
    facts.destinationUnoccupied = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts.destinationUnoccupied = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("self no-op controller selections keep observer and occupied assignments native-valid");
    facts = remote_facts(); facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    facts.destinationCountry = AUTHORITY_COUNTRY_OBSERVER;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts = remote_facts(); facts.destinationCountry = facts.sourceCountry;
    facts.destinationUnoccupied = AUTHORITY_TRUTH_FALSE;
    facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.sender.machineId = 500; facts.sender.generation = 3;
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts = remote_facts(); facts.destinationCountry = 21;
    facts.sourceDestinationCanonicalEqual = AUTHORITY_TRUTH_TRUE;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("host and script grants bind remote executors to affected peer or trusted delegate");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts();
    use_coop_executor(&facts);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    grant.executor = facts.sender;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("duplicate trusted grant delivery does not mint a second use");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts();
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_GRANT_INVALID);

    begin("assignment lock denies a country change without an exact grant");
    facts = remote_facts();
    result = evaluate(facts, 100);
    CHECK(result.decision == AUTHORITY_DECISION_DENY);
    CHECK(result.reason == AUTHORITY_REASON_ASSIGNMENT_LOCKED);

    begin("script grant overrides assignment lock exactly once");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts();
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("trusted script grant may retag an occupied destination while lock is off");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    grant.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts();
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("trusted host grant may assign occupied destination while lock is off");
    grant = grant_for(AUTHORITY_GRANT_HOST);
    grant.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts();
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("coop grant may bind approval to the currently authorized country");
    grant = grant_for(AUTHORITY_GRANT_COOP);
    grant.approver.machineId = 0;
    grant.approver.generation = 0;
    grant.authorityCountry = 20;
    grant.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.commit = 0;
    use_coop_executor(&facts);
    facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts = remote_facts(); facts.commit = 0; facts.currentAuthorityCountry = 21;
    facts.currentAuthorityAuthorizedForGrant = AUTHORITY_TRUTH_FALSE;
    use_coop_executor(&facts);
    facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("host grant overrides assignment lock");
    grant = grant_for(AUTHORITY_GRANT_HOST);
    grant.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("assigning another human's country requires an approved coop grant");
    facts = remote_facts(); facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("coop leader can approve an affected peer country change");
    facts = remote_facts();
    use_coop_executor(&facts);
    facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    grant = grant_for(AUTHORITY_GRANT_COOP);
    grant.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    {
        AuthorityFacts outsider = facts;
        outsider.sender.machineId = 700;
        outsider.sender.generation = 1;
        CHECK(evaluate(outsider, 100).decision == AUTHORITY_DECISION_DENY);
    }
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    grant = grant_for(AUTHORITY_GRANT_COOP);
    grant.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("coop grant requires its approver to retain current authority");
    grant = grant_for(AUTHORITY_GRANT_COOP);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.currentAuthority.generation++;
    use_coop_executor(&facts);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts = remote_facts(); facts.currentAuthorityAuthorizedForGrant = AUTHORITY_TRUTH_UNKNOWN;
    use_coop_executor(&facts);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DEFER);
    facts = remote_facts();
    use_coop_executor(&facts);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("read-only policy checks do not consume one-use grants");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.commit = 0;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.commit = 1;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    begin("native rejection leaves an otherwise matching grant untouched");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.nativeValid = 0;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts.nativeValid = 1;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("twelve simultaneous original executions consume one pending grant once");
    grant = grant_for(AUTHORITY_GRANT_COOP);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    {
        ConsumerArgs args[12];
        HANDLE threads[12];
        unsigned allowed = 0;
        for (size_t i = 0; i < 12; ++i) {
            memset(&args[i], 0, sizeof(args[i]));
            args[i].facts = remote_facts();
            use_coop_executor(&args[i].facts);
            threads[i] = CreateThread(NULL, 0, consume_thread, &args[i], 0, NULL);
            CHECK(threads[i] != NULL);
        }
        CHECK(WaitForMultipleObjects(12, threads, TRUE, INFINITE) == WAIT_OBJECT_0);
        for (size_t i = 0; i < 12; ++i) {
            if (args[i].result.decision == AUTHORITY_DECISION_ALLOW) ++allowed;
            CloseHandle(threads[i]);
        }
        CHECK(allowed == 1);
    }

    begin("two current coop approvers racing a country-bound grant still consume once");
    grant = grant_for(AUTHORITY_GRANT_COOP);
    grant.approver.machineId = 0;
    grant.approver.generation = 0;
    grant.authorityCountry = 20;
    grant.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    {
        ConsumerArgs args[2];
        HANDLE threads[2];
        unsigned allowed = 0;
        for (size_t i = 0; i < 2; ++i) {
            memset(&args[i], 0, sizeof(args[i]));
            args[i].facts = remote_facts();
            args[i].facts.sourceCountry = AUTHORITY_COUNTRY_OBSERVER;
            args[i].facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
            args[i].facts.sender.machineId = 500 + i * 100;
            args[i].facts.sender.generation = 3 + (uint32_t)i;
            args[i].facts.requester.machineId = 1001;
            args[i].facts.requester.generation = 9;
            args[i].facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
            args[i].facts.currentAuthority = args[i].facts.sender;
            args[i].facts.currentAuthorityCountry = 20;
            threads[i] = CreateThread(NULL, 0, consume_thread, &args[i], 0, NULL);
            CHECK(threads[i] != NULL);
        }
        CHECK(WaitForMultipleObjects(2, threads, TRUE, INFINITE) == WAIT_OBJECT_0);
        for (size_t i = 0; i < 2; ++i) {
            if (args[i].result.decision == AUTHORITY_DECISION_ALLOW) ++allowed;
            CloseHandle(threads[i]);
        }
        CHECK(allowed == 1);

    begin("a later coop request supersedes the affected human's stale pending popup");
    grant = grant_for(AUTHORITY_GRANT_COOP);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    AuthorityGrant newer = grant_for(AUTHORITY_GRANT_COOP); newer.destinationCountry = 30;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &newer, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); use_coop_executor(&facts);
    facts.destinationCountry = 30;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);
    facts.destinationCountry = 20;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    }

    begin("grant expires at its supplied timestamp and old peer generations are pruned");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.expiresAt = 200;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(remote_facts(), 200).decision == AUTHORITY_DECISION_DENY);
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.expiresAt = 0;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    AuthorityPolicyPrunePeer(&policy, grant.peer.machineId, grant.peer.generation + 1);
    CHECK(evaluate(remote_facts(), 100).decision == AUTHORITY_DECISION_DENY);

    begin("source role changes invalidate stale authority and assignment grants");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.affectedPeerControlsSource = AUTHORITY_TRUTH_FALSE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    CHECK(evaluate(remote_facts(), 100).decision == AUTHORITY_DECISION_DENY);

    begin("any actual country assignment revokes pending grants for that affected human");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    CHECK(evaluate(remote_facts(), 100).decision == AUTHORITY_DECISION_ALLOW);
    AuthorityPolicyRevokeAffectedPeer(&policy, grant.peer.machineId);
    CHECK(evaluate(remote_facts(), 100).decision == AUTHORITY_DECISION_DENY);

    begin("ordered same-source script grants rebase later intents after the first approved move");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.destinationCountry = 20;
    grant.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    AuthorityGrant later = grant_for(AUTHORITY_GRANT_SCRIPT); later.destinationCountry = 30;
    later.allowOccupiedDestination = 1;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &later, 100, epoch) == AUTHORITY_REASON_NONE);
    facts = remote_facts(); facts.destinationHumanControlled = AUTHORITY_TRUTH_TRUE;
    facts.assignmentLockEnabled = AUTHORITY_TRUTH_FALSE;
    facts.actorControlledBySender = AUTHORITY_TRUTH_FALSE;
    AuthorityResult firstScriptMove = evaluate(facts, 100);
    CHECK(firstScriptMove.decision == AUTHORITY_DECISION_ALLOW);
    CHECK(firstScriptMove.usedGrantKind == AUTHORITY_GRANT_SCRIPT);
    AuthorityPolicyRebaseScriptGrants(&policy, grant.peer.machineId, grant.peer.generation, 10, 20);
    facts.sourceCountry = 20; facts.destinationCountry = 30;
    facts.currentAuthorityCountry = 30;
    AuthorityResult secondScriptMove = evaluate(facts, 100);
    CHECK(secondScriptMove.decision == AUTHORITY_DECISION_ALLOW);
    CHECK(secondScriptMove.usedGrantKind == AUTHORITY_GRANT_SCRIPT);
    AuthorityPolicyRevokeAffectedPeer(&policy, grant.peer.machineId);
    facts.sourceCountry = 10; facts.destinationCountry = 30;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    /* Reassigning back to the old source/destination cannot revive the grant. */
    CHECK(evaluate(remote_facts(), 100).decision == AUTHORITY_DECISION_DENY);

    begin("new grants stop at global capacity without evicting live grants");
    for (uint64_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        grant = grant_for(AUTHORITY_GRANT_SCRIPT);
        grant.peer.machineId = 10000 + i;
        CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    }
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.peer.machineId = 99999;
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_GRANT_CAPACITY);
    grant = grant_for(AUTHORITY_GRANT_SCRIPT); grant.peer.machineId = 10000;
    facts = remote_facts(); facts.sender = grant.peer; facts.requester = grant.peer;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_ALLOW);

    begin("session reset clears grants and session mismatch refuses old commands");
    grant = grant_for(AUTHORITY_GRANT_SCRIPT);
    CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, 100, epoch) == AUTHORITY_REASON_NONE);
    AuthorityPolicyReset(&policy, epoch + 1);
    facts = remote_facts(); facts.sessionEpoch = epoch;
    CHECK(evaluate(facts, 100).reason == AUTHORITY_REASON_SESSION_MISMATCH);

    begin("unknown authentication and command facts defer; invalid peers deny");
    facts = remote_facts(); facts.peerStatus = AUTHORITY_PEER_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DEFER);
    facts.peerStatus = AUTHORITY_PEER_INVALID;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);
    facts.peerStatus = AUTHORITY_PEER_VALID; facts.command = AUTHORITY_COMMAND_UNREVIEWED;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DEFER);
    facts.command = AUTHORITY_COMMAND_HOST_ONLY; facts.nativeClassKnown = AUTHORITY_TRUTH_UNKNOWN;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DEFER);
    facts.nativeClassKnown = AUTHORITY_TRUTH_TRUE; facts.nativeClassHostOnly = AUTHORITY_TRUTH_TRUE;
    CHECK(evaluate(facts, 100).decision == AUTHORITY_DECISION_DENY);

    printf("PASS %u authority policy assertions\n", assertions);
    return 0;
}
