#ifndef HOI4_AUTHORITY_GUARD_H
#define HOI4_AUTHORITY_GUARD_H

#include "../protocol.h"

typedef void (*AuthorityGuardPacketCallback)(void *, const void *, uint32_t, uintptr_t, int);
typedef void (*AuthorityGuardLogger)(const char *message);

typedef enum AuthorityGuardState {
    AUTHORITY_GUARD_STOPPED = 0,
    AUTHORITY_GUARD_VERIFYING,
    AUTHORITY_GUARD_INSTALLED,
    AUTHORITY_GUARD_FAILED
} AuthorityGuardState;

typedef struct AuthorityGuardStats {
    uint64_t receiveCallbacks;
    uint64_t receiveScopes;
    uint64_t nativeValidCalls;
    uint64_t nativeInvalid;
    uint64_t policyAllows;
    uint64_t policyDenies;
    uint64_t policyDefers;
    uint64_t provenanceMisses;
    uint64_t provenanceFull;
    uint64_t staleEpochs;
    uint64_t stalePeers;
    uint64_t transientLoadRefusals;
    uint64_t grantIssues;
    uint64_t grantIssueRefusals;
    uint64_t installFailures;
    uint64_t verifyFailures;
} AuthorityGuardStats;

/* Call the original host channel-0 receive callback through the authenticated
 * TLS scope. All other channels pass through unchanged. */
void AuthorityGuardReceive(AuthorityGuardPacketCallback original, void *server,
    const void *packet, uint32_t length, uintptr_t connection, int channel);

/* Performs hash, proof-byte, vtable-slot, and transactional hook checks.
 * Call outside DllMain and before accepting admission. */
int AuthorityGuardStart(AuthorityGuardLogger logger);
int AuthorityGuardVerify(void);
void AuthorityGuardStop(void); /* resident hooks; disables policy decisions */
int AuthorityGuardInstalled(void);
AuthorityGuardState AuthorityGuardGetState(void);
void AuthorityGuardGetStats(AuthorityGuardStats *stats);
/* Flush bounded reject counters from a worker/heartbeat thread, never a hook. */
void AuthorityGuardFlushDiagnostics(void);

#ifdef AUTHORITY_GUARD_TEST
#include "authority_policy.h"
#include "command_provenance.h"
int AuthorityGuardTestEvaluate(AuthorityPolicy *policy, CommandProvenanceStore *store,
    CommandProvenanceSnapshot *snapshot, AuthorityFacts *facts,
    int (*nativeValid)(void *), void *command, uint64_t now, int commit);
int AuthorityGuardTestDestroy(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, void (*nativeDestroy)(void *), void *command);
#endif

#endif
