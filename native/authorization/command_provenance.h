#ifndef HOI4_COMMAND_PROVENANCE_H
#define HOI4_COMMAND_PROVENANCE_H

#include "../protocol.h"

#ifndef COMMAND_PROVENANCE_CAPACITY
#define COMMAND_PROVENANCE_CAPACITY 32768u
#endif
#ifndef COMMAND_PROVENANCE_MAX_LIVE
#define COMMAND_PROVENANCE_MAX_LIVE (COMMAND_PROVENANCE_CAPACITY / 2u)
#endif

_Static_assert(COMMAND_PROVENANCE_CAPACITY >= 2u, "Provenance capacity must be at least two entries");
_Static_assert((COMMAND_PROVENANCE_CAPACITY & (COMMAND_PROVENANCE_CAPACITY - 1u)) == 0u,
    "Provenance capacity must be a power of two");
_Static_assert(COMMAND_PROVENANCE_MAX_LIVE > 0u &&
    COMMAND_PROVENANCE_MAX_LIVE <= COMMAND_PROVENANCE_CAPACITY / 2u,
    "Maximum live provenance entries must leave at least half the table empty");

typedef enum CommandProvenanceCaptureResult {
    COMMAND_PROVENANCE_CAPTURED = 0,
    COMMAND_PROVENANCE_CAPTURE_REPLACED,
    COMMAND_PROVENANCE_CAPTURE_INVALID_ARGUMENT,
    COMMAND_PROVENANCE_CAPTURE_NATIVE_INVALID,
    COMMAND_PROVENANCE_CAPTURE_SENDER_MISMATCH,
    COMMAND_PROVENANCE_CAPTURE_SESSION_MISMATCH,
    COMMAND_PROVENANCE_CAPTURE_FULL,
    COMMAND_PROVENANCE_CAPTURE_GENERATION_EXHAUSTED
} CommandProvenanceCaptureResult;

typedef enum CommandProvenanceDecisionResult {
    COMMAND_PROVENANCE_DECISION_OK = 0,
    COMMAND_PROVENANCE_DECISION_NATIVE_INVALID,
    COMMAND_PROVENANCE_DECISION_NOT_FOUND,
    COMMAND_PROVENANCE_DECISION_STALE,
    COMMAND_PROVENANCE_DECISION_UNSET,
    COMMAND_PROVENANCE_DECISION_CONFLICT
} CommandProvenanceDecisionResult;

typedef struct CommandProvenanceSnapshot {
    const void *command;
    const void *vtable;
    uintptr_t hostServer;
    uintptr_t transportConnection;
    uintptr_t transportSessionContext;
    uint64_t sessionEpoch;
    uint64_t generation;
    uint64_t authenticatedMachineId;
    uint32_t authenticatedPeerGeneration;
    uint8_t hasCachedDecision;
    uint8_t cachedAllows;
    uint8_t cachedGrantKind;
} CommandProvenanceSnapshot;

typedef struct CommandProvenanceEntry {
    CommandProvenanceSnapshot value;
    uint8_t occupied;
} CommandProvenanceEntry;

typedef struct CommandProvenanceStats {
    uint64_t captures;
    uint64_t replacements;
    uint64_t fullFailures;
    uint64_t lookups;
    uint64_t lookupHits;
    uint64_t lookupMisses;
    uint64_t removals;
    uint64_t staleOperations;
    uint64_t decisionCommits;
    uint64_t decisionConflicts;
    uint64_t resets;
    uint64_t totalProbes;
    uint64_t maximumProbes;
    uint32_t count;
    uint32_t highWaterCount;
} CommandProvenanceStats;

typedef struct CommandProvenanceStore {
    SRWLOCK lock;
    uint64_t sessionEpoch;
    uint64_t generationCounter;
    CommandProvenanceStats stats;
    CommandProvenanceEntry entries[COMMAND_PROVENANCE_CAPACITY];
} CommandProvenanceStore;

void CommandProvenanceInit(CommandProvenanceStore *store, uint64_t sessionEpoch);
/* Advance the capture epoch without dropping queued-command provenance. */
int CommandProvenanceAdvanceSession(CommandProvenanceStore *store, uint64_t newSessionEpoch);
/* Explicit teardown/test clear only. Do not use for world-load transitions with queued commands. */
void CommandProvenanceReset(CommandProvenanceStore *store, uint64_t newSessionEpoch);

/* No game pointer is dereferenced. Capture requires native acceptance and an exact authenticated sender match. */
CommandProvenanceCaptureResult CommandProvenanceCapture(CommandProvenanceStore *store,
    const void *command, const void *vtable, uint64_t sessionEpoch,
    uint64_t claimedSender, uint64_t authenticatedSender, uint32_t authenticatedPeerGeneration,
    uintptr_t hostServer,
    uintptr_t transportConnection, uintptr_t transportSessionContext, int nativeValid,
    CommandProvenanceSnapshot *outSnapshot);

int CommandProvenanceFind(CommandProvenanceStore *store, const void *command,
    const void *vtable, uint64_t sessionEpoch, CommandProvenanceSnapshot *outSnapshot);
/* Resolve by native object identity when the callback has not yet read its captured epoch. */
int CommandProvenanceFindAny(CommandProvenanceStore *store, const void *command,
    const void *vtable, CommandProvenanceSnapshot *outSnapshot);

/* The first cached policy decision is stable for this command generation. */
CommandProvenanceDecisionResult CommandProvenanceCommitDecision(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, int policyAllows);
CommandProvenanceDecisionResult CommandProvenanceSetGrantKind(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, uint8_t grantKind);

/* Native rejection always resolves to deny, even if a cached policy decision allowed. */
CommandProvenanceDecisionResult CommandProvenanceGetDecision(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, int *outPolicyAllows);

/* Destructor path: removal succeeds only for the exact captured generation. */
int CommandProvenanceRemove(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot);

void CommandProvenanceGetStats(CommandProvenanceStore *store, CommandProvenanceStats *outStats);

#endif
