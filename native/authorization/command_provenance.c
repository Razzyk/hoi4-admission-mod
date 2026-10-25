#include "command_provenance.h"

_Static_assert(COMMAND_PROVENANCE_CAPACITY <= UINT32_MAX,
    "Provenance capacity must fit the bounded count field");

#define PROVENANCE_MASK (COMMAND_PROVENANCE_CAPACITY - 1u)

static void saturated_add(uint64_t *value, uint64_t amount) {
    if (UINT64_MAX - *value < amount) *value = UINT64_MAX;
    else *value += amount;
}

static size_t hash_command(const void *command) {
    uint64_t value = (uint64_t)(uintptr_t)command;
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return (size_t)value & PROVENANCE_MASK;
}

static size_t distance_from(size_t home, size_t position) {
    return (position - home) & PROVENANCE_MASK;
}

static int find_index_locked(CommandProvenanceStore *store, const void *command,
    uint32_t *outProbes) {
    size_t index = hash_command(command);
    uint32_t probes = 0;
    for (size_t visited = 0; visited < COMMAND_PROVENANCE_CAPACITY; ++visited) {
        CommandProvenanceEntry *entry = &store->entries[index];
        ++probes;
        if (!entry->occupied || entry->value.command == command) {
            *outProbes = probes;
            return entry->occupied ? (int)index : -1;
        }
        index = (index + 1u) & PROVENANCE_MASK;
    }
    *outProbes = probes;
    return -1;
}

static void record_probes_locked(CommandProvenanceStore *store, uint32_t probes) {
    saturated_add(&store->stats.totalProbes, probes);
    if (probes > store->stats.maximumProbes) store->stats.maximumProbes = probes;
}

static int snapshot_matches(const CommandProvenanceSnapshot *snapshot,
    const CommandProvenanceEntry *entry) {
    return entry->occupied &&
        entry->value.command == snapshot->command &&
        entry->value.vtable == snapshot->vtable &&
        entry->value.sessionEpoch == snapshot->sessionEpoch &&
        entry->value.generation == snapshot->generation;
}

static int snapshot_index_locked(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, uint32_t *outProbes) {
    int index;
    if (!snapshot || !snapshot->command || !snapshot->vtable || snapshot->generation == 0) {
        *outProbes = 0;
        return -1;
    }
    index = find_index_locked(store, snapshot->command, outProbes);
    if (index < 0 || !snapshot_matches(snapshot, &store->entries[index]))
        return -1;
    return index;
}

static void remove_index_locked(CommandProvenanceStore *store, size_t hole) {
    size_t scan = (hole + 1u) & PROVENANCE_MASK;
    for (size_t visited = 0; visited < COMMAND_PROVENANCE_CAPACITY &&
        store->entries[scan].occupied; ++visited) {
        size_t home = hash_command(store->entries[scan].value.command);
        if (distance_from(home, scan) >= distance_from(hole, scan)) {
            store->entries[hole] = store->entries[scan];
            hole = scan;
        }
        scan = (scan + 1u) & PROVENANCE_MASK;
    }
    memset(&store->entries[hole], 0, sizeof(store->entries[hole]));
    --store->stats.count;
}

void CommandProvenanceInit(CommandProvenanceStore *store, uint64_t sessionEpoch) {
    if (!store) return;
    memset(store, 0, sizeof(*store));
    InitializeSRWLock(&store->lock);
    store->sessionEpoch = sessionEpoch;
}

void CommandProvenanceReset(CommandProvenanceStore *store, uint64_t newSessionEpoch) {
    if (!store) return;
    AcquireSRWLockExclusive(&store->lock);
    memset(store->entries, 0, sizeof(store->entries));
    store->sessionEpoch = newSessionEpoch;
    store->stats.count = 0;
    saturated_add(&store->stats.resets, 1);
    ReleaseSRWLockExclusive(&store->lock);
}

int CommandProvenanceAdvanceSession(CommandProvenanceStore *store, uint64_t newSessionEpoch) {
    int advanced = 0;
    if (!store) return 0;
    AcquireSRWLockExclusive(&store->lock);
    if (newSessionEpoch > store->sessionEpoch) {
        store->sessionEpoch = newSessionEpoch;
        advanced = 1;
    }
    ReleaseSRWLockExclusive(&store->lock);
    return advanced;
}

CommandProvenanceCaptureResult CommandProvenanceCapture(CommandProvenanceStore *store,
    const void *command, const void *vtable, uint64_t sessionEpoch,
    uint64_t claimedSender, uint64_t authenticatedSender, uint32_t authenticatedPeerGeneration,
    uintptr_t hostServer,
    uintptr_t transportConnection, uintptr_t transportSessionContext, int nativeValid,
    CommandProvenanceSnapshot *outSnapshot) {
    uint32_t probes = 0;
    int index;
    uint64_t generation;
    CommandProvenanceEntry *entry;
    int replaced;

    if (!store || !command || !vtable || !outSnapshot)
        return COMMAND_PROVENANCE_CAPTURE_INVALID_ARGUMENT;
    if (!nativeValid) return COMMAND_PROVENANCE_CAPTURE_NATIVE_INVALID;
    if (authenticatedSender == 0 || authenticatedPeerGeneration == 0 ||
        claimedSender != authenticatedSender)
        return COMMAND_PROVENANCE_CAPTURE_SENDER_MISMATCH;
    if (hostServer == 0 || transportConnection == 0 || transportSessionContext == 0)
        return COMMAND_PROVENANCE_CAPTURE_INVALID_ARGUMENT;

    AcquireSRWLockExclusive(&store->lock);
    if (sessionEpoch != store->sessionEpoch) {
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_CAPTURE_SESSION_MISMATCH;
    }
    index = find_index_locked(store, command, &probes);
    record_probes_locked(store, probes);
    replaced = index >= 0;
    if (!replaced && store->stats.count >= COMMAND_PROVENANCE_MAX_LIVE) {
        saturated_add(&store->stats.fullFailures, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_CAPTURE_FULL;
    }
    if (store->generationCounter == UINT64_MAX) {
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_CAPTURE_GENERATION_EXHAUSTED;
    }
    generation = ++store->generationCounter;
    if (replaced) {
        entry = &store->entries[index];
        saturated_add(&store->stats.replacements, 1);
    } else {
        size_t insertIndex;
        insertIndex = hash_command(command);
        while (store->entries[insertIndex].occupied)
            insertIndex = (insertIndex + 1u) & PROVENANCE_MASK;
        entry = &store->entries[insertIndex];
        ++store->stats.count;
        if (store->stats.count > store->stats.highWaterCount)
            store->stats.highWaterCount = store->stats.count;
    }

    memset(&entry->value, 0, sizeof(entry->value));
    entry->value.command = command;
    entry->value.vtable = vtable;
    entry->value.hostServer = hostServer;
    entry->value.transportConnection = transportConnection;
    entry->value.transportSessionContext = transportSessionContext;
    entry->value.sessionEpoch = sessionEpoch;
    entry->value.generation = generation;
    entry->value.authenticatedMachineId = authenticatedSender;
    entry->value.authenticatedPeerGeneration = authenticatedPeerGeneration;
    entry->occupied = 1;
    *outSnapshot = entry->value;
    saturated_add(&store->stats.captures, 1);
    ReleaseSRWLockExclusive(&store->lock);
    return replaced ? COMMAND_PROVENANCE_CAPTURE_REPLACED : COMMAND_PROVENANCE_CAPTURED;
}

int CommandProvenanceFind(CommandProvenanceStore *store, const void *command,
    const void *vtable, uint64_t sessionEpoch, CommandProvenanceSnapshot *outSnapshot) {
    uint32_t probes = 0;
    int index;
    if (!store || !command || !vtable || !outSnapshot) return 0;
    AcquireSRWLockExclusive(&store->lock);
    saturated_add(&store->stats.lookups, 1);
    index = find_index_locked(store, command, &probes);
    record_probes_locked(store, probes);
    if (index < 0 || store->entries[index].value.vtable != vtable ||
        store->entries[index].value.sessionEpoch != sessionEpoch) {
        saturated_add(&store->stats.lookupMisses, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return 0;
    }
    *outSnapshot = store->entries[index].value;
    saturated_add(&store->stats.lookupHits, 1);
    ReleaseSRWLockExclusive(&store->lock);
    return 1;
}

int CommandProvenanceFindAny(CommandProvenanceStore *store, const void *command,
    const void *vtable, CommandProvenanceSnapshot *outSnapshot) {
    uint32_t probes = 0;
    int index;
    if (!store || !command || !vtable || !outSnapshot) return 0;
    AcquireSRWLockExclusive(&store->lock);
    saturated_add(&store->stats.lookups, 1);
    index = find_index_locked(store, command, &probes);
    record_probes_locked(store, probes);
    if (index < 0 || store->entries[index].value.vtable != vtable) {
        saturated_add(&store->stats.lookupMisses, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return 0;
    }
    *outSnapshot = store->entries[index].value;
    saturated_add(&store->stats.lookupHits, 1);
    ReleaseSRWLockExclusive(&store->lock);
    return 1;
}

CommandProvenanceDecisionResult CommandProvenanceCommitDecision(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, int policyAllows) {
    uint32_t probes = 0;
    int index;
    CommandProvenanceSnapshot *value;
    if (!nativeValid) return COMMAND_PROVENANCE_DECISION_NATIVE_INVALID;
    if (!store || !snapshot) return COMMAND_PROVENANCE_DECISION_NOT_FOUND;
    AcquireSRWLockExclusive(&store->lock);
    if (snapshot->sessionEpoch != store->sessionEpoch) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    index = snapshot_index_locked(store, snapshot, &probes);
    record_probes_locked(store, probes);
    if (index < 0) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    value = &store->entries[index].value;
    if (value->hasCachedDecision) {
        CommandProvenanceDecisionResult result =
            value->cachedAllows == (uint8_t)(policyAllows != 0) ?
                COMMAND_PROVENANCE_DECISION_OK : COMMAND_PROVENANCE_DECISION_CONFLICT;
        if (result == COMMAND_PROVENANCE_DECISION_CONFLICT)
            saturated_add(&store->stats.decisionConflicts, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return result;
    }
    value->hasCachedDecision = 1;
    value->cachedAllows = (uint8_t)(policyAllows != 0);
    saturated_add(&store->stats.decisionCommits, 1);
    ReleaseSRWLockExclusive(&store->lock);
    return COMMAND_PROVENANCE_DECISION_OK;
}

CommandProvenanceDecisionResult CommandProvenanceSetGrantKind(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, uint8_t grantKind) {
    uint32_t probes = 0;
    int index;
    if (!nativeValid) return COMMAND_PROVENANCE_DECISION_NATIVE_INVALID;
    if (!store || !snapshot || grantKind == 0 || grantKind > 3)
        return COMMAND_PROVENANCE_DECISION_NOT_FOUND;
    AcquireSRWLockExclusive(&store->lock);
    if (snapshot->sessionEpoch != store->sessionEpoch) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    index = snapshot_index_locked(store, snapshot, &probes);
    record_probes_locked(store, probes);
    if (index < 0) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    CommandProvenanceSnapshot *value = &store->entries[index].value;
    if ((value->hasCachedDecision && !value->cachedAllows) ||
        (value->cachedGrantKind && value->cachedGrantKind != grantKind)) {
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_CONFLICT;
    }
    value->cachedGrantKind = grantKind;
    ReleaseSRWLockExclusive(&store->lock);
    return COMMAND_PROVENANCE_DECISION_OK;
}

CommandProvenanceDecisionResult CommandProvenanceGetDecision(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, int *outPolicyAllows) {
    uint32_t probes = 0;
    int index;
    if (outPolicyAllows) *outPolicyAllows = 0;
    if (!nativeValid) return COMMAND_PROVENANCE_DECISION_NATIVE_INVALID;
    if (!store || !snapshot || !outPolicyAllows) return COMMAND_PROVENANCE_DECISION_NOT_FOUND;
    AcquireSRWLockExclusive(&store->lock);
    if (snapshot->sessionEpoch != store->sessionEpoch) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    index = snapshot_index_locked(store, snapshot, &probes);
    record_probes_locked(store, probes);
    if (index < 0) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_STALE;
    }
    if (!store->entries[index].value.hasCachedDecision) {
        ReleaseSRWLockExclusive(&store->lock);
        return COMMAND_PROVENANCE_DECISION_UNSET;
    }
    *outPolicyAllows = store->entries[index].value.cachedAllows != 0;
    ReleaseSRWLockExclusive(&store->lock);
    return COMMAND_PROVENANCE_DECISION_OK;
}

int CommandProvenanceRemove(CommandProvenanceStore *store,
    const CommandProvenanceSnapshot *snapshot) {
    uint32_t probes = 0;
    int index;
    if (!store || !snapshot) return 0;
    AcquireSRWLockExclusive(&store->lock);
    index = snapshot_index_locked(store, snapshot, &probes);
    record_probes_locked(store, probes);
    if (index < 0) {
        saturated_add(&store->stats.staleOperations, 1);
        ReleaseSRWLockExclusive(&store->lock);
        return 0;
    }
    remove_index_locked(store, (size_t)index);
    saturated_add(&store->stats.removals, 1);
    ReleaseSRWLockExclusive(&store->lock);
    return 1;
}

void CommandProvenanceGetStats(CommandProvenanceStore *store, CommandProvenanceStats *outStats) {
    if (!store || !outStats) return;
    AcquireSRWLockShared(&store->lock);
    *outStats = store->stats;
    ReleaseSRWLockShared(&store->lock);
}
