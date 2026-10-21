#include "../native/authorization/command_provenance.c"

static unsigned assertions;
static const char *case_name;
#define CHECK(condition) do { \
    ++assertions; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s line %d: %s\n", case_name, __LINE__, #condition); \
        ExitProcess(1); \
    } \
} while (0)

static CommandProvenanceStore store;
static volatile LONG workerFailures;

static void begin(const char *name, uint64_t epoch) {
    case_name = name;
    CommandProvenanceInit(&store, epoch);
}

static void *pointer_value(uintptr_t value) {
    return (void *)value;
}

static CommandProvenanceCaptureResult capture(const void *command, const void *vtable,
    uint64_t epoch, uint64_t sender, uintptr_t connection,
    CommandProvenanceSnapshot *snapshot) {
    return CommandProvenanceCapture(&store, command, vtable, epoch, sender, sender,
        9, (uintptr_t)0x7000u, connection, (uintptr_t)0x8000u, 1, snapshot);
}

static uint64_t elapsed_us(LARGE_INTEGER start, LARGE_INTEGER finish, LARGE_INTEGER frequency) {
    return (uint64_t)((finish.QuadPart - start.QuadPart) * INT64_C(1000000) / frequency.QuadPart);
}

typedef struct WorkerArgs {
    uint32_t worker;
    uint32_t iterations;
} WorkerArgs;

static DWORD WINAPI provenance_worker(void *context) {
    WorkerArgs *args = (WorkerArgs *)context;
    const uint64_t epoch = 91;
    const void *vtable = pointer_value((uintptr_t)0x9000u + args->worker * 16u);
    for (uint32_t i = 0; i < args->iterations; ++i) {
        const void *command = pointer_value((uintptr_t)0x2000000u +
            args->worker * 0x100000u + i * 16u);
        CommandProvenanceSnapshot snapshot, found;
        int allowed = 1;
        if (capture(command, vtable, epoch, (uint64_t)args->worker + 1u,
            (uintptr_t)i + 1u, &snapshot) != COMMAND_PROVENANCE_CAPTURED ||
            !CommandProvenanceFind(&store, command, vtable, epoch, &found) ||
            found.generation != snapshot.generation ||
            CommandProvenanceCommitDecision(&store, &snapshot, 1, 0) !=
                COMMAND_PROVENANCE_DECISION_OK ||
            CommandProvenanceGetDecision(&store, &snapshot, 1, &allowed) !=
                COMMAND_PROVENANCE_DECISION_OK || allowed ||
            !CommandProvenanceRemove(&store, &snapshot)) {
            InterlockedIncrement(&workerFailures);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    CommandProvenanceSnapshot first, found, replacement, temporary;
    CommandProvenanceStats stats;
    int allowed = 99;

    begin("capture accepts only native-valid authenticated sender metadata", 11);
    CHECK(CommandProvenanceCapture(&store, pointer_value(0x1000u), pointer_value(0x2000u),
        11, 12, 12, 4, 0x7000u, 0x3000u, 0x4000u, 1, &first) == COMMAND_PROVENANCE_CAPTURED);
    CHECK(first.authenticatedMachineId == 12 && first.hostServer == 0x7000u);
    CHECK(first.authenticatedPeerGeneration == 4);
    CHECK(first.transportConnection == 0x3000u && first.transportSessionContext == 0x4000u);
    CHECK(CommandProvenanceCapture(&store, pointer_value(0x1001u), pointer_value(0x2000u),
        11, 12, 12, 4, 0, 0, 0, 0, &temporary) == COMMAND_PROVENANCE_CAPTURE_NATIVE_INVALID);
    CHECK(CommandProvenanceCapture(&store, pointer_value(0x1002u), pointer_value(0x2000u),
        11, 99, 12, 4, 0, 0, 0, 1, &temporary) == COMMAND_PROVENANCE_CAPTURE_SENDER_MISMATCH);
    CHECK(CommandProvenanceCapture(&store, pointer_value(0x1003u), pointer_value(0x2000u),
        12, 12, 12, 4, 0x7000u, 0x3000u, 0x4000u, 1, &temporary) ==
        COMMAND_PROVENANCE_CAPTURE_SESSION_MISMATCH);
    CHECK(!CommandProvenanceFind(&store, pointer_value(0x1001u), pointer_value(0x2000u), 11, &found));

    begin("pointer reuse replaces metadata and invalidates prior generation operations", 12);
    CHECK(capture(pointer_value(0x1100u), pointer_value(0x2100u), 12, 31, 41, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 0) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(capture(pointer_value(0x1100u), pointer_value(0x2200u), 12, 32, 42, &replacement) ==
        COMMAND_PROVENANCE_CAPTURE_REPLACED);
    CHECK(replacement.generation != first.generation);
    CHECK(replacement.authenticatedMachineId == 32 && replacement.transportConnection == 42);
    CHECK(!CommandProvenanceFind(&store, first.command, first.vtable, 12, &found));
    CHECK(CommandProvenanceFind(&store, replacement.command, replacement.vtable, 12, &found));
    CHECK(found.generation == replacement.generation && !found.hasCachedDecision);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 1) == COMMAND_PROVENANCE_DECISION_STALE);
    CHECK(!CommandProvenanceRemove(&store, &first));

    begin("cached denial stays stable and native invalidity always forces deny", 13);
    CHECK(capture(pointer_value(0x1200u), pointer_value(0x2200u), 13, 50, 60, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 0) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 1) == COMMAND_PROVENANCE_DECISION_CONFLICT);
    CHECK(CommandProvenanceGetDecision(&store, &first, 1, &allowed) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(allowed == 0);
    allowed = 99;
    CHECK(CommandProvenanceGetDecision(&store, &first, 0, &allowed) ==
        COMMAND_PROVENANCE_DECISION_NATIVE_INVALID);
    CHECK(allowed == 0);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 0, 1) ==
        COMMAND_PROVENANCE_DECISION_NATIVE_INVALID);
    CHECK(CommandProvenanceGetDecision(&store, &first, 1, &allowed) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(allowed == 0);

    begin("cached allow cannot override native rejection and unset decisions stay explicit", 14);
    CHECK(capture(pointer_value(0x1300u), pointer_value(0x2300u), 14, 51, 61, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(CommandProvenanceGetDecision(&store, &first, 1, &allowed) == COMMAND_PROVENANCE_DECISION_UNSET);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 1) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(CommandProvenanceGetDecision(&store, &first, 0, &allowed) ==
        COMMAND_PROVENANCE_DECISION_NATIVE_INVALID);
    CHECK(allowed == 0);
    CHECK(CommandProvenanceGetDecision(&store, &first, 1, &allowed) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(allowed == 1);

    begin("destructor removal requires the exact generation", 15);
    CHECK(capture(pointer_value(0x1400u), pointer_value(0x2400u), 15, 52, 62, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(capture(pointer_value(0x1400u), pointer_value(0x2401u), 15, 53, 63, &replacement) ==
        COMMAND_PROVENANCE_CAPTURE_REPLACED);
    CHECK(!CommandProvenanceRemove(&store, &first));
    CHECK(CommandProvenanceRemove(&store, &replacement));
    CHECK(!CommandProvenanceFind(&store, replacement.command, replacement.vtable, 15, &found));

    begin("session advance preserves queued command provenance until explicit teardown", 16);
    CHECK(capture(pointer_value(0x1500u), pointer_value(0x2500u), 16, 54, 64, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 1) == COMMAND_PROVENANCE_DECISION_OK);
    CHECK(CommandProvenanceAdvanceSession(&store, 17));
    CHECK(!CommandProvenanceAdvanceSession(&store, 16));
    CHECK(CommandProvenanceFind(&store, first.command, first.vtable, 16, &found));
    CHECK(found.sessionEpoch == 16 && found.generation == first.generation);
    CHECK(CommandProvenanceFindAny(&store, first.command, first.vtable, &found));
    CHECK(found.sessionEpoch == 16 && found.generation == first.generation);
    CHECK(CommandProvenanceCapture(&store, pointer_value(0x1501u), pointer_value(0x2500u),
        16, 54, 54, 9, 0x7000u, 0x3000u, 0x4000u, 1, &temporary) ==
        COMMAND_PROVENANCE_CAPTURE_SESSION_MISMATCH);
    allowed = 99;
    CHECK(CommandProvenanceGetDecision(&store, &first, 1, &allowed) == COMMAND_PROVENANCE_DECISION_STALE);
    CHECK(allowed == 0);
    CHECK(CommandProvenanceCommitDecision(&store, &first, 1, 0) == COMMAND_PROVENANCE_DECISION_STALE);
    CHECK(CommandProvenanceFindAny(&store, first.command, first.vtable, &found));
    CHECK(found.sessionEpoch == 16 && found.hasCachedDecision && found.cachedAllows == 1);
    CHECK(capture(pointer_value(0x1501u), pointer_value(0x2500u), 17, 54, 64, &replacement) ==
        COMMAND_PROVENANCE_CAPTURED);
    CHECK(replacement.generation > first.generation);
    CommandProvenanceReset(&store, 18);
    CHECK(!CommandProvenanceFind(&store, first.command, first.vtable, 16, &found));
    CHECK(CommandProvenanceCommitDecision(&store, &replacement, 1, 0) == COMMAND_PROVENANCE_DECISION_STALE);

    begin("low-load timing and lookup statistics", 0);
    {
        LARGE_INTEGER frequency, start, finish;
        uint64_t captureUs, lookupUs;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        for (uintptr_t i = 0; i < 128u; ++i) {
            CHECK(capture(pointer_value(0x100000u + i * 16u), pointer_value(0x3000u),
                0, i + 1u, i + 1u, &temporary) == COMMAND_PROVENANCE_CAPTURED);
        }
        QueryPerformanceCounter(&finish);
        captureUs = elapsed_us(start, finish, frequency);
        QueryPerformanceCounter(&start);
        for (uintptr_t i = 0; i < 128u; ++i) {
            CHECK(CommandProvenanceFind(&store, pointer_value(0x100000u + i * 16u),
                pointer_value(0x3000u), 0, &found));
        }
        QueryPerformanceCounter(&finish);
        lookupUs = elapsed_us(start, finish, frequency);
        printf("Provenance low load: 128 captures %llu us, 128 lookups %llu us\n",
            (unsigned long long)captureUs, (unsigned long long)lookupUs);
        CommandProvenanceGetStats(&store, &stats);
        CHECK(stats.count == 128 && stats.lookupHits == 128 && stats.lookupMisses == 0);
        CHECK(stats.maximumProbes < 16);
    }

    begin("high-load timing, full rejection, replacement at capacity, and backshift deletion", 21);
    {
        LARGE_INTEGER frequency, start, finish;
        uint64_t captureUs, lookupUs;
        const uintptr_t base = (uintptr_t)0x1000000u;
        const void *vtable = pointer_value(0x6000u);
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        for (uintptr_t i = 0; i < COMMAND_PROVENANCE_MAX_LIVE; ++i) {
            CommandProvenanceCaptureResult captureResult = capture(
                pointer_value(base + i * 16u), vtable, 21, i + 1000u, i + 1u, &temporary);
            if (captureResult != COMMAND_PROVENANCE_CAPTURED) {
                case_name = "high-load capacity fill";
                CHECK(captureResult == COMMAND_PROVENANCE_CAPTURED);
            }
        }
        QueryPerformanceCounter(&finish);
        captureUs = elapsed_us(start, finish, frequency);
        QueryPerformanceCounter(&start);
        for (uintptr_t i = 0; i < 4096u; ++i) {
            uintptr_t key = (i * 7u) % COMMAND_PROVENANCE_MAX_LIVE;
            CHECK(CommandProvenanceFind(&store, pointer_value(base + key * 16u), vtable, 21, &found));
        }
        QueryPerformanceCounter(&finish);
        lookupUs = elapsed_us(start, finish, frequency);
        printf("Provenance full load: %u entries captured %llu us, 4096 lookups %llu us\n",
            (unsigned)COMMAND_PROVENANCE_MAX_LIVE,
            (unsigned long long)captureUs, (unsigned long long)lookupUs);
        CommandProvenanceGetStats(&store, &stats);
        CHECK(stats.count == COMMAND_PROVENANCE_MAX_LIVE);
        CHECK(stats.highWaterCount == COMMAND_PROVENANCE_MAX_LIVE);
        CHECK(stats.maximumProbes < 256u);
        printf("Provenance high-load maximum probes: %llu\n",
            (unsigned long long)stats.maximumProbes);
        CHECK(capture(pointer_value(base + (uintptr_t)COMMAND_PROVENANCE_MAX_LIVE * 16u),
            vtable, 21, 999999u, 999999u, &temporary) == COMMAND_PROVENANCE_CAPTURE_FULL);
        CHECK(capture(pointer_value(base), pointer_value(0x6001u), 21, 777u, 777u,
            &replacement) == COMMAND_PROVENANCE_CAPTURE_REPLACED);
        CHECK(CommandProvenanceRemove(&store, &replacement));
        CHECK(!CommandProvenanceFind(&store, replacement.command, replacement.vtable, 21, &found));
        for (uintptr_t i = 1; i < 4096u; ++i) {
            CHECK(CommandProvenanceFind(&store, pointer_value(base + i * 16u),
                vtable, 21, &found));
        }
        CHECK(capture(pointer_value(base + (uintptr_t)COMMAND_PROVENANCE_MAX_LIVE * 16u),
            vtable, 21, 999999u, 999999u, &temporary) == COMMAND_PROVENANCE_CAPTURED);
        CommandProvenanceGetStats(&store, &stats);
        CHECK(stats.count == COMMAND_PROVENANCE_MAX_LIVE && stats.fullFailures == 1);
    }

    begin("parallel capture lookup cache and destruction remain generation safe", 91);
    {
        enum { THREAD_COUNT = 8, ITERATIONS = 1200 };
        WorkerArgs args[THREAD_COUNT];
        HANDLE threads[THREAD_COUNT];
        workerFailures = 0;
        for (uint32_t i = 0; i < THREAD_COUNT; ++i) {
            args[i].worker = i;
            args[i].iterations = ITERATIONS;
            threads[i] = CreateThread(NULL, 0, provenance_worker, &args[i], 0, NULL);
            CHECK(threads[i] != NULL);
        }
        CHECK(WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE) == WAIT_OBJECT_0);
        for (uint32_t i = 0; i < THREAD_COUNT; ++i) CloseHandle(threads[i]);
        CHECK(InterlockedCompareExchange(&workerFailures, 0, 0) == 0);
        CommandProvenanceGetStats(&store, &stats);
        CHECK(stats.count == 0 && stats.captures == THREAD_COUNT * ITERATIONS);
        CHECK(stats.removals == THREAD_COUNT * ITERATIONS);
    }

    begin("statistics saturate instead of wrapping", 0);
    store.stats.captures = UINT64_MAX;
    CHECK(capture(pointer_value(0x1600u), pointer_value(0x2600u), 0, 55, 65, &first) ==
        COMMAND_PROVENANCE_CAPTURED);
    CommandProvenanceGetStats(&store, &stats);
    CHECK(stats.captures == UINT64_MAX);

    printf("PASS %u command provenance assertions\n", assertions);
    return 0;
}
