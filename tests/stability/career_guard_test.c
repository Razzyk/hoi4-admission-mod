/* Native deterministic concurrency regression; does not load or launch HOI4. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../native/stability/career_guard.h"

#define MAX_ENTRIES 64
#define TEST_WAIT_MS 5000u

_Static_assert(sizeof(void *) == 8, "tests require Windows x64");
_Static_assert(offsetof(CareerArray, data) == 0, "native array pointer");
_Static_assert(offsetof(CareerArray, capacity) == 8, "native array capacity");
_Static_assert(offsetof(CareerArray, count) == 12, "native array count");
_Static_assert(offsetof(CareerArray, allocator) == 16, "native array allocator");
_Static_assert(sizeof(CareerArray) == 24, "native array size");
_Static_assert(offsetof(CareerRange, end) == 0, "native range end precedes begin");
_Static_assert(offsetof(CareerRange, begin) == 4, "native range begin");
_Static_assert(offsetof(CareerRange, grain) == 8, "native range grain");
_Static_assert(sizeof(CareerRange) == 16, "native range size");
_Static_assert(offsetof(CareerCapture, state) == 0x18, "native capture state");
_Static_assert(offsetof(CareerCapture, countries) == 0x20, "native capture countries");
_Static_assert(sizeof(CareerCapture) == 0x28, "native capture size");

typedef struct {
    CareerArray array;
    CareerArray before_array;
    int32_t values[MAX_ENTRIES];
    int32_t before[MAX_ENTRIES];
    volatile LONG scheduler_calls;
    volatile LONG kernel_calls;
    volatile LONG entries_processed;
    volatile LONG overlap_events;
    volatile LONG errors;
    volatile LONG all_entries_active;
    volatile LONG order_count;
    volatile LONG active_by_country[MAX_ENTRIES];
    volatile LONG64 statistics_weight;
    int32_t order[MAX_ENTRIES];
    HANDLE start_gate;
    HANDLE all_active_gate;
    int concurrent;
    int scheduler_only;
    int expect_full_range;
    int allocator_marker;
} TestState;

typedef struct {
    TestState *state;
    int32_t entry;
} Worker;

static unsigned int assertions;

static void require(int condition, const char *description)
{
    ++assertions;
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", description);
        ExitProcess(1);
    }
}

static void initialize(TestState *state, const int32_t *values, int32_t count)
{
    memset(state, 0, sizeof(*state));
    require(count >= 0 && count <= MAX_ENTRIES, "fixture count in bounds");
    if (count) memcpy(state->values, values, (size_t)count * sizeof(int32_t));
    memcpy(state->before, state->values, sizeof(state->before));
    state->array.data = state->values;
    state->array.count = count;
    state->array.capacity = MAX_ENTRIES;
    state->array.allocator = &state->allocator_marker;
    state->before_array = state->array;
}

static int32_t country_index(const TestState *state, int32_t tag)
{
    for (int32_t i = 0; i < state->array.count; ++i)
        if (state->values[i] == tag) return i;
    return -1;
}

static void native_kernel(CareerCapture *capture, const CareerRange *range)
{
    TestState *state = (TestState *)*capture->state;
    const CareerArray *array = capture->countries;
    int32_t native_range_words[2];
    memcpy(native_range_words, range, sizeof(native_range_words));
    InterlockedIncrement(&state->kernel_calls);
    if (array->data != state->before_array.data || array->capacity != state->before_array.capacity ||
        array->count != state->before_array.count || array->allocator != state->before_array.allocator ||
        range->begin < 0 || range->end < range->begin || range->end > array->count ||
        range->grain != 1 || native_range_words[0] != range->end ||
        native_range_words[1] != range->begin) {
        InterlockedIncrement(&state->errors);
        return;
    }
    if (state->expect_full_range && (range->begin != 0 || range->end != array->count))
        InterlockedIncrement(&state->errors);
    for (size_t i = 0; i < sizeof(capture->scheduler_fields); ++i)
        if (capture->scheduler_fields[i] != 0) InterlockedIncrement(&state->errors);
    for (int32_t i = range->begin; i < range->end; ++i) {
        int32_t tag = array->data[i];
        int32_t index = country_index(state, tag);
        LONG active, order_slot;
        if (index < 0) { InterlockedIncrement(&state->errors); continue; }
        active = InterlockedIncrement(&state->active_by_country[index]);
        if (active > 1) InterlockedIncrement(&state->overlap_events);
        if (state->concurrent) {
            /* Every worker keeps its country active until every entry has started.
               Duplicate baseline overlap is therefore deterministic, not timing luck. */
            if (InterlockedIncrement(&state->all_entries_active) == array->count)
                SetEvent(state->all_active_gate);
            if (WaitForSingleObject(state->all_active_gate, TEST_WAIT_MS) != WAIT_OBJECT_0)
                InterlockedIncrement(&state->errors);
        }
        order_slot = InterlockedIncrement(&state->order_count) - 1;
        if (order_slot < MAX_ENTRIES) state->order[order_slot] = tag;
        else InterlockedIncrement(&state->errors);
        InterlockedAdd64(&state->statistics_weight, (LONG64)tag * 7);
        InterlockedIncrement(&state->entries_processed);
        InterlockedDecrement(&state->active_by_country[index]);
    }
}

static DWORD WINAPI run_entry(void *argument)
{
    Worker *worker = (Worker *)argument;
    TestState *state = worker->state;
    void *opaque = state;
    CareerCapture capture = {{0}, &opaque, &state->array};
    CareerRange range = {worker->entry + 1, worker->entry, 1};
    if (WaitForSingleObject(state->start_gate, TEST_WAIT_MS) != WAIT_OBJECT_0) {
        InterlockedIncrement(&state->errors);
        return 1;
    }
    native_kernel(&capture, &range);
    return 0;
}

static void original_scheduler(void *opaque)
{
    TestState *state = (TestState *)opaque;
    HANDLE threads[MAX_ENTRIES] = {0};
    Worker workers[MAX_ENTRIES];
    int32_t count = state->array.count;
    InterlockedIncrement(&state->scheduler_calls);
    if (state->scheduler_only || count == 0) return;
    require(count > 0 && count <= MAX_ENTRIES, "scheduler fixture count valid");
    state->concurrent = 1;
    state->start_gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    state->all_active_gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(state->start_gate && state->all_active_gate, "create scheduler start gates");
    for (int32_t i = 0; i < count; ++i) {
        workers[i].state = state;
        workers[i].entry = i;
        threads[i] = CreateThread(NULL, 0, run_entry, &workers[i], 0, NULL);
        require(threads[i] != NULL, "create per-entry scheduler worker");
    }
    require(SetEvent(state->start_gate) != 0, "release all scheduler workers together");
    require(WaitForMultipleObjects((DWORD)count, threads, TRUE, TEST_WAIT_MS) == WAIT_OBJECT_0,
            "all scheduler workers complete");
    for (int32_t i = 0; i < count; ++i) {
        DWORD exit_code = 1;
        require(GetExitCodeThread(threads[i], &exit_code) && exit_code == 0, "scheduler worker succeeded");
        CloseHandle(threads[i]);
    }
    CloseHandle(state->start_gate);
    CloseHandle(state->all_active_gate);
    state->start_gate = NULL;
    state->all_active_gate = NULL;
    state->concurrent = 0;
}

static LONG64 expected_weight(const TestState *state)
{
    LONG64 weight = 0;
    for (int32_t i = 0; i < state->array.count; ++i) weight += (LONG64)state->values[i] * 7;
    return weight;
}

static void verify_immutable_and_complete(const TestState *state)
{
    require(state->errors == 0, "native capture and end/begin/grain contract preserved");
    require(state->array.data == state->before_array.data && state->array.count == state->before_array.count &&
            state->array.capacity == state->before_array.capacity && state->array.allocator == state->before_array.allocator,
            "original array fields and ownership remain immutable");
    require(memcmp(state->values, state->before, sizeof(state->before)) == 0, "original source array remains immutable");
    require(state->entries_processed == state->array.count, "every original per-player entry executes once");
    require(state->statistics_weight == expected_weight(state), "original per-player statistics weight preserved");
    for (int32_t i = 0; i < state->array.count; ++i)
        require(state->active_by_country[i] == 0, "no country remains active");
}

static void repeated_country_regression(void)
{
    static const int32_t repeated[] = {3, 9, 3, 11, 9, 3};
    TestState baseline, guarded;
    int32_t scratch[MAX_ENTRIES] = {0};
    CareerOutcome outcome;
    initialize(&baseline, repeated, (int32_t)(sizeof(repeated) / sizeof(repeated[0])));
    original_scheduler(&baseline);
    verify_immutable_and_complete(&baseline);
    require(baseline.scheduler_calls == 1 && baseline.kernel_calls == baseline.array.count,
            "baseline executes original parallel scheduler once");
    require(baseline.overlap_events > 0, "baseline reproduces concurrent same-country entry overlap");
    initialize(&guarded, repeated, baseline.array.count);
    guarded.expect_full_range = 1;
    outcome = career_dispatch(&guarded, &guarded.array, original_scheduler, native_kernel, scratch, MAX_ENTRIES);
    verify_immutable_and_complete(&guarded);
    require(outcome.duplicates == 3 && outcome.unique == 3 && outcome.fallback == 0, "repeated-country detection counts");
    require(guarded.scheduler_calls == 0 && guarded.kernel_calls == 1, "duplicates invoke one synchronous native full-list kernel");
    require(guarded.overlap_events == 0, "serialized guard prevents concurrent same-country overlap");
    require(guarded.order_count == guarded.array.count &&
            memcmp(guarded.order, repeated, sizeof(repeated)) == 0, "serialized path preserves original entry order and repetitions");
    require(guarded.entries_processed == baseline.entries_processed &&
            guarded.statistics_weight == baseline.statistics_weight, "guard preserves baseline entry count and statistics weighting");
    printf("PASS duplicate concurrency regression: baseline overlaps=%ld; guard overlaps=%ld; entries=%ld; weight=%lld\n",
           (long)baseline.overlap_events, (long)guarded.overlap_events, (long)guarded.entries_processed,
           (long long)guarded.statistics_weight);
}

static void unique_pass_through(void)
{
    static const int32_t unique[] = {7, -2, 41, 0};
    TestState state;
    int32_t scratch[MAX_ENTRIES] = {0};
    CareerOutcome outcome;
    initialize(&state, unique, (int32_t)(sizeof(unique) / sizeof(unique[0])));
    outcome = career_dispatch(&state, &state.array, original_scheduler, native_kernel, scratch, MAX_ENTRIES);
    verify_immutable_and_complete(&state);
    require(outcome.duplicates == 0 && outcome.unique == 4 && outcome.fallback == 0, "unique detection outcome");
    require(state.scheduler_calls == 1, "unique source passes through original scheduler exactly once");
    require(state.kernel_calls == state.array.count, "unique path introduces no additional kernel call");
    require(state.overlap_events == 0, "unique scheduler has no same-country overlap");
    printf("PASS unique pass-through: scheduler=%ld; native per-entry kernels=%ld\n", (long)state.scheduler_calls, (long)state.kernel_calls);
}

static void fallback_case(const char *name, const CareerArray *source, int32_t *scratch, int32_t scratch_count)
{
    TestState state;
    CareerOutcome outcome;
    initialize(&state, NULL, 0);
    state.scheduler_only = 1;
    outcome = career_dispatch(&state, source, original_scheduler, native_kernel, scratch, scratch_count);
    require(outcome.fallback == 1 && outcome.duplicates == 0 && outcome.unique == 0, "invalid input returns clean fallback outcome");
    require(state.scheduler_calls == 1 && state.kernel_calls == 0 && state.entries_processed == 0,
            "invalid input calls original once without any partial kernel work");
    require(memcmp(state.values, state.before, sizeof(state.before)) == 0, "fallback leaves source fixture immutable");
    printf("PASS fallback: %s\n", name);
}

static void invalid_and_empty_inputs(void)
{
    int32_t values[] = {5, 5, 9};
    int32_t before[3];
    int32_t scratch[MAX_ENTRIES] = {0};
    CareerArray source = {values, 3, 3, NULL};
    TestState empty;
    CareerOutcome outcome;
    memcpy(before, values, sizeof(values));
    fallback_case("NULL source", NULL, scratch, MAX_ENTRIES);
    source.count = -1;
    fallback_case("negative source count", &source, scratch, MAX_ENTRIES);
    source.count = 3; source.capacity = 2;
    fallback_case("capacity smaller than count", &source, scratch, MAX_ENTRIES);
    source.capacity = 3; source.data = NULL;
    fallback_case("nonempty NULL source data", &source, scratch, MAX_ENTRIES);
    source.data = values;
    fallback_case("nonempty NULL scratch", &source, NULL, MAX_ENTRIES);
    fallback_case("negative scratch limit", &source, scratch, -1);
    fallback_case("source exceeds scratch limit", &source, scratch, 2);
    source.count = MAX_ENTRIES + 1; source.capacity = MAX_ENTRIES + 1;
    fallback_case("oversized source rejected before reading array", &source, scratch, MAX_ENTRIES);
    source.count = 0; source.capacity = -1; source.data = NULL;
    fallback_case("negative empty-array capacity", &source, scratch, MAX_ENTRIES);
    require(memcmp(before, values, sizeof(values)) == 0, "all invalid-source cases preserve their original input");
    initialize(&empty, NULL, 0);
    empty.array.data = NULL;
    outcome = career_dispatch(&empty, &empty.array, original_scheduler, native_kernel, NULL, 0);
    require(outcome.fallback == 0 && outcome.duplicates == 0 && outcome.unique == 0, "valid empty array outcome");
    require(empty.scheduler_calls == 1 && empty.kernel_calls == 0, "empty array passes through exactly once");
    printf("PASS valid empty-array pass-through\n");
}

static void all_same_country(void)
{
    static const int32_t values[] = {19, 19, 19, 19, 19};
    TestState state;
    int32_t scratch[MAX_ENTRIES] = {0};
    CareerOutcome outcome;
    initialize(&state, values, 5);
    state.expect_full_range = 1;
    outcome = career_dispatch(&state, &state.array, original_scheduler, native_kernel, scratch, MAX_ENTRIES);
    verify_immutable_and_complete(&state);
    require(outcome.unique == 1 && outcome.duplicates == 4 && outcome.fallback == 0, "all-same-country detection");
    require(state.scheduler_calls == 0 && state.kernel_calls == 1 && state.overlap_events == 0,
            "all-same-country source uses one synchronous kernel");
    require(memcmp(state.order, values, sizeof(values)) == 0, "all same-country per-player entries preserved in order");
    printf("PASS all-same-country weighting and order\n");
}

int main(void)
{
    repeated_country_regression();
    unique_pass_through();
    all_same_country();
    invalid_and_empty_inputs();
    printf("All %u assertions passed. Native tests use authored fixtures; no HOI4 process was launched.\n", assertions);
    return 0;
}
