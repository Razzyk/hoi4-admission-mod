#ifndef HOI4_CAREER_GUARD_H
#define HOI4_CAREER_GUARD_H
#include <stddef.h>
#include <stdint.h>

/* Native Windows x64 layout, established from the two original callees. */
typedef struct {
    int32_t *data;
    int32_t capacity;
    int32_t count;
    void *allocator;
} CareerArray;
typedef struct {
    int32_t end;
    int32_t begin;
    uint64_t grain;
} CareerRange;
typedef struct {
    unsigned char scheduler_fields[0x18];
    void **state;
    CareerArray *countries;
} CareerCapture;
_Static_assert(offsetof(CareerArray, count) == 0xc, "native count offset");
_Static_assert(offsetof(CareerCapture, state) == 0x18, "native state capture");
_Static_assert(offsetof(CareerCapture, countries) == 0x20, "native array capture");
_Static_assert(sizeof(CareerCapture) == 0x28, "native capture size");
_Static_assert(sizeof(CareerRange) == 16, "native range size");

typedef void (*CareerScheduler)(void *state);
typedef void (*CareerKernel)(CareerCapture *capture, const CareerRange *range);
typedef struct {
    uint32_t duplicates;
    uint32_t unique;
    uint32_t fallback;
} CareerOutcome;

/* Stable order; never modifies or takes ownership of the per-player list. */
static inline int32_t career_unique(const int32_t *input, int32_t count, int32_t *output)
{
    int32_t used = 0;
    for (int32_t i = 0; i < count; ++i) {
        int32_t j = 0;
        while (j < used && output[j] != input[i]) ++j;
        if (j == used) output[used++] = input[i];
    }
    return used;
}

static inline CareerOutcome career_dispatch(void *state, const CareerArray *source,
    CareerScheduler original, CareerKernel kernel, int32_t *scratch, int32_t scratch_count)
{
    CareerOutcome outcome = {0,0,0};
    if (!source || scratch_count < 0 || source->count < 0 || source->count > scratch_count ||
        source->capacity < source->count || (source->count && (!source->data || !scratch))) {
        outcome.fallback = 1;
        original(state);
        return outcome;
    }
    int32_t unique = career_unique(source->data, source->count, scratch);
    outcome.unique = (uint32_t)unique;
    outcome.duplicates = (uint32_t)(source->count - unique);
    if (!outcome.duplicates) {
        original(state);
    } else {
        /* Preserve every per-player operation and its statistics weighting. */
        CareerArray temporary = *source;
        CareerRange range = {source->count,0,1};
        CareerCapture capture = {{0},&state,&temporary};
        /* Native kernel is synchronous and reads only the verified fields. */
        kernel(&capture,&range);
    }
    return outcome;
}
#endif
