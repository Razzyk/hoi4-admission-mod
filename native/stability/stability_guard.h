#ifndef HOI4_STABILITY_GUARD_API_H
#define HOI4_STABILITY_GUARD_API_H
#include <windows.h>
#include <stdint.h>

typedef void (*StabilityGuardLogger)(const char *message);
typedef struct {
    uint32_t size;
    uint32_t version;
    uint32_t installed;
    uint32_t reserved;
    LONG64 calls;
    LONG64 serialized_days;
    LONG64 duplicate_entries_detected;
    LONG64 rejected_inputs;
} StabilityGuardStats;

/* Invoke from Admission's startup worker, never from DllMain. */
DWORD StabilityGuardStart(HMODULE module, StabilityGuardLogger logger);
int StabilityGuardInstalled(void);
/* False only when a failed thaw left a live target thread paused. */
int StabilityGuardSafeToLog(void);
DWORD StabilityGuardVerify(void);
DWORD StabilityGuardGetStats(StabilityGuardStats *destination);

/* These entry points are deliberately absent from production builds. */
#ifdef STABILITY_GUARD_DIAGNOSTICS
DWORD StabilityGuardExercise(void);
DWORD StabilityGuardUninstall(void);
#endif
#endif
