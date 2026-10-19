#ifndef HOI4_LOBBY_GUARD_H
#define HOI4_LOBBY_GUARD_H
#include "protocol.h"

typedef void (*LobbyLog)(const char *message);
int LobbyGuardStart(const AdmissionConfig *config, volatile LONG *eligible, LobbyLog logger,
    const char *dll_hash, const char *manifest_hash);
// Stop keeps the installed guard resident and denies subsequent joins.
void LobbyGuardStop(void);
DWORD LobbyGuardState(void);
#endif
