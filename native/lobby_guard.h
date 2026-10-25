#ifndef HOI4_LOBBY_GUARD_H
#define HOI4_LOBBY_GUARD_H
#include "protocol.h"

typedef void (*LobbyLog)(const char *message);
typedef void (*LobbyPacketCallback)(void *, const void *, uint32_t, uintptr_t, int);
typedef void (*LobbyCommandReceiver)(LobbyPacketCallback, void *, const void *, uint32_t, uintptr_t, int);
/* Set before Start publishes the receive wrapper. The receiver must stay resident. */
int LobbyGuardSetCommandReceiver(LobbyCommandReceiver receiver);
int LobbyGuardStart(const AdmissionConfig *config, volatile LONG *eligible, LobbyLog logger,
    const char *dll_hash, const char *manifest_hash);
// Stop keeps the installed guard resident and denies subsequent joins.
void LobbyGuardStop(void);
DWORD LobbyGuardState(void);
#endif
