#ifndef HOI4_AUTHORITY_EVENT_PAYLOAD_H
#define HOI4_AUTHORITY_EVENT_PAYLOAD_H

#include "authority_policy.h"

/* safetyOnly validates fields that must be safe before native IsValid. Full
 * validation additionally binds the choice to the live pending event and
 * sender's current recipient country; call it at the ordered boundary. */
AuthorityResult AuthorityValidateEventPayload(unsigned char *imageBase,
    void *world, void *command, uint64_t senderMachineId, int safetyOnly);

#ifdef AUTHORITY_EVENT_PAYLOAD_TEST
typedef void *(__fastcall *AuthorityEventResolveRefTestFn)(void *reference);
typedef void *(__fastcall *AuthorityEventResolveEntityTestFn)(void *scope);
typedef unsigned char (__fastcall *AuthorityEventCanonicalEqualTestFn)(const int32_t *left,
    int32_t right);
void AuthorityEventPayloadTestSetResolvers(AuthorityEventResolveRefTestFn eventResolver,
    AuthorityEventResolveEntityTestFn entityResolver,
    AuthorityEventCanonicalEqualTestFn canonicalEqual);
#endif

#endif
