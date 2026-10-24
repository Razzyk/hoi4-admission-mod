#ifndef HOI4_AUTHORITY_FACTORY_PAYLOAD_H
#define HOI4_AUTHORITY_FACTORY_PAYLOAD_H

#include "authority_policy.h"

/* Validate remote add-factories commands against the native production lines.
 * safetyOnly performs all command/reference/vector/type checks before the
 * original native validity predicate. Full mode also checks sender ownership
 * and each requested + delta value against the native line maximum. */
AuthorityResult AuthorityValidateFactoryPayload(unsigned char *imageBase,
    void *world, void *command, uint64_t senderMachineId,
    uint32_t commandVtableRva, int safetyOnly);

#ifdef AUTHORITY_FACTORY_PAYLOAD_TEST
typedef void *(__fastcall *AuthorityFactoryResolveRefTestFn)(void *reference);
typedef unsigned char (__fastcall *AuthorityFactoryCanonicalEqualTestFn)(const int32_t *left,
    int32_t right);
typedef int32_t (__fastcall *AuthorityFactoryMaxTestFn)(void *line);
void AuthorityFactoryPayloadTestSetResolvers(AuthorityFactoryResolveRefTestFn resolveRef,
    AuthorityFactoryCanonicalEqualTestFn canonicalEqual,
    AuthorityFactoryMaxTestFn maxFactories);
#endif

#endif
