#ifndef HOI4_AUTHORITY_EQUIPMENT_PAYLOAD_H
#define HOI4_AUTHORITY_EQUIPMENT_PAYLOAD_H

#include "authority_policy.h"

/* Validate the narrow equipment-upgrade payload subset. Actor authorization
 * is handled by the caller. safetyOnly validates structure and references
 * without invoking the game level predicate. */
AuthorityResult AuthorityValidateEquipmentPayload(unsigned char *imageBase,
    void *command, int safetyOnly);

#ifdef AUTHORITY_EQUIPMENT_PAYLOAD_TEST
typedef void *(__fastcall *AuthorityEquipmentResolveRefTestFn)(void *reference);
typedef unsigned char (__fastcall *AuthorityEquipmentLevelAllowedTestFn)(
    void *definition, int32_t *actorTag, uint8_t requested, void *unused, uint32_t flags);
void AuthorityEquipmentPayloadTestSetResolvers(
    AuthorityEquipmentResolveRefTestFn resolveRef,
    AuthorityEquipmentLevelAllowedTestFn levelAllowed);
#endif

#endif
