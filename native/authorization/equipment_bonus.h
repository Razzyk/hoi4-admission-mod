#ifndef HOI4_AUTHORITY_EQUIPMENT_BONUS_H
#define HOI4_AUTHORITY_EQUIPMENT_BONUS_H

#include "authority_policy.h"

/* Canonicalize serialized MIO trait bonuses at the ordered host boundary,
 * after actor authorization and before native IsValid/broadcast. */
AuthorityResult AuthorityCanonicalizeEquipmentBonus(unsigned char *imageBase,
    void *command);

/* Read-only ingress check for serialized MIO references and bonus storage. */
AuthorityResult AuthorityValidateEquipmentBonusReferences(unsigned char *imageBase,
    void *command);

#ifdef AUTHORITY_EQUIPMENT_BONUS_TEST
typedef void *(__fastcall *AuthorityEquipmentBonusResolveTestFn)(void *reference);
typedef void *(__fastcall *AuthorityEquipmentBonusQueryTestFn)(
    void *mio, void *output, void *equipmentType);
typedef void (__fastcall *AuthorityEquipmentBonusCopyTestFn)(void *destination, void *source);
typedef void (__fastcall *AuthorityEquipmentBonusDestroyTestFn)(void *object, uint32_t flags);
void AuthorityEquipmentBonusTestSetResolvers(
    AuthorityEquipmentBonusResolveTestFn resolveRef,
    AuthorityEquipmentBonusQueryTestFn query,
    AuthorityEquipmentBonusCopyTestFn copy,
    AuthorityEquipmentBonusDestroyTestFn destroy);
#endif

#endif
