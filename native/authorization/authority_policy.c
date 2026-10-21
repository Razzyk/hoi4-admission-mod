#include "authority_policy.h"

static AuthorityResult result(AuthorityDecision decision, AuthorityReason reason) {
    AuthorityResult value;
    value.decision = decision;
    value.reason = reason;
    value.usedGrantKind = 0;
    return value;
}

static int peer_equal(AuthorityPeerIdentity left, AuthorityPeerIdentity right) {
    return left.machineId == right.machineId && left.generation == right.generation;
}

static int grant_equal(const AuthorityGrant *left, const AuthorityGrant *right) {
    return left->grantId == right->grantId && left->sessionEpoch == right->sessionEpoch &&
        peer_equal(left->peer, right->peer) &&
        left->sourceCountry == right->sourceCountry &&
        left->destinationCountry == right->destinationCountry &&
        left->expiresAt == right->expiresAt && left->kind == right->kind &&
        left->allowOccupiedDestination == right->allowOccupiedDestination &&
        peer_equal(left->executor, right->executor) &&
        peer_equal(left->approver, right->approver) &&
        left->authorityCountry == right->authorityCountry;
}

static int grant_is_expired(const AuthorityGrant *grant, uint64_t now) {
    return grant->expiresAt != 0 && now >= grant->expiresAt;
}

static void prune_locked(AuthorityPolicy *policy, uint64_t now, uint64_t sessionEpoch,
    uint64_t peerMachineId, uint32_t peerGeneration) {
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        if (!slot->occupied) continue;
        if (slot->grant.sessionEpoch != sessionEpoch || grant_is_expired(&slot->grant, now) ||
            (peerMachineId != 0 && slot->grant.peer.machineId == peerMachineId &&
             slot->grant.peer.generation != peerGeneration)) {
            slot->occupied = 0;
        }
    }
}

void AuthorityPolicyInit(AuthorityPolicy *policy, uint64_t sessionEpoch) {
    if (!policy) return;
    InitializeSRWLock(&policy->lock);
    policy->sessionEpoch = sessionEpoch;
    policy->highestGrantId = 0;
    memset(policy->grants, 0, sizeof(policy->grants));
}

void AuthorityPolicyReset(AuthorityPolicy *policy, uint64_t newSessionEpoch) {
    if (!policy) return;
    AcquireSRWLockExclusive(&policy->lock);
    memset(policy->grants, 0, sizeof(policy->grants));
    policy->sessionEpoch = newSessionEpoch;
    policy->highestGrantId = 0;
    ReleaseSRWLockExclusive(&policy->lock);
}

AuthorityReason AuthorityPolicyGrantTrusted(AuthorityPolicy *policy,
    const AuthorityGrant *grant, uint64_t now, uint64_t currentSessionEpoch) {
    if (!policy || !grant || grant->grantId == 0 ||
        grant->sessionEpoch != currentSessionEpoch ||
        grant->peer.machineId == 0 || grant->peer.generation == 0 ||
        grant->sourceCountry == AUTHORITY_COUNTRY_UNKNOWN ||
        grant->destinationCountry == AUTHORITY_COUNTRY_UNKNOWN ||
        (grant->kind != AUTHORITY_GRANT_COOP && grant->kind != AUTHORITY_GRANT_SCRIPT &&
         grant->kind != AUTHORITY_GRANT_HOST) || grant_is_expired(grant, now)) {
        return AUTHORITY_REASON_GRANT_INVALID;
    }
    if ((grant->executor.machineId == 0) != (grant->executor.generation == 0))
        return AUTHORITY_REASON_GRANT_INVALID;
    if (grant->approver.machineId != 0 && grant->approver.generation == 0)
        return AUTHORITY_REASON_GRANT_INVALID;
    if (grant->kind == AUTHORITY_GRANT_COOP && grant->approver.machineId == 0 &&
        grant->authorityCountry == AUTHORITY_COUNTRY_UNKNOWN) {
        return AUTHORITY_REASON_GRANT_INVALID;
    }

    AcquireSRWLockExclusive(&policy->lock);
    if (policy->sessionEpoch != currentSessionEpoch) {
        ReleaseSRWLockExclusive(&policy->lock);
        return AUTHORITY_REASON_SESSION_MISMATCH;
    }
    prune_locked(policy, now, currentSessionEpoch, 0, 0);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        if (policy->grants[i].occupied) {
            if (grant_equal(&policy->grants[i].grant, grant)) {
                ReleaseSRWLockExclusive(&policy->lock);
                return AUTHORITY_REASON_NONE;
            }
        }
    }
    if (grant->grantId <= policy->highestGrantId) {
        ReleaseSRWLockExclusive(&policy->lock);
        return AUTHORITY_REASON_GRANT_INVALID;
    }
    /* A repeated accepted request supersedes its still-pending authorization
     * instead of consuming another bounded slot. */
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        AuthorityGrant *old = &slot->grant;
        int same_pending_coop = grant->kind == AUTHORITY_GRANT_COOP &&
            old->kind == AUTHORITY_GRANT_COOP && old->peer.machineId == grant->peer.machineId &&
            old->peer.generation == grant->peer.generation;
        int same_exact_request = grant->kind != AUTHORITY_GRANT_COOP &&
            old->sessionEpoch == grant->sessionEpoch && old->kind == grant->kind &&
            old->peer.machineId == grant->peer.machineId && old->peer.generation == grant->peer.generation &&
            old->sourceCountry == grant->sourceCountry && old->destinationCountry == grant->destinationCountry;
        if (slot->occupied && (same_pending_coop || same_exact_request)) {
            slot->grant = *grant;
            policy->highestGrantId = grant->grantId;
            ReleaseSRWLockExclusive(&policy->lock);
            return AUTHORITY_REASON_NONE;
        }
    }
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        if (policy->grants[i].occupied) continue;
        policy->grants[i].grant = *grant;
        policy->grants[i].occupied = 1;
        policy->highestGrantId = grant->grantId;
        ReleaseSRWLockExclusive(&policy->lock);
        return AUTHORITY_REASON_NONE;
    }
    ReleaseSRWLockExclusive(&policy->lock);
    return AUTHORITY_REASON_GRANT_CAPACITY;
}

void AuthorityPolicyPrunePeer(AuthorityPolicy *policy, uint64_t machineId,
    uint32_t currentGeneration) {
    if (!policy || machineId == 0) return;
    AcquireSRWLockExclusive(&policy->lock);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        if (slot->occupied && slot->grant.peer.machineId == machineId &&
            slot->grant.peer.generation != currentGeneration) {
            slot->occupied = 0;
        } else if (slot->occupied && slot->grant.kind == AUTHORITY_GRANT_COOP &&
            slot->grant.approver.machineId == machineId &&
            slot->grant.approver.generation != currentGeneration) {
            slot->occupied = 0;
        }
    }
    ReleaseSRWLockExclusive(&policy->lock);
}

void AuthorityPolicyRevokeAffectedPeer(AuthorityPolicy *policy, uint64_t machineId) {
    if (!policy || !machineId) return;
    AcquireSRWLockExclusive(&policy->lock);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        if (slot->occupied && slot->grant.peer.machineId == machineId)
            memset(slot, 0, sizeof(*slot));
    }
    ReleaseSRWLockExclusive(&policy->lock);
}

void AuthorityPolicyRebaseScriptGrants(AuthorityPolicy *policy, uint64_t machineId,
    uint32_t generation, int32_t oldSourceCountry, int32_t newSourceCountry) {
    if (!policy || machineId == 0 || generation == 0 ||
        oldSourceCountry == AUTHORITY_COUNTRY_UNKNOWN ||
        newSourceCountry == AUTHORITY_COUNTRY_UNKNOWN || oldSourceCountry == newSourceCountry) return;
    AcquireSRWLockExclusive(&policy->lock);
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        AuthorityGrant *grant = &slot->grant;
        if (!slot->occupied || grant->peer.machineId != machineId || grant->peer.generation != generation)
            continue;
        if (grant->kind == AUTHORITY_GRANT_SCRIPT && grant->sourceCountry == oldSourceCountry)
            grant->sourceCountry = newSourceCountry;
        else
            slot->occupied = 0;
    }
    ReleaseSRWLockExclusive(&policy->lock);
}

static int coop_approver_matches(const AuthorityGrant *grant, const AuthorityFacts *facts) {
    if (facts->currentAuthorityKnown != AUTHORITY_TRUTH_TRUE ||
        facts->currentAuthorityAuthorizedForGrant != AUTHORITY_TRUTH_TRUE) return 0;
    if (grant->approver.machineId != 0) {
        return peer_equal(grant->approver, facts->currentAuthority);
    }
    /* For country-scoped approvals, the adapter has already checked current
       canonical country control and leader authority against authorityCountry.
       Raw tag equality would reject dynamic aliases after canonical retagging. */
    return grant->authorityCountry != AUTHORITY_COUNTRY_UNKNOWN;
}

static AuthorityResult country_change(AuthorityPolicy *policy,
    const AuthorityFacts *facts, uint64_t now) {
    if (facts->sourceCountry == AUTHORITY_COUNTRY_UNKNOWN ||
        facts->destinationCountry == AUTHORITY_COUNTRY_UNKNOWN ||
        facts->requester.machineId == 0 || facts->requester.generation == 0) {
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    }
    int same_canonical = facts->sourceCountry == facts->destinationCountry ||
        facts->sourceDestinationCanonicalEqual == AUTHORITY_TRUTH_TRUE;
    if (!same_canonical &&
        facts->assignmentLockEnabled == AUTHORITY_TRUTH_UNKNOWN)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (facts->affectedPeerControlsSource == AUTHORITY_TRUTH_UNKNOWN)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (facts->affectedPeerControlsSource == AUTHORITY_TRUTH_FALSE) {
        for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
            AuthorityGrantSlot *slot = &policy->grants[i];
            if (slot->occupied && peer_equal(slot->grant.peer, facts->requester))
                slot->occupied = 0;
        }
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);
    }

    /* Grants bind to the affected/requesting peer, which may differ from the executor. */
    AuthorityGrantSlot *match = NULL;
    int coop_authority_unknown = 0;
    int occupancy_unknown = 0;
    for (size_t i = 0; i < AUTHORITY_POLICY_MAX_GRANTS; ++i) {
        AuthorityGrantSlot *slot = &policy->grants[i];
        const AuthorityGrant *grant;
        if (!slot->occupied) continue;
        grant = &slot->grant;
        if (grant->sessionEpoch != facts->sessionEpoch ||
            !peer_equal(grant->peer, facts->requester) ||
            grant->sourceCountry != facts->sourceCountry ||
            grant->destinationCountry != facts->destinationCountry || grant_is_expired(grant, now)) continue;
        if (grant->kind == AUTHORITY_GRANT_COOP) {
            if (facts->currentAuthorityKnown != AUTHORITY_TRUTH_TRUE ||
                facts->currentAuthorityAuthorizedForGrant == AUTHORITY_TRUTH_UNKNOWN) {
                coop_authority_unknown = 1;
                continue;
            }
            if (!peer_equal(facts->sender, facts->currentAuthority)) continue;
            if (!coop_approver_matches(grant, facts)) continue;
        } else {
            if (grant->executor.machineId != 0) {
                if (!peer_equal(grant->executor, facts->sender)) continue;
            } else if (!peer_equal(facts->requester, facts->sender)) {
                continue;
            }
        }
        if (grant->kind != AUTHORITY_GRANT_COOP && !grant->allowOccupiedDestination) {
            if (facts->destinationHumanControlled == AUTHORITY_TRUTH_TRUE) continue;
            if (facts->destinationHumanControlled == AUTHORITY_TRUTH_UNKNOWN) {
                occupancy_unknown = 1;
                continue;
            }
        }
        match = slot;
        break;
    }
    if (match) {
        AuthorityResult allowed = result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
        allowed.usedGrantKind = match->grant.kind;
        if (facts->commit) match->occupied = 0;
        return allowed;
    }
    if (coop_authority_unknown || occupancy_unknown)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);

    if (!peer_equal(facts->requester, facts->sender) ||
        facts->actorControlledBySender == AUTHORITY_TRUTH_FALSE) {
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);
    }
    if (facts->actorControlledBySender != AUTHORITY_TRUTH_TRUE)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (facts->destinationCountry == AUTHORITY_COUNTRY_OBSERVER)
        return result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
    if (same_canonical)
        return result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
    if (facts->assignmentLockEnabled == AUTHORITY_TRUTH_TRUE)
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ASSIGNMENT_LOCKED);
    if (facts->destinationNativeAvailable == AUTHORITY_TRUTH_FALSE ||
        facts->destinationUnoccupied == AUTHORITY_TRUTH_FALSE) {
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_COUNTRY_CHANGE_UNAUTHORIZED);
    }
    if (facts->destinationNativeAvailable == AUTHORITY_TRUTH_TRUE &&
        facts->destinationUnoccupied == AUTHORITY_TRUTH_TRUE) {
        return result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
    }
    return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
}

AuthorityResult AuthorityPolicyEvaluate(AuthorityPolicy *policy,
    const AuthorityFacts *facts, uint64_t now) {
    AuthorityResult decision;
    if (!policy || !facts) return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (!facts->nativeValid) return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_NATIVE_INVALID);
    if (facts->origin == AUTHORITY_ORIGIN_UNKNOWN)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (facts->origin == AUTHORITY_ORIGIN_HOST_LOCAL || facts->origin == AUTHORITY_ORIGIN_AI)
        return result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
    if (facts->origin != AUTHORITY_ORIGIN_REMOTE)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    if (facts->peerStatus == AUTHORITY_PEER_INVALID)
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_PEER_INVALID);
    if (facts->peerStatus != AUTHORITY_PEER_VALID || facts->sender.machineId == 0 ||
        facts->sender.generation == 0)
        return result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
    AcquireSRWLockExclusive(&policy->lock);
    if (facts->sessionEpoch != policy->sessionEpoch) {
        ReleaseSRWLockExclusive(&policy->lock);
        return result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_SESSION_MISMATCH);
    }
    prune_locked(policy, now, policy->sessionEpoch, facts->sender.machineId,
        facts->sender.generation);
    if (facts->requester.machineId != 0 && facts->requester.generation != 0 &&
        !peer_equal(facts->requester, facts->sender)) {
        prune_locked(policy, now, policy->sessionEpoch, facts->requester.machineId,
            facts->requester.generation);
    }

    switch (facts->command) {
        case AUTHORITY_COMMAND_UNREVIEWED:
            decision = result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_UNREVIEWED);
            break;
        case AUTHORITY_COMMAND_COUNTRY_ACTOR:
            if (facts->actorControlledBySender == AUTHORITY_TRUTH_TRUE)
                decision = result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
            else if (facts->actorControlledBySender == AUTHORITY_TRUTH_FALSE)
                decision = result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);
            else decision = result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
            break;
        case AUTHORITY_COMMAND_COUNTRY_CHANGE:
            decision = country_change(policy, facts, now);
            break;
        case AUTHORITY_COMMAND_COOP_REQUEST:
            if (facts->requester.machineId == 0 || facts->requester.generation == 0)
                decision = result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
            else if (peer_equal(facts->requester, facts->sender))
                decision = result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
            else decision = result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_REQUESTER_MISMATCH);
            break;
        case AUTHORITY_COMMAND_HOST_ONLY:
            if (facts->nativeClassKnown != AUTHORITY_TRUTH_TRUE ||
                facts->nativeClassHostOnly == AUTHORITY_TRUTH_UNKNOWN) {
                decision = result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN);
            } else if (facts->nativeClassHostOnly == AUTHORITY_TRUTH_TRUE) {
                decision = result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_HOST_ONLY_REMOTE);
            } else decision = result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
            break;
        default:
            decision = result(AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_UNREVIEWED);
            break;
    }
    ReleaseSRWLockExclusive(&policy->lock);
    return decision;
}
