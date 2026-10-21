#ifndef HOI4_AUTHORITY_POLICY_H
#define HOI4_AUTHORITY_POLICY_H

#include "../protocol.h"

#define AUTHORITY_POLICY_MAX_GRANTS 128u
/* Adapter maps HOI4's native observer target to this policy sentinel. */
#define AUTHORITY_COUNTRY_OBSERVER INT32_MIN
#define AUTHORITY_COUNTRY_UNKNOWN (INT32_MIN + 1)

typedef enum AuthorityOrigin {
    AUTHORITY_ORIGIN_UNKNOWN = 0,
    AUTHORITY_ORIGIN_REMOTE = 1,
    AUTHORITY_ORIGIN_HOST_LOCAL = 2,
    AUTHORITY_ORIGIN_AI = 3
} AuthorityOrigin;

typedef enum AuthorityCommandKind {
    AUTHORITY_COMMAND_UNREVIEWED = 0,
    AUTHORITY_COMMAND_COUNTRY_ACTOR = 1,
    AUTHORITY_COMMAND_COUNTRY_CHANGE = 2,
    AUTHORITY_COMMAND_COOP_REQUEST = 3,
    AUTHORITY_COMMAND_HOST_ONLY = 4
} AuthorityCommandKind;

typedef enum AuthorityTruth {
    AUTHORITY_TRUTH_UNKNOWN = 0,
    AUTHORITY_TRUTH_FALSE = 1,
    AUTHORITY_TRUTH_TRUE = 2
} AuthorityTruth;

typedef enum AuthorityPeerStatus {
    AUTHORITY_PEER_UNKNOWN = 0,
    AUTHORITY_PEER_VALID = 1,
    AUTHORITY_PEER_INVALID = 2
} AuthorityPeerStatus;

typedef enum AuthorityGrantKind {
    AUTHORITY_GRANT_COOP = 1,
    AUTHORITY_GRANT_SCRIPT = 2,
    AUTHORITY_GRANT_HOST = 3
} AuthorityGrantKind;

typedef enum AuthorityDecision {
    AUTHORITY_DECISION_DENY = 0,
    AUTHORITY_DECISION_ALLOW = 1,
    AUTHORITY_DECISION_DEFER = 2
} AuthorityDecision;

typedef enum AuthorityReason {
    AUTHORITY_REASON_NONE = 0,
    AUTHORITY_REASON_NATIVE_INVALID,
    AUTHORITY_REASON_FACTS_UNKNOWN,
    AUTHORITY_REASON_PEER_INVALID,
    AUTHORITY_REASON_SESSION_MISMATCH,
    AUTHORITY_REASON_UNREVIEWED,
    AUTHORITY_REASON_ACTOR_NOT_CONTROLLED,
    AUTHORITY_REASON_REQUESTER_MISMATCH,
    AUTHORITY_REASON_HOST_ONLY_REMOTE,
    AUTHORITY_REASON_COUNTRY_CHANGE_UNAUTHORIZED,
    AUTHORITY_REASON_ASSIGNMENT_LOCKED,
    AUTHORITY_REASON_GRANT_USED,
    AUTHORITY_REASON_GRANT_CAPACITY,
    AUTHORITY_REASON_GRANT_INVALID,
    AUTHORITY_REASON_EQUIPMENT_LEVEL_INVALID
} AuthorityReason;

typedef struct AuthorityPeerIdentity {
    uint64_t machineId;
    uint32_t generation;
} AuthorityPeerIdentity;

typedef struct AuthorityGrant {
    uint64_t grantId; /* Trusted adapter's monotonic, session-scoped issuance sequence. */
    uint64_t sessionEpoch;
    AuthorityPeerIdentity peer;
    int32_t sourceCountry;
    int32_t destinationCountry;
    uint64_t expiresAt; /* 0 means no time expiry; epochs and roles still apply. */
    AuthorityGrantKind kind;
    uint8_t allowOccupiedDestination; /* Trusted host execution fact; never populated from a client request. */
    AuthorityPeerIdentity executor; /* Optional trusted delegate; zero requires executor == affected peer. */
    AuthorityPeerIdentity approver;
    int32_t authorityCountry;
} AuthorityGrant;

typedef struct AuthorityGrantSlot {
    AuthorityGrant grant;
    uint8_t occupied;
} AuthorityGrantSlot;

typedef struct AuthorityPolicy {
    SRWLOCK lock;
    uint64_t sessionEpoch;
    uint64_t highestGrantId;
    AuthorityGrantSlot grants[AUTHORITY_POLICY_MAX_GRANTS];
} AuthorityPolicy;

typedef struct AuthorityFacts {
    AuthorityOrigin origin;
    AuthorityCommandKind command;
    uint64_t sessionEpoch;
    AuthorityPeerStatus peerStatus;
    AuthorityPeerIdentity sender;
    int nativeValid;
    int commit; /* Consume an exact one-use grant only for an accepted original execution. */

    AuthorityTruth actorControlledBySender;
    AuthorityTruth affectedPeerControlsSource;
    int32_t sourceCountry;
    int32_t destinationCountry;
    AuthorityTruth assignmentLockEnabled;
    AuthorityTruth destinationNativeAvailable;
    AuthorityTruth destinationUnoccupied;
    AuthorityTruth destinationHumanControlled;
    AuthorityTruth sourceDestinationCanonicalEqual;

    AuthorityPeerIdentity requester;
    AuthorityTruth nativeClassKnown;
    AuthorityTruth nativeClassHostOnly;

    /* Host-resolved current authority identity used to revalidate coop approvals. */
    AuthorityTruth currentAuthorityKnown;
    AuthorityPeerIdentity currentAuthority;
    int32_t currentAuthorityCountry;
    AuthorityTruth currentAuthorityAuthorizedForGrant;
} AuthorityFacts;

typedef struct AuthorityResult {
    AuthorityDecision decision;
    AuthorityReason reason;
    AuthorityGrantKind usedGrantKind; /* Set only when this decision matched a trusted grant. */
} AuthorityResult;

/* Call during host policy lifecycle. Reset intentionally clears every grant. */
void AuthorityPolicyInit(AuthorityPolicy *policy, uint64_t sessionEpoch);
void AuthorityPolicyReset(AuthorityPolicy *policy, uint64_t newSessionEpoch);

/* Trusted host adapter only: call after validating a canonical host execution. */
AuthorityReason AuthorityPolicyGrantTrusted(AuthorityPolicy *policy,
    const AuthorityGrant *grant, uint64_t now, uint64_t currentSessionEpoch);

/* Call when host peer tracking observes a generation replacement/removal. */
void AuthorityPolicyPrunePeer(AuthorityPolicy *policy, uint64_t machineId,
    uint32_t currentGeneration);
/* Revoke pending approvals/grants for one affected human after its canonical
 * assignment actually changes, including transitions that used no grant. */
void AuthorityPolicyRevokeAffectedPeer(AuthorityPolicy *policy, uint64_t machineId);
/* Preserve later native SCRIPT transitions in an ordered A->B, A->C batch by
 * rebasing the latter to B only after the first SCRIPT grant was consumed. */
void AuthorityPolicyRebaseScriptGrants(AuthorityPolicy *policy, uint64_t machineId,
    uint32_t generation, int32_t oldSourceCountry, int32_t newSourceCountry);

/* Native permission must be evaluated first and supplied as nativeValid. */
AuthorityResult AuthorityPolicyEvaluate(AuthorityPolicy *policy,
    const AuthorityFacts *facts, uint64_t now);

#endif
