#include "authority_guard.h"
#include "authority_policy.h"
#include "command_provenance.h"
#include "event_payload.h"
#include "factory_payload.h"
#include "equipment_payload.h"
#include "equipment_bonus.h"
#include "../vtable_hook.h"
#if defined(_MSC_VER)
#include <intrin.h>
#define AUTH_RETURN_ADDRESS() _ReturnAddress()
#else
#define AUTH_RETURN_ADDRESS() __builtin_return_address(0)
#endif

#if !defined(_WIN64)
#error AuthorityGuard requires Windows x64.
#endif

#define AUTH_MAX_HOOKS 16u
#define AUTH_MAX_PEERS 256u
#define AUTH_EPOCH_INITIAL 1u
#define AUTH_OBSERVER_NATIVE 0
#define AUTH_HOST_LOCAL_GENERATION UINT32_MAX

enum AuthorityStatIndex {
    STAT_RECEIVE_CALLBACKS, STAT_RECEIVE_SCOPES, STAT_NATIVE_VALID,
    STAT_NATIVE_INVALID, STAT_POLICY_ALLOWS, STAT_POLICY_DENIES,
    STAT_POLICY_DEFERS, STAT_PROVENANCE_MISSES, STAT_PROVENANCE_FULL,
    STAT_STALE_EPOCHS, STAT_STALE_PEERS, STAT_LOAD_REFUSALS,
    STAT_GRANT_ISSUES, STAT_GRANT_ISSUE_REFUSALS, STAT_INSTALL_FAILURES,
    STAT_VERIFY_FAILURES
};

typedef unsigned char u8;
typedef unsigned char (__fastcall *IsValidFn)(void *, void *);
typedef void *(__fastcall *DestructorFn)(void *, unsigned int);
typedef unsigned char (__fastcall *LoggableFn)(void *);
typedef uint64_t (__fastcall *SenderResolverFn)(void *, uintptr_t);
typedef void *(__fastcall *LoadTaskFn)(void *);
typedef void (__fastcall *ExecuteFn)(void *);
typedef void *(__fastcall *ScriptGetterFn)(void *, int32_t *, void *);
typedef void (__fastcall *PacketCallback)(void *, const void *, uint32_t, uintptr_t, int);

typedef struct CoveredClass {
    uint32_t vtableRva, dtorRva, validRva, logRva;
    uint32_t executeRva;
    uint32_t actorOffset;
    AuthorityCommandKind kind;
    const char *dtorBytes, *validBytes, *logBytes, *executeBytes;
    IsValidFn originalValid;
    DestructorFn originalDestructor;
    LoggableFn originalLoggable;
    ExecuteFn originalExecute;
} CoveredClass;

/* Rows and entry fingerprints are extracted from the SHA-pinned 1.19.3
 * image's virtual-method inventory. The adapter only covers these exact classes. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
static CoveredClass classes[] = {
    {0x2994770,0xdb4580,0x11616f0,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d053bcf9601","48895c241048896c2418565741564883","32c0c3cccccccccccccccccccccccccc"},
    {0x2993708,0xdb45f0,0x11622f0,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05cbce9601","48895c241048896c2418488974242057","32c0c3cccccccccccccccccccccccccc"},
    {0x29937d0,0x11490f0,0x1162260,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"48895c24084889742410574883ec20","48895c24084889742410574883ec2083","32c0c3cccccccccccccccccccccccccc"},
    {0x2995328,0xdb45f0,0x1161ac0,0x11d220,0,0x28,AUTHORITY_COMMAND_IDEA_MUTATION,"40534883ec20488d05cbce9601","40574883ec20803d5c0a2f0200488bf9","32c0c3cccccccccccccccccccccccccc"},
    {0x2995648,0xdb45f0,0x1165950,0x11d220,0,0x28,AUTHORITY_COMMAND_IDEA_MUTATION,"40534883ec20488d05cbce9601","40574883ec20803dcccb2e0200488bf9","32c0c3cccccccccccccccccccccccccc"},
    {0x29958a0,0xdb4520,0x1165bf0,0x11d220,0,0x28,AUTHORITY_COMMAND_IDEA_MUTATION,"40534883ec20488d059bcf9601","48895c24104889742420574883ec2083","32c0c3cccccccccccccccccccccccccc"},
    {0x2994f40,0xdb45f0,0x1166bc0,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05cbce9601","48895c24104889742420574883ec2048","32c0c3cccccccccccccccccccccccccc"},
    {0x2995008,0xdb45f0,0x1167fd0,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05cbce9601","48895c24104889742420574883ec2048","32c0c3cccccccccccccccccccccccccc"},
    {0x2996458,0xdb4550,0x1166830,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d056bcf9601","48895c24084889742410574883ec4048","32c0c3cccccccccccccccccccccccccc"},
    {0x2996908,0xdb4550,0x1165f10,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d056bcf9601","48895c2408574881ecf0000000488bd9","32c0c3cccccccccccccccccccccccccc"},
    {0x29969d0,0xdb45f0,0x1166030,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05cbce9601","48895c241048896c2418488974242057","32c0c3cccccccccccccccccccccccccc"},
    {0x2a240c0,0x19a1de0,0x19a5af0,0x11d220,0,0x30,AUTHORITY_COMMAND_COUNTRY_ACTOR,"48895c240848896c2410488974241857","48895c24104889742418574883ec2048","32c0c3cccccccccccccccccccccccccc"},
    {0x2a24188,0x19a2150,0x19a5e20,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"48895c240848896c2410488974241857","48895c24105556574154415541564157","32c0c3cccccccccccccccccccccccccc"},
    {0x295e368,0x22d200,0xcee530,0x1807b0,0xcece50,0x2c,AUTHORITY_COMMAND_COUNTRY_CHANGE,"40534883ec20488d05bb424f02","48895c241048896c2418565741544156","b001c3cccccccccccccccccccccccccc","48895c241848894c2408555657415441"},
    {0x2996390,0xdb4550,0x1162b60,0x11d220,0x1153210,0x30,AUTHORITY_COMMAND_COUNTRY_CHANGE,"40534883ec20488d056bcf9601","40574883ec30803de5ef470200488bf9","32c0c3cccccccccccccccccccccccccc","48894c24085553565741544155415641"},
    {0x295e430,0x22d200,0xcee2c0,0x1807b0,0xcec380,0x2c,AUTHORITY_COMMAND_COOP_REQUEST,"40534883ec20488d05bb424f02","40534883ec30803d85388f0200488bd9","b001c3cccccccccccccccccccccccccc","48895c24085556574154415541564157"},
    {0x29e68a0,0x22d200,0x1807b0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d05bb424f02","b001c3cccccccccccccccccccccccccc","b001c3cccccccccccccccccccccccccc"},
    {0x272dac0,0x22d200,0x1166710,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05bb424f02","837928007e0983792c027703b001c332","32c0c3cccccccccccccccccccccccccc"},
    {0x272db88,0x22d200,0x1166710,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05bb424f02","837928007e0983792c027703b001c332","32c0c3cccccccccccccccccccccccccc"},
    {0x272dc50,0x22d200,0x1166710,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05bb424f02","837928007e0983792c027703b001c332","32c0c3cccccccccccccccccccccccccc"},
    {0x272dd18,0x22d200,0x1166710,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05bb424f02","837928007e0983792c027703b001c332","32c0c3cccccccccccccccccccccccccc"},
    {0x272dde0,0x22d200,0x1166710,0x11d220,0,0x28,AUTHORITY_COMMAND_COUNTRY_ACTOR,"40534883ec20488d05bb424f02","837928007e0983792c027703b001c332","32c0c3cccccccccccccccccccccccccc"},
    {0x2938e60,0xa0d450,0x153afb0,0x11d220,0,0x34,AUTHORITY_COMMAND_EVENT_OPTION,"48895c2408574883ec20488bf98bda48","48895c241048896c2418488974242057","32c0c3cccccccccccccccccccccccccc"},
    {0x2994db0,0xdb4550,0x1162420,0x11d220,0,0,AUTHORITY_COMMAND_FACTORY_PAYLOAD,"40534883ec20488d056bcf96","48895c2408574883ec20488bf9","32c0c3cccccccccccccccccccccccccc"},
    {0x2993a28,0x1149060,0x1161be0,0x11d220,0,0,AUTHORITY_COMMAND_FACTORY_PAYLOAD,"48895c24084889742410574883","48895c241048896c2418488974242057","32c0c3cccccccccccccccccccccccccc"},
    {0x29e6328,0x163c1c0,0x163ddb0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"48895c2408574883ec20488d0557a13a","4c8bdc49895b105556574883ec60488b","b001c3cccccccccccccccccccccccccc"},
    {0x29e6260,0x22d200,0x1807b0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d05bb424f02488bd9","b001c3cccccccccccccccccccccccccc","b001c3cccccccccccccccccccccccccc"},
    {0x29e63f0,0x22d200,0x163e050,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d05bb424f02488bd9","40534883ec30837928ff488bd90f849a","b001c3cccccccccccccccccccccccccc"},
    {0x2a99a98,0x1c94a0,0x1807b0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d051b805502488bd9","b001c3cccccccccccccccccccccccccc","b001c3cccccccccccccccccccccccccc"},
    {0x2a99b60,0x1c94a0,0x1807b0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d051b805502488bd9","b001c3cccccccccccccccccccccccccc","b001c3cccccccccccccccccccccccccc"},
    {0x29e6710,0xdb45f0,0x1807b0,0x1807b0,0,0,AUTHORITY_COMMAND_HOST_ONLY,"40534883ec20488d05cbce9601488bd9","b001c3cccccccccccccccccccccccccc","b001c3cccccccccccccccccccccccccc"},
    {0x2967cd8,0xdb4520,0x199d910,0x11d220,0,0,AUTHORITY_COMMAND_MIO_TRAIT_OWNER,"40534883ec20488d059bcf9601","488bc448895810488970184889782055","32c0c3cccccccccccccccccccccccccc"},
    {0x2967e68,0xdb4520,0x199d220,0x11d220,0,0,AUTHORITY_COMMAND_MIO_TRAIT_OWNER,"40534883ec20488d059bcf9601","48895c2408574883ec20488bf94883c140","32c0c3cccccccccccccccccccccccccc"},
    {0x2967f30,0xdb4520,0x199d3a0,0x11d220,0,0,AUTHORITY_COMMAND_MIO_TRAIT_OWNER,"40534883ec20488d059bcf9601","40534883ec20488bd94883c1408339007506","32c0c3cccccccccccccccccccccccccc"},
    {0x2967ff8,0xdb4580,0x199d2f0,0x11d220,0,0,AUTHORITY_COMMAND_MIO_TRAIT_OWNER,"40534883ec20488d053bcf9601","48895c24084889742410574883ec20488bd9","32c0c3cccccccccccccccccccccccccc"},
    {0x29680c0,0xdb4620,0x199d820,0x11d220,0,0,AUTHORITY_COMMAND_MIO_TRAIT_OWNER,"48895c24084889742410574883ec20","4889742410574883ec20488bf94883c148","32c0c3cccccccccccccccccccccccccc"}
};
#pragma clang diagnostic pop

typedef struct PeerSlot {
    uint64_t machineId;
    uintptr_t server, connection, context;
    uint32_t generation;
} PeerSlot;
typedef struct IngressScope {
    uint64_t machineId, epoch;
    uint32_t peerGeneration;
    uintptr_t server, connection, context;
    int active;
} IngressScope;
typedef struct HookRef { size_t classIndex; unsigned slot; } HookRef;

static unsigned char *imageBase;
static SIZE_T imageSize;
static VtableHookSet hookSets[8];
static VtableHookSet lifecycleHookSet;
static VtableHookSet scriptGetterHookSet;
static HookRef hookRefs[128];
static size_t hookRefCount, hookSetCount;
static AuthorityPolicy policy;
static CommandProvenanceStore provenance;
static SRWLOCK peerLock = SRWLOCK_INIT;
static PeerSlot peers[AUTH_MAX_PEERS];
static uintptr_t trackedServer, trackedContext;
static volatile LONG64 epochCounter = AUTH_EPOCH_INITIAL;
static volatile LONG64 peerGenerationCounter;
static volatile LONG active, stopped, stateValue;
static volatile LONG64 stats[16];
static volatile LONG64 rejectionReasons[AUTHORITY_REASON_MIO_OWNER_NOT_CONTROLLED + 1];
static AuthorityGuardLogger logCallback;
static __thread IngressScope ingress;
static SenderResolverFn senderResolver;
static LoadTaskFn originalLoadTask;
static ScriptGetterFn originalScriptGetter;
static volatile LONG64 nextGrantId;

static uint64_t current_epoch(void) { return (uint64_t)InterlockedCompareExchange64(&epochCounter, 0, 0); }
static void inc_stat(size_t index) { if (index < 16) InterlockedIncrement64(&stats[index]); }
static void count_reason(AuthorityReason reason) {
    if (reason > AUTHORITY_REASON_NONE && reason <= AUTHORITY_REASON_MIO_OWNER_NOT_CONTROLLED)
        InterlockedIncrement64(&rejectionReasons[reason]);
}

static uint64_t advance_session(int clearPeers) {
    uint64_t next = (uint64_t)InterlockedIncrement64(&epochCounter);
    if (!next) next = (uint64_t)InterlockedIncrement64(&epochCounter);
    AuthorityPolicyReset(&policy, next);
    CommandProvenanceAdvanceSession(&provenance, next);
    if (clearPeers) {
        AcquireSRWLockExclusive(&peerLock);
        memset(peers, 0, sizeof(peers));
        ReleaseSRWLockExclusive(&peerLock);
    }
    return next;
}

static int observe_server_context(uintptr_t server, uintptr_t context) {
    int changed = 0;
    AcquireSRWLockExclusive(&peerLock);
    if (!trackedServer || !trackedContext) {
        trackedServer = server; trackedContext = context;
    } else if (trackedServer != server || trackedContext != context) {
        trackedServer = server; trackedContext = context; changed = 1;
    }
    ReleaseSRWLockExclusive(&peerLock);
    if (changed) advance_session(1);
    return changed;
}

static int copy_from_process(const void *source, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return source && ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) && copied == size;
}

static int bytes_equal(uint32_t rva, const u8 *expected, size_t length) {
    u8 actual[32];
    return length <= sizeof(actual) && imageBase && rva <= imageSize && length <= imageSize - rva &&
        copy_from_process(imageBase + rva, actual, length) && memcmp(actual, expected, length) == 0;
}

static int decode_hex(const char *hex, u8 out[16], size_t bytes) {
    if (!hex || bytes == 0 || bytes > 16 || strlen(hex) < bytes * 2) return 0;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned value = 0;
        for (size_t j = 0; j < 2; ++j) {
            char c = hex[i * 2 + j];
            unsigned digit = c >= '0' && c <= '9' ? (unsigned)(c - '0') :
                c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10) : 99u;
            if (digit > 15) return 0;
            value = value * 16 + digit;
        }
        out[i] = (u8)value;
    }
    return 1;
}

static CoveredClass *class_for(void *command) {
    void *vtable = NULL;
    if (!copy_from_process(command, &vtable, sizeof(vtable))) return NULL;
    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i)
        if (vtable == imageBase + classes[i].vtableRva) return &classes[i];
    return NULL;
}

static int image_rva_of(const void *returnAddress, uint32_t *outRva) {
    uintptr_t address = (uintptr_t)returnAddress, base = (uintptr_t)imageBase;
    if (!imageBase || address < base || address - base >= imageSize) return 0;
    *outRva = (uint32_t)(address - base);
    return 1;
}

static int peer_generation(uint64_t machineId, uintptr_t server, uintptr_t connection,
    uintptr_t context, uint32_t *outGeneration, int create) {
    int freeIndex = -1, machineIndex = -1;
    if (!machineId || !outGeneration) return 0;
    AcquireSRWLockExclusive(&peerLock);
    for (size_t i = 0; i < AUTH_MAX_PEERS; ++i) {
        PeerSlot *slot = &peers[i];
        if (!slot->machineId) { if (freeIndex < 0) freeIndex = (int)i; continue; }
        if (slot->server == server && slot->connection == connection && slot->context == context) {
            if (slot->machineId == machineId) {
                *outGeneration = slot->generation;
                ReleaseSRWLockExclusive(&peerLock);
                return 1;
            }
            memset(slot, 0, sizeof(*slot));
            if (freeIndex < 0) freeIndex = (int)i;
        }
        if (slot->machineId == machineId) machineIndex = (int)i;
    }
    if (!create) { ReleaseSRWLockExclusive(&peerLock); return 0; }
    int index = machineIndex >= 0 ? machineIndex : freeIndex;
    if (index < 0) { ReleaseSRWLockExclusive(&peerLock); return 0; }
    PeerSlot *slot = &peers[index];
    slot->machineId = machineId; slot->server = server; slot->connection = connection; slot->context = context;
    uint64_t nextGeneration = (uint64_t)InterlockedIncrement64(&peerGenerationCounter);
    if ((uint32_t)nextGeneration == 0)
        nextGeneration = (uint64_t)InterlockedIncrement64(&peerGenerationCounter);
    slot->generation = (uint32_t)nextGeneration;
    *outGeneration = slot->generation;
    ReleaseSRWLockExclusive(&peerLock);
    return 1;
}

static int current_peer_generation(uint64_t machineId, uint32_t *outGeneration) {
    if (!machineId || !outGeneration) return 0;
    AcquireSRWLockShared(&peerLock);
    for (size_t i = 0; i < AUTH_MAX_PEERS; ++i) {
        if (peers[i].machineId == machineId) {
            *outGeneration = peers[i].generation;
            ReleaseSRWLockShared(&peerLock);
            return 1;
        }
    }
    ReleaseSRWLockShared(&peerLock);
    return 0;
}

static uint64_t native_sender(void *server, uintptr_t connection, uintptr_t *outContext) {
    uintptr_t context = 0;
    if (!copy_from_process((const u8 *)server + 0x48, &context, sizeof(context)) || !context || !senderResolver)
        return 0;
    if (outContext) *outContext = context;
    /* The native caller consumes the low 32-bit machine ID (EAX). Upper RAX
       bits are unspecified by the resolver's ABI and must not affect identity. */
    uint32_t machineId = (uint32_t)senderResolver((void *)context, connection);
    return machineId > 0 && machineId <= INT32_MAX ? machineId : 0;
}

static int country_tag_valid(void *world, int32_t country) {
    int32_t count = 0;
    uintptr_t map = 0;
    return world && country >= 0 && copy_from_process((u8 *)world + 0x34c, &count, sizeof(count)) &&
        copy_from_process((u8 *)world + 0x340, &map, sizeof(map)) && map && country < count;
}

static AuthorityTruth countries_equal(void *world, int32_t left, int32_t right) {
    typedef unsigned char (__fastcall *CanonicalEqual)(const int32_t *, int32_t);
    if (left == AUTHORITY_COUNTRY_OBSERVER || right == AUTHORITY_COUNTRY_OBSERVER)
        return left == right ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
    if (!country_tag_valid(world, left) || !country_tag_valid(world, right)) return AUTHORITY_TRUTH_UNKNOWN;
    if (left == right) return AUTHORITY_TRUTH_TRUE;
    return ((CanonicalEqual)(imageBase + 0xbb52f0))(&left, right) ?
        AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
}

static int native_available(void *world, int32_t country) {
    typedef unsigned char (__fastcall *Availability)(void *, int32_t *);
    return country_tag_valid(world, country) &&
        ((Availability)(imageBase + 0x1e2460))(world, &country) != 0;
}

static AuthorityTruth game_started(void *world) {
    /* CCurrentGameState::HasGameStarted reads this byte; its native setter is
       0x1edff0. Both offsets are bound to the exact GAME_SHA256 image at start. */
    u8 started = 0;
    if (!world || !copy_from_process((u8 *)world + 0xa39, &started, sizeof(started)))
        return AUTHORITY_TRUTH_UNKNOWN;
    return started ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
}

static AuthorityTruth native_observer_eligible(void *world, int32_t country) {
    typedef void *(__fastcall *CountryLookup)(int32_t *);
    typedef unsigned char (__fastcall *ObserverEligible)(void *);
    if (!world || !country_tag_valid(world, country)) return AUTHORITY_TRUTH_UNKNOWN;
    /* The pinned game's tag lookup resolves aliases to their native country;
       0x6fcfa0 is the game's predicate `*(int *)(country + 0x41c) < 1`.
       The image hash check in AuthorityGuardStart rejects unknown builds. */
    void *nativeCountry = ((CountryLookup)(imageBase + 0xbb48f0))(&country);
    if (!nativeCountry) return AUTHORITY_TRUTH_UNKNOWN;
    return ((ObserverEligible)(imageBase + 0x6fcfa0))(nativeCountry) ?
        AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
}

static int country_has_other_human(void *world, int32_t country, int32_t affected) {
    uintptr_t records = 0;
    int32_t count = 0;
    if (!country_tag_valid(world, country) ||
        !copy_from_process((u8 *)world + 0xf8, &records, sizeof(records)) ||
        !copy_from_process((u8 *)world + 0x104, &count, sizeof(count)) || !records || count < 0)
        return -1;
    for (int32_t i = 0; i < count; ++i) {
        u8 *record = (u8 *)records + (size_t)i * 0xa0;
        int32_t id = -1, tag = -1;
        if (!copy_from_process(record + 0x98, &id, sizeof(id)) ||
            !copy_from_process(record + 0x70, &tag, sizeof(tag))) return -1;
        if (id == affected || tag <= AUTH_OBSERVER_NATIVE) continue;
        if (countries_equal(world, tag, country) == AUTHORITY_TRUTH_TRUE) return 1;
    }
    return 0;
}

void AuthorityGuardReceive(PacketCallback original, void *server, const void *packet,
    uint32_t length, uintptr_t connection, int channel) {
    if (!original) return;
    inc_stat(STAT_RECEIVE_CALLBACKS);
    if (channel != 0 || !active) {
        original(server, packet, length, connection, channel);
        return;
    }
    /* Once installed, an authenticated host channel-0 packet cannot enter the
       native receiver without a TLS identity scope. */
    if (!server || !connection) {
        count_reason(AUTHORITY_REASON_PEER_INVALID);
        inc_stat(STAT_POLICY_DENIES); return;
    }
    uintptr_t context = 0;
    uint64_t sender = native_sender(server, connection, &context);
    if (sender && context) observe_server_context((uintptr_t)server, context);
    uint32_t generation = 0;
    if (!sender || !peer_generation(sender, (uintptr_t)server, connection, context, &generation, 1)) {
        count_reason(AUTHORITY_REASON_PEER_INVALID);
        inc_stat(STAT_STALE_PEERS);
        return;
    }
    AuthorityPolicyPrunePeer(&policy, sender, generation);
    IngressScope previous = ingress;
    ingress.machineId = sender; ingress.peerGeneration = generation; ingress.epoch = current_epoch();
    ingress.server = (uintptr_t)server; ingress.connection = connection; ingress.context = context; ingress.active = 1;
    inc_stat(STAT_RECEIVE_SCOPES);
    original(server, packet, length, connection, channel);
    ingress = previous;
}

static AuthorityTruth actor_controlled(uint64_t machineId, int32_t country, void *world) {
    typedef void *(__fastcall *HumanLookup)(void *, int32_t);
    HumanLookup lookup = (HumanLookup)(imageBase + 0x1c9cd0);
    if (machineId > INT32_MAX || !world) return AUTHORITY_TRUTH_UNKNOWN;
    void *record = lookup(world, (int32_t)machineId);
    int32_t foundId = -1, foundCountry = -1;
    if (!record || !copy_from_process((u8 *)record + 0x98, &foundId, sizeof(foundId)) ||
        !copy_from_process((u8 *)record + 0x70, &foundCountry, sizeof(foundCountry))) return AUTHORITY_TRUTH_FALSE;
    if (foundId != (int32_t)machineId) return AUTHORITY_TRUTH_FALSE;
    if (country == AUTHORITY_COUNTRY_OBSERVER) return foundCountry == AUTH_OBSERVER_NATIVE ?
        AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
    if (country < 0 || foundCountry < 0 || !country_tag_valid(world, country) ||
        !country_tag_valid(world, foundCountry)) return AUTHORITY_TRUTH_FALSE;
    return countries_equal(world, foundCountry, country);
}

static int current_authority_facts(void *world, uint64_t machineId, uint32_t generation,
    int32_t destination, AuthorityFacts *facts) {
    typedef void *(__fastcall *HumanLookup)(void *, int32_t);
    if (!world || machineId == 0 || machineId > INT32_MAX || generation == 0 ||
        !country_tag_valid(world, destination)) return 0;
    void *record = ((HumanLookup)(imageBase + 0x1c9cd0))(world, (int32_t)machineId);
    int32_t exact = -1, country = -1;
    uint32_t flags = 0;
    if (!record || !copy_from_process((u8 *)record + 0x98, &exact, sizeof(exact)) || exact != (int32_t)machineId ||
        !copy_from_process((u8 *)record + 0x70, &country, sizeof(country)) ||
        !copy_from_process((u8 *)record + 0x94, &flags, sizeof(flags))) return 0;
    if (country != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, country)) return 0;
    facts->currentAuthorityKnown = AUTHORITY_TRUTH_TRUE;
    facts->currentAuthority.machineId = machineId;
    facts->currentAuthority.generation = generation;
    facts->currentAuthorityCountry = country == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : country;
    if (!(flags & 1u) || country == AUTH_OBSERVER_NATIVE) {
        facts->currentAuthorityAuthorizedForGrant = AUTHORITY_TRUTH_FALSE;
    } else {
        facts->currentAuthorityAuthorizedForGrant = countries_equal(world, country, destination);
    }
    return 1;
}

static int32_t current_local_human_id(void *world) {
    typedef void *(__fastcall *LocalHumanLookup)(void *);
    if (!world) return -1;
    void *localRecord = ((LocalHumanLookup)(imageBase + 0x1db8e0))(world);
    int32_t localId = -1;
    if (!localRecord || !copy_from_process((u8 *)localRecord + 0x98, &localId, sizeof(localId)) || localId <= 0)
        return -1;
    uintptr_t records = 0;
    int32_t count = 0;
    if (!copy_from_process((u8 *)world + 0xf8, &records, sizeof(records)) ||
        !copy_from_process((u8 *)world + 0x104, &count, sizeof(count)) ||
        !records || count < 0 || count > (int32_t)AUTH_MAX_PEERS) return -1;
    for (int32_t i = 0; i < count; ++i) {
        u8 *record = (u8 *)records + (size_t)i * 0xa0;
        int32_t foundId = -1;
        if (!copy_from_process(record + 0x98, &foundId, sizeof(foundId))) return -1;
        if (foundId == localId) return localId;
    }
    return -1;
}

static int load_in_progress(void *world) {
    u8 value = 0;
    if (!world || !copy_from_process((u8 *)world + 0xa35, &value, 1)) return 1;
    return value != 0;
}

static uint32_t idea_cost_flag_offset(const CoveredClass *row) {
    if (!row) return 0;
    if (row->vtableRva == 0x2995328 || row->vtableRva == 0x2995648) return 0x38;
    if (row->vtableRva == 0x29958a0) return 0x40;
    return 0;
}

static int read_value_at(const void *base, uintptr_t offset, void *out, size_t size) {
    uintptr_t address = (uintptr_t)base;
    if (!base || !out || !size || offset > UINTPTR_MAX - size ||
        address > UINTPTR_MAX - offset - size) return 0;
    return copy_from_process((const void *)(address + offset), out, size);
}

static int read_pointer_at(const void *base, uintptr_t offset, void **out) {
    return read_value_at(base, offset, out, sizeof(*out));
}

/* Safely follows idea -> category -> group metadata. This implements the
 * exclusions confirmed in native politics eligibility 0x15ea750 (type 1
 * national spirits and hidden groups). That UI function is not called here.
 * The exact GAME_SHA256 check binds these offsets to the reviewed image. */
static int idea_reference_selectable(void *idea) {
    void *category = NULL, *group = NULL;
    int32_t groupType = -1;
    u8 hidden = 0;
    if (!read_pointer_at(idea, 0xaa0, &category) || !category ||
        !read_pointer_at(category, 0x60, &group) || !group) return 0;
    if (!read_value_at(group, 0x78, &groupType, sizeof(groupType)) ||
        !read_value_at(group, 0x7c, &hidden, sizeof(hidden))) return 0;
    return groupType != 1 && hidden == 0;
}

static int idea_references_preflight(const CoveredClass *row, const void *command) {
    uint32_t ideaOffsets[2] = {0, 0};
    size_t ideaCount = 0;
    if (!row || !command) return 0;
    if (row->vtableRva == 0x2995328 || row->vtableRva == 0x2995648) {
        ideaOffsets[ideaCount++] = 0x30;
    } else if (row->vtableRva == 0x29958a0) {
        ideaOffsets[ideaCount++] = 0x30;
        ideaOffsets[ideaCount++] = 0x38;
    } else return 0;
    for (size_t i = 0; i < ideaCount; ++i) {
        void *idea = NULL;
        if (!read_pointer_at(command, ideaOffsets[i], &idea) || !idea ||
            !idea_reference_selectable(idea)) return 0;
    }
    return 1;
}

typedef struct NativeMioReference {
    void *organization;
    int32_t ownerCountry;
} NativeMioReference;

static int resolve_mio_reference(const void *reference, void *world,
    uint64_t sender, int checkOwner, NativeMioReference *out) {
    typedef void *(__fastcall *ResolveReferenceFn)(void *);
    if (!reference || !world || !out) return 0;
    /* The native resolver consumes the typed reference object. First prove its
       storage is readable, then bind the result to COrganisation's pinned vtable. */
    uintptr_t marker = 0;
    if (!copy_from_process(reference, &marker, sizeof(marker)) || !marker) return 0;
    void *organization = ((ResolveReferenceFn)(imageBase + 0x221f310))((void *)reference);
    void *vtable = NULL;
    int32_t ownerCountry = -1;
    if (!organization || !copy_from_process(organization, &vtable, sizeof(vtable)) ||
        vtable != imageBase + 0x2967a28 ||
        !copy_from_process((u8 *)organization + 0x120, &ownerCountry, sizeof(ownerCountry)) ||
        ownerCountry <= 0 || !country_tag_valid(world, ownerCountry)) return 0;
    if (checkOwner && actor_controlled(sender, ownerCountry, world) != AUTHORITY_TRUTH_TRUE)
        return 0;
    out->organization = organization;
    out->ownerCountry = ownerCountry;
    return 1;
}

static int mio_references_preflight(const CoveredClass *row, const void *command,
    void *world, uint64_t sender, int checkOwner) {
    if (!row || !command || !world || !sender) return 0;
    uint32_t referenceOffset = 0x40;
    if (row->vtableRva == 0x29680c0) {
        uintptr_t entries = 0;
        int32_t capacity = 0, count = 0;
        if (!copy_from_process((const u8 *)command + 0x30, &entries, sizeof(entries)) ||
            !copy_from_process((const u8 *)command + 0x38, &capacity, sizeof(capacity)) ||
            !copy_from_process((const u8 *)command + 0x3c, &count, sizeof(count)) ||
            capacity < 0 || count < 0 || count > capacity || (count && !entries) ||
            (count && entries > UINTPTR_MAX - (uintptr_t)(uint32_t)count * 0x10)) return 0;
        for (int32_t i = 0; i < count; ++i) {
            u8 traitId[0x10];
            uintptr_t address = entries + (uintptr_t)(uint32_t)i * 0x10;
            if (!copy_from_process((const void *)address, traitId, sizeof(traitId))) return 0;
        }
        referenceOffset = 0x48;
    }
    if (row->vtableRva != 0x2967cd8 && row->vtableRva != 0x2967e68 &&
        row->vtableRva != 0x2967f30 && row->vtableRva != 0x2967ff8 &&
        row->vtableRva != 0x29680c0) return 0;
    NativeMioReference resolved;
    return resolve_mio_reference((const u8 *)command + referenceOffset,
        world, sender, checkOwner, &resolved);
}

static int idea_command_cost_is_paid(const CoveredClass *row, const void *command) {
    u8 costFlag = 0;
    uint32_t offset = idea_cost_flag_offset(row);
    return offset && read_value_at(command, offset, &costFlag, sizeof(costFlag)) && costFlag == 1;
}

static int resolve_update_variant(void *command, void *world, void **outVariant, int32_t *outActor) {
    typedef void *(__fastcall *ResolveVariantFn)(void *);
    if (!command || !world || !outVariant || !outActor) return 0;
    void *variant = ((ResolveVariantFn)(imageBase + 0x221f310))((u8 *)command + 0x28);
    void *vtable = NULL;
    int32_t actor = -1;
    if (!variant || !copy_from_process(variant, &vtable, sizeof(vtable)) ||
        vtable != imageBase + 0x2951608 ||
        !copy_from_process((u8 *)variant + 0x1c, &actor, sizeof(actor)) ||
        actor <= 0 || !country_tag_valid(world, actor)) return 0;
    *outVariant = variant;
    *outActor = actor;
    return 1;
}

static AuthorityResult evaluate_remote(CoveredClass *row, void *command,
    const CommandProvenanceSnapshot *snapshot, int nativeValid, int commit) {
    AuthorityFacts facts;
    memset(&facts, 0, sizeof(facts));
    facts.origin = AUTHORITY_ORIGIN_REMOTE;
    facts.command = row->kind;
    facts.sessionEpoch = snapshot->sessionEpoch;
    facts.peerStatus = AUTHORITY_PEER_VALID;
    facts.sender.machineId = snapshot->authenticatedMachineId;
    facts.sender.generation = snapshot->authenticatedPeerGeneration;
    facts.nativeValid = nativeValid;
    facts.commit = commit;
    facts.nativeClassKnown = AUTHORITY_TRUTH_TRUE;
    facts.nativeClassHostOnly = row->kind == AUTHORITY_COMMAND_HOST_ONLY ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
    AuthorityPeerIdentity requester = facts.sender;
    int32_t actor = 0;
    void *world = NULL;
    if (row->kind == AUTHORITY_COMMAND_HOST_ONLY)
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    if (!copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) || !world || load_in_progress(world)) {
        facts.origin = AUTHORITY_ORIGIN_UNKNOWN;
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    }
    if (row->kind == AUTHORITY_COMMAND_MIO_TRAIT_OWNER) {
        if (!mio_references_preflight(row, command, world,
            snapshot->authenticatedMachineId, 0))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_MIO_REFERENCE_INVALID, 0};
        if (!mio_references_preflight(row, command, world,
            snapshot->authenticatedMachineId, 1))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_MIO_OWNER_NOT_CONTROLLED, 0};
        return (AuthorityResult){AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE, 0};
    }
    if (row->kind == AUTHORITY_COMMAND_COUNTRY_ACTOR) {
        if (row->vtableRva == 0x2a24188) {
            void *variant = NULL;
            if (!resolve_update_variant(command, world, &variant, &actor))
                return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
            facts.actorControlledBySender = actor_controlled(snapshot->authenticatedMachineId, actor, world);
            if (facts.actorControlledBySender != AUTHORITY_TRUTH_TRUE)
                return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED, 0};
            AuthorityResult payload = AuthorityValidateEquipmentPayload(imageBase, command, 0);
            if (payload.decision != AUTHORITY_DECISION_ALLOW) return payload;
            return AuthorityCanonicalizeEquipmentBonus(imageBase, command);
        } else if (!copy_from_process((u8 *)command + row->actorOffset, &actor, sizeof(actor)) ||
            actor <= 0 || !country_tag_valid(world, actor)) {
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        }
        facts.actorControlledBySender = actor_controlled(snapshot->authenticatedMachineId, actor, world);
        if (facts.actorControlledBySender == AUTHORITY_TRUTH_UNKNOWN)
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        if (row->vtableRva == 0x2a240c0) {
            if (facts.actorControlledBySender != AUTHORITY_TRUTH_TRUE)
                return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED, 0};
            AuthorityResult payload = AuthorityValidateEquipmentPayload(imageBase, command, 0);
            if (payload.decision != AUTHORITY_DECISION_ALLOW) return payload;
            return AuthorityCanonicalizeEquipmentBonus(imageBase, command);
        }
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    }
    if (row->kind == AUTHORITY_COMMAND_EVENT_OPTION)
        return AuthorityValidateEventPayload(imageBase, world, command,
            snapshot->authenticatedMachineId, 0);
    if (row->kind == AUTHORITY_COMMAND_FACTORY_PAYLOAD)
        return AuthorityValidateFactoryPayload(imageBase, world, command,
            snapshot->authenticatedMachineId, row->vtableRva, 0);
    if (row->kind == AUTHORITY_COMMAND_IDEA_MUTATION) {
        if (!idea_references_preflight(row, command) || !idea_command_cost_is_paid(row, command) ||
            !copy_from_process((u8 *)command + row->actorOffset, &actor, sizeof(actor)) ||
            actor <= 0 || !country_tag_valid(world, actor))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_IDEA_MUTATION_INVALID, 0};
        facts.command = AUTHORITY_COMMAND_COUNTRY_ACTOR;
        facts.actorControlledBySender = actor_controlled(snapshot->authenticatedMachineId, actor, world);
        if (facts.actorControlledBySender == AUTHORITY_TRUTH_UNKNOWN)
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    }
    if (row->kind == AUTHORITY_COMMAND_COUNTRY_CHANGE) {
        int32_t affected = 0, destination = 0;
        uint32_t affectedOffset = row->vtableRva == 0x295e368 ? 0x2c : 0x30;
        if (!copy_from_process((u8 *)command + affectedOffset, &affected, sizeof(affected)) ||
            !copy_from_process((u8 *)command + 0x28, &destination, sizeof(destination)))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        if (affected <= 0 || (destination != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, destination)))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        typedef void *(__fastcall *HumanLookup)(void *, int32_t);
        void *record = ((HumanLookup)(imageBase + 0x1c9cd0))(world, affected);
        int32_t exact = -1, source = AUTHORITY_COUNTRY_UNKNOWN;
        if (!record || !copy_from_process((u8 *)record + 0x98, &exact, sizeof(exact)) || exact != affected ||
            !copy_from_process((u8 *)record + 0x70, &source, sizeof(source)))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        if (source != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, source))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        requester.machineId = (uint64_t)(uint32_t)affected;
        uint32_t gen = 0;
        if (!current_peer_generation(requester.machineId, &gen)) {
            if (requester.machineId == snapshot->authenticatedMachineId)
                gen = snapshot->authenticatedPeerGeneration;
            else if ((int32_t)requester.machineId == current_local_human_id(world))
                gen = AUTH_HOST_LOCAL_GENERATION;
            else
                return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        }
        requester.generation = gen;
        facts.requester = requester;
        facts.sourceCountry = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : source;
        facts.destinationCountry = destination == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : destination;
        facts.sourceDestinationCanonicalEqual = facts.sourceCountry == AUTHORITY_COUNTRY_OBSERVER ||
            facts.destinationCountry == AUTHORITY_COUNTRY_OBSERVER ?
            (facts.sourceCountry == facts.destinationCountry ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE) :
            countries_equal(world, source, destination);
        facts.affectedPeerControlsSource = AUTHORITY_TRUTH_TRUE;
        facts.actorControlledBySender = actor_controlled(snapshot->authenticatedMachineId,
            facts.sourceCountry, world);
        AuthorityTruth started = game_started(world);
        facts.assignmentLockEnabled = started;
        facts.sourceObserverEligible = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_TRUTH_FALSE :
            started == AUTHORITY_TRUTH_TRUE ? native_observer_eligible(world, source) : AUTHORITY_TRUTH_UNKNOWN;
        if (destination != AUTH_OBSERVER_NATIVE)
            current_authority_facts(world, snapshot->authenticatedMachineId,
                snapshot->authenticatedPeerGeneration, destination, &facts);
        if (destination == AUTH_OBSERVER_NATIVE) {
            facts.destinationNativeAvailable = AUTHORITY_TRUTH_UNKNOWN;
            facts.destinationUnoccupied = AUTHORITY_TRUTH_UNKNOWN;
            facts.destinationHumanControlled = AUTHORITY_TRUTH_UNKNOWN;
        } else {
            int otherHuman = country_has_other_human(world, destination, affected);
            facts.destinationNativeAvailable = native_available(world, destination) ?
                AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
            facts.destinationHumanControlled = otherHuman < 0 ? AUTHORITY_TRUTH_UNKNOWN :
                otherHuman ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
            facts.destinationUnoccupied = otherHuman < 0 ? AUTHORITY_TRUTH_UNKNOWN :
                otherHuman ? AUTHORITY_TRUTH_FALSE : AUTHORITY_TRUTH_TRUE;
        }
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    }
    if (row->kind == AUTHORITY_COMMAND_COOP_REQUEST) {
        int32_t destination = 0, requesterId = 0;
        if (!copy_from_process((u8 *)command + 0x28, &destination, sizeof(destination)) ||
            !copy_from_process((u8 *)command + 0x2c, &requesterId, sizeof(requesterId)))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        if (requesterId <= 0 || (uint64_t)(uint32_t)requesterId != snapshot->authenticatedMachineId ||
            destination <= AUTH_OBSERVER_NATIVE || !country_tag_valid(world, destination))
            return (AuthorityResult){AUTHORITY_DECISION_DENY, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        facts.requester.machineId = (uint64_t)(uint32_t)requesterId;
        uint32_t requesterGeneration = 0;
        if (!current_peer_generation(facts.requester.machineId, &requesterGeneration))
            return (AuthorityResult){AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_FACTS_UNKNOWN, 0};
        facts.requester.generation = requesterGeneration;
        facts.actorControlledBySender = requesterId == (int32_t)snapshot->authenticatedMachineId ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE;
        facts.destinationCountry = destination;
        return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
    }
    return AuthorityPolicyEvaluate(&policy, &facts, GetTickCount64());
}

static __attribute__((noinline)) unsigned char __fastcall guarded_is_valid(void *command, void *motivation) {
    uint32_t callerRva = 0;
    void *returnAddress = AUTH_RETURN_ADDRESS();
    CoveredClass *row = class_for(command);
    if (!row || !row->originalValid) return 0;
    if (!active) return row->originalValid(command, motivation) != 0;
    int callerKnown = image_rva_of(returnAddress, &callerRva);
    int ingressRemote = callerKnown && callerRva == 0x236795c && ingress.active;
    int primaryOrderedCaller = callerKnown &&
        (callerRva == 0x22530ef || callerRva == 0x2250dbd);
    int orderedRemote = 0;
    CommandProvenanceSnapshot orderedSnapshot;
    memset(&orderedSnapshot, 0, sizeof(orderedSnapshot));
    if (callerKnown && (callerRva == 0x22530ef || callerRva == 0x2250dbd || callerRva == 0x22536df)) {
        orderedRemote = CommandProvenanceFindAny(&provenance, command,
            (void *)(imageBase + row->vtableRva), &orderedSnapshot);
    }
    /* Reject stale queued commands before any command-specific resolver can
       follow serialized references into a replaced world. */
    if (orderedRemote) {
        if (orderedSnapshot.sessionEpoch != current_epoch()) {
            count_reason(AUTHORITY_REASON_SESSION_MISMATCH);
            inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0;
        }
        uint32_t currentGeneration = 0;
        if (!peer_generation(orderedSnapshot.authenticatedMachineId,
            orderedSnapshot.hostServer, orderedSnapshot.transportConnection,
            orderedSnapshot.transportSessionContext, &currentGeneration, 0) ||
            currentGeneration != orderedSnapshot.authenticatedPeerGeneration) {
            count_reason(AUTHORITY_REASON_PEER_INVALID);
            inc_stat(STAT_STALE_PEERS); inc_stat(STAT_POLICY_DENIES); return 0;
        }
    }
    if (ingressRemote || orderedRemote) {
        void *world = NULL;
        if (!copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) || load_in_progress(world)) {
            count_reason(AUTHORITY_REASON_FACTS_UNKNOWN);
            inc_stat(STAT_LOAD_REFUSALS); inc_stat(STAT_POLICY_DENIES);
            return 0;
        }
        /* The native receive path also calls IsValid before queueing. Check
           direct country indices there, before native code can index them. */
        if (row->kind == AUTHORITY_COMMAND_COUNTRY_ACTOR && row->vtableRva != 0x2a24188) {
            int32_t actorTag = -1;
            if (!copy_from_process((u8 *)command + row->actorOffset, &actorTag, sizeof(actorTag)) ||
                actorTag <= 0 || !country_tag_valid(world, actorTag)) {
                count_reason(AUTHORITY_REASON_FACTS_UNKNOWN);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
        }
        if (row->kind == AUTHORITY_COMMAND_MIO_TRAIT_OWNER &&
            !mio_references_preflight(row, command, world,
                orderedRemote ? orderedSnapshot.authenticatedMachineId : ingress.machineId, 0)) {
            count_reason(AUTHORITY_REASON_MIO_REFERENCE_INVALID);
            inc_stat(STAT_POLICY_DENIES); return 0;
        }
        if (row->kind == AUTHORITY_COMMAND_IDEA_MUTATION) {
            int32_t actorTag = -1;
            if (!idea_references_preflight(row, command) ||
                !copy_from_process((u8 *)command + row->actorOffset, &actorTag, sizeof(actorTag)) ||
                actorTag <= 0 || !country_tag_valid(world, actorTag)) {
                count_reason(AUTHORITY_REASON_IDEA_MUTATION_INVALID);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
        }
        if (row->kind == AUTHORITY_COMMAND_EVENT_OPTION) {
            if (orderedRemote) {
                if (orderedSnapshot.sessionEpoch != current_epoch()) {
                    count_reason(AUTHORITY_REASON_SESSION_MISMATCH);
                    inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0;
                }
                uint32_t currentGeneration = 0;
                if (!peer_generation(orderedSnapshot.authenticatedMachineId,
                    orderedSnapshot.hostServer, orderedSnapshot.transportConnection,
                    orderedSnapshot.transportSessionContext, &currentGeneration, 0) ||
                    currentGeneration != orderedSnapshot.authenticatedPeerGeneration) {
                    count_reason(AUTHORITY_REASON_PEER_INVALID);
                    inc_stat(STAT_STALE_PEERS); inc_stat(STAT_POLICY_DENIES); return 0;
                }
            }
            AuthorityResult preflight = AuthorityValidateEventPayload(imageBase, world,
                command, orderedRemote ? orderedSnapshot.authenticatedMachineId : ingress.machineId, 1);
            if (preflight.decision != AUTHORITY_DECISION_ALLOW) {
                count_reason(preflight.reason);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
        }
        if (row->kind == AUTHORITY_COMMAND_FACTORY_PAYLOAD) {
            uint64_t sender = orderedRemote ? orderedSnapshot.authenticatedMachineId : ingress.machineId;
            if (orderedRemote) {
                if (orderedSnapshot.sessionEpoch != current_epoch()) {
                    count_reason(AUTHORITY_REASON_SESSION_MISMATCH);
                    inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0;
                }
                uint32_t currentGeneration = 0;
                if (!peer_generation(sender, orderedSnapshot.hostServer,
                    orderedSnapshot.transportConnection, orderedSnapshot.transportSessionContext,
                    &currentGeneration, 0) || currentGeneration != orderedSnapshot.authenticatedPeerGeneration) {
                    count_reason(AUTHORITY_REASON_PEER_INVALID);
                    inc_stat(STAT_STALE_PEERS); inc_stat(STAT_POLICY_DENIES); return 0;
                }
            }
            AuthorityResult preflight = AuthorityValidateFactoryPayload(imageBase, world,
                command, sender, row->vtableRva, 1);
            if (preflight.decision != AUTHORITY_DECISION_ALLOW) {
                count_reason(preflight.reason);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
        }
        if ((ingressRemote || (orderedRemote && primaryOrderedCaller)) &&
            (row->vtableRva == 0x2a240c0 || row->vtableRva == 0x2a24188)) {
            AuthorityResult bonusReferences =
                AuthorityValidateEquipmentBonusReferences(imageBase, command);
            if (bonusReferences.decision != AUTHORITY_DECISION_ALLOW) {
                count_reason(bonusReferences.reason);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
            AuthorityResult preflight = AuthorityValidateEquipmentPayload(imageBase, command, 1);
            if (preflight.decision != AUTHORITY_DECISION_ALLOW) {
                count_reason(preflight.reason);
                inc_stat(STAT_POLICY_DENIES); return 0;
            }
        }
    }
    /* Do not call native code with a queued command from an earlier world or
       transport generation. Its serialized references may already be stale. */
    /* Equipment payload checks and MIO bonus canonicalization must happen at
       the first ordered boundary, before native IsValid inspects the bytes.
       The cached decision is consulted first so retries never re-resolve
       world state or rewrite an already accepted serialized command. */
    int equipmentCommand = row->vtableRva == 0x2a240c0 || row->vtableRva == 0x2a24188;
    int primaryCaller = callerKnown && (callerRva == 0x22530ef || callerRva == 0x2250dbd);
    int equipmentDecisionPending = 0;
    AuthorityResult equipmentDecision = {AUTHORITY_DECISION_DEFER, AUTHORITY_REASON_NONE, 0};
    if (orderedRemote && primaryCaller && equipmentCommand) {
        int cachedBeforeNative = 0;
        CommandProvenanceDecisionResult cachedBeforeNativeResult =
            CommandProvenanceGetDecision(&provenance, &orderedSnapshot, 1, &cachedBeforeNative);
        if (cachedBeforeNativeResult == COMMAND_PROVENANCE_DECISION_STALE) {
            count_reason(AUTHORITY_REASON_SESSION_MISMATCH);
            inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0;
        }
        if (cachedBeforeNativeResult == COMMAND_PROVENANCE_DECISION_UNSET) {
            equipmentDecision = evaluate_remote(row, command, &orderedSnapshot, 1, 1);
            if (equipmentDecision.decision == AUTHORITY_DECISION_DEFER) {
                equipmentDecision.reason = equipmentDecision.reason == AUTHORITY_REASON_NONE ?
                    AUTHORITY_REASON_FACTS_UNKNOWN : equipmentDecision.reason;
            }
            equipmentDecisionPending = 1;
            if (equipmentDecision.decision != AUTHORITY_DECISION_ALLOW) {
                CommandProvenanceCommitDecision(&provenance, &orderedSnapshot, 1, 0);
                count_reason(equipmentDecision.reason);
                inc_stat(equipmentDecision.decision == AUTHORITY_DECISION_DEFER ?
                    STAT_POLICY_DEFERS : STAT_POLICY_DENIES);
                return 0;
            }
        }
    }
    int nativeValid = row->originalValid(command, motivation) != 0;
    inc_stat(STAT_NATIVE_VALID);
    if (!nativeValid) {
        inc_stat(STAT_NATIVE_INVALID);
        /* Canonicalization is part of the first ordered validation attempt.
           If native validation rejects that canonical payload, pin the refusal
           to this object so a motivation retry cannot re-query MIO and mutate
           the serialized command after native state changes. */
        if (equipmentDecisionPending && equipmentDecision.decision == AUTHORITY_DECISION_ALLOW)
            CommandProvenanceCommitDecision(&provenance, &orderedSnapshot, 1, 0);
        return 0;
    }
    if (equipmentDecisionPending && equipmentDecision.decision == AUTHORITY_DECISION_ALLOW) {
        CommandProvenanceCommitDecision(&provenance, &orderedSnapshot, 1, 1);
        inc_stat(STAT_POLICY_ALLOWS);
    }
    if (!callerKnown) return nativeValid;
    if (callerRva == 0x236795c) {
        if (!ingress.active) { count_reason(AUTHORITY_REASON_PEER_INVALID); return 0; }
        int32_t claimed = 0;
        if (!copy_from_process((u8 *)command + 0x0c, &claimed, sizeof(claimed)) ||
            (uint64_t)(uint32_t)claimed != ingress.machineId) {
            count_reason(AUTHORITY_REASON_REQUESTER_MISMATCH);
            return 0;
        }
        CommandProvenanceSnapshot captured;
        CommandProvenanceCaptureResult result = CommandProvenanceCapture(&provenance, command,
            (void *)(imageBase + row->vtableRva), ingress.epoch, (uint64_t)(uint32_t)claimed,
            ingress.machineId, ingress.peerGeneration, ingress.server, ingress.connection,
            ingress.context, nativeValid, &captured);
        if (result != COMMAND_PROVENANCE_CAPTURED && result != COMMAND_PROVENANCE_CAPTURE_REPLACED) {
            count_reason(AUTHORITY_REASON_FACTS_UNKNOWN);
            inc_stat(STAT_PROVENANCE_FULL);
            return 0;
        }
        return nativeValid;
    }
    int primary = callerRva == 0x22530ef || callerRva == 0x2250dbd;
    int late = callerRva == 0x22536df;
    if (!primary && !late) return nativeValid;
    CommandProvenanceSnapshot snapshot;
    if (!CommandProvenanceFindAny(&provenance, command, (void *)(imageBase + row->vtableRva), &snapshot)) {
        inc_stat(STAT_PROVENANCE_MISSES); return nativeValid;
    }
    if (snapshot.sessionEpoch != current_epoch()) { count_reason(AUTHORITY_REASON_SESSION_MISMATCH); inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0; }
    uint32_t generation = 0;
    if (!peer_generation(snapshot.authenticatedMachineId, snapshot.hostServer,
        snapshot.transportConnection, snapshot.transportSessionContext, &generation, 0) ||
        generation != snapshot.authenticatedPeerGeneration) { count_reason(AUTHORITY_REASON_PEER_INVALID); inc_stat(STAT_STALE_PEERS); inc_stat(STAT_POLICY_DENIES); return 0; }
    int cached = 0;
    CommandProvenanceDecisionResult cachedResult =
        CommandProvenanceGetDecision(&provenance, &snapshot, nativeValid, &cached);
    if (cachedResult == COMMAND_PROVENANCE_DECISION_OK)
        return cached ? nativeValid : 0;
    if (cachedResult == COMMAND_PROVENANCE_DECISION_STALE) {
        count_reason(AUTHORITY_REASON_SESSION_MISMATCH);
        inc_stat(STAT_STALE_EPOCHS); inc_stat(STAT_POLICY_DENIES); return 0;
    }
    if (late) {
        return nativeValid;
    }
    AuthorityResult result = evaluate_remote(row, command, &snapshot, nativeValid, 1);
    if (result.decision == AUTHORITY_DECISION_DENY) {
        CommandProvenanceCommitDecision(&provenance, &snapshot, nativeValid, 0);
        count_reason(result.reason);
        inc_stat(STAT_POLICY_DENIES); return 0;
    }
    if (result.decision == AUTHORITY_DECISION_ALLOW) {
        if (result.usedGrantKind)
            CommandProvenanceSetGrantKind(&provenance, &snapshot, nativeValid, (uint8_t)result.usedGrantKind);
        CommandProvenanceCommitDecision(&provenance, &snapshot, nativeValid, 1);
        inc_stat(STAT_POLICY_ALLOWS); return nativeValid;
    }
    /* Every installed class row is reviewed. A missing authoritative fact in
       one of those rows must not silently become native permission. */
    CommandProvenanceCommitDecision(&provenance, &snapshot, nativeValid, 0);
    count_reason(result.reason == AUTHORITY_REASON_NONE ? AUTHORITY_REASON_FACTS_UNKNOWN : result.reason);
    inc_stat(STAT_POLICY_DEFERS);
    inc_stat(STAT_POLICY_DENIES);
    return 0;
}

static __attribute__((noinline)) void *__fastcall guarded_destructor(void *command, unsigned int flags) {
    CoveredClass *row = class_for(command);
    if (!row || !row->originalDestructor) return command;
    CommandProvenanceSnapshot snapshot;
    if (CommandProvenanceFindAny(&provenance, command, (void *)(imageBase + row->vtableRva), &snapshot))
        CommandProvenanceRemove(&provenance, &snapshot);
    return row->originalDestructor(command, flags);
}

static __attribute__((noinline)) unsigned char __fastcall guarded_loggable(void *command) {
    uint32_t callerRva = 0;
    void *returnAddress = AUTH_RETURN_ADDRESS();
    CoveredClass *row = class_for(command);
    if (!row || !row->originalLoggable) return 0;
    int allowed = row->originalLoggable(command);
    if (!image_rva_of(returnAddress, &callerRva) || callerRva != 0x225381d) return allowed;
    CommandProvenanceSnapshot snapshot;
    if (!CommandProvenanceFindAny(&provenance, command, (void *)(imageBase + row->vtableRva), &snapshot)) return allowed;
    if (snapshot.sessionEpoch != current_epoch()) return 0;
    int cached = 0;
    CommandProvenanceDecisionResult cachedResult =
        CommandProvenanceGetDecision(&provenance, &snapshot, 1, &cached);
    return cachedResult == COMMAND_PROVENANCE_DECISION_OK && cached ? allowed : 0;
}

static void issue_coop_grant_after_execute(CoveredClass *row, void *command,
    const CommandProvenanceSnapshot *snapshot) {
    if (!row) return;
    int32_t requesterId = 0, destination = 0;
    if (!copy_from_process((u8 *)command + 0x2c, &requesterId, sizeof(requesterId)) ||
        !copy_from_process((u8 *)command + 0x28, &destination, sizeof(destination)) ||
        requesterId <= 0 ||
        destination <= 0) return;
    void *world = NULL;
    if (!copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) ||
        !world || load_in_progress(world)) return;
    uint32_t generation = 0;
    uint64_t requesterMachineId = (uint64_t)(uint32_t)requesterId;
    uint64_t sessionEpoch = current_epoch();
    if (snapshot) {
        if (snapshot->sessionEpoch != sessionEpoch || requesterMachineId != snapshot->authenticatedMachineId ||
            !peer_generation(snapshot->authenticatedMachineId, snapshot->hostServer,
                snapshot->transportConnection, snapshot->transportSessionContext, &generation, 0) ||
            generation != snapshot->authenticatedPeerGeneration) return;
        generation = snapshot->authenticatedPeerGeneration;
    } else {
        if (requesterId != current_local_human_id(world)) return;
        generation = AUTH_HOST_LOCAL_GENERATION;
    }
    typedef void *(__fastcall *HumanLookup)(void *, int32_t);
    void *record = ((HumanLookup)(imageBase + 0x1c9cd0))(world, requesterId);
    int32_t exact = -1, source = -1;
    if (!record || !copy_from_process((u8 *)record + 0x98, &exact, sizeof(exact)) || exact != requesterId ||
        !copy_from_process((u8 *)record + 0x70, &source, sizeof(source)) ||
        (source != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, source))) return;
    AuthorityGrant grant;
    memset(&grant, 0, sizeof(grant));
    grant.grantId = (uint64_t)InterlockedIncrement64(&nextGrantId);
    grant.sessionEpoch = sessionEpoch;
    grant.peer.machineId = requesterMachineId;
    grant.peer.generation = generation;
    grant.sourceCountry = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : source;
    grant.destinationCountry = destination;
    grant.kind = AUTHORITY_GRANT_COOP;
    grant.authorityCountry = destination;
    AuthorityReason reason = AuthorityPolicyGrantTrusted(&policy, &grant, GetTickCount64(), current_epoch());
    if (reason == AUTHORITY_REASON_NONE) inc_stat(STAT_GRANT_ISSUES);
    else inc_stat(STAT_GRANT_ISSUE_REFUSALS);
}

static void issue_script_grants(int32_t source, int32_t destination, void *scope) {
    (void)scope;
    void *world = NULL;
    if (source < AUTH_OBSERVER_NATIVE || destination <= AUTH_OBSERVER_NATIVE ||
        !copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) ||
        !world || load_in_progress(world) || !country_tag_valid(world, destination) ||
        (source != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, source))) return;
    AuthorityTruth equal = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_TRUTH_FALSE :
        countries_equal(world, source, destination);
    if (equal != AUTHORITY_TRUTH_FALSE) return;
    uintptr_t records = 0;
    int32_t count = 0;
    if (!copy_from_process((u8 *)world + 0xf8, &records, sizeof(records)) ||
        !copy_from_process((u8 *)world + 0x104, &count, sizeof(count)) ||
        !records || count < 0 || count > (int32_t)AUTH_MAX_PEERS) return;
    int32_t policySource = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : source;
    for (int32_t i = 0; i < count; ++i) {
        u8 *record = (u8 *)records + (size_t)i * 0xa0;
        int32_t machineId = -1, currentCountry = -1;
        if (!copy_from_process(record + 0x98, &machineId, sizeof(machineId)) ||
            !copy_from_process(record + 0x70, &currentCountry, sizeof(currentCountry))) return;
        if (machineId <= 0 || currentCountry < 0) continue;
        int controlsSource = source == AUTH_OBSERVER_NATIVE ? currentCountry == AUTH_OBSERVER_NATIVE :
            countries_equal(world, currentCountry, source) == AUTHORITY_TRUTH_TRUE;
        if (!controlsSource) continue;
        uint32_t generation = 0;
        if (!current_peer_generation((uint64_t)(uint32_t)machineId, &generation)) continue;
        AuthorityGrant grant;
        memset(&grant, 0, sizeof(grant));
        grant.grantId = (uint64_t)InterlockedIncrement64(&nextGrantId);
        grant.sessionEpoch = current_epoch();
        grant.peer.machineId = (uint64_t)(uint32_t)machineId;
        grant.peer.generation = generation;
        grant.sourceCountry = policySource;
        grant.destinationCountry = destination;
        grant.kind = AUTHORITY_GRANT_SCRIPT;
        grant.allowOccupiedDestination = 1;
        AuthorityReason reason = AuthorityPolicyGrantTrusted(&policy, &grant, GetTickCount64(), current_epoch());
        if (reason == AUTHORITY_REASON_NONE) inc_stat(STAT_GRANT_ISSUES);
        else inc_stat(STAT_GRANT_ISSUE_REFUSALS);
    }
}

static int current_country_for_human(void *world, int32_t affected, int32_t *outCountry) {
    typedef void *(__fastcall *HumanLookup)(void *, int32_t);
    void *record = ((HumanLookup)(imageBase + 0x1c9cd0))(world, affected);
    int32_t exact = -1, country = -1;
    if (!record || !copy_from_process((u8 *)record + 0x98, &exact, sizeof(exact)) || exact != affected ||
        !copy_from_process((u8 *)record + 0x70, &country, sizeof(country))) return 0;
    if (country != AUTH_OBSERVER_NATIVE && !country_tag_valid(world, country)) return 0;
    *outCountry = country;
    return 1;
}

static void revoke_changed_assignment(CoveredClass *row, void *command, int havePrevious, int32_t previousSource,
    const CommandProvenanceSnapshot *snapshot) {
    if (!row) return;
    int32_t affected = 0, destination = 0, source = -1;
    uint32_t affectedOffset = row->vtableRva == 0x295e368 ? 0x2c : 0x30;
    if (!copy_from_process((u8 *)command + affectedOffset, &affected, sizeof(affected)) || affected <= 0 ||
        !copy_from_process((u8 *)command + 0x28, &destination, sizeof(destination))) return;
    if (!havePrevious) {
        AuthorityPolicyRevokeAffectedPeer(&policy, (uint64_t)(uint32_t)affected);
        return;
    }
    void *world = NULL;
    if (!copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) || !world || load_in_progress(world)) {
        AuthorityPolicyRevokeAffectedPeer(&policy, (uint64_t)(uint32_t)affected);
        return;
    }
    if (!current_country_for_human(world, affected, &source)) {
        AuthorityPolicyRevokeAffectedPeer(&policy, (uint64_t)(uint32_t)affected);
        return;
    }
    if (havePrevious) {
        int32_t normalizedSource = previousSource == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : previousSource;
        int32_t normalizedCurrent = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : source;
        AuthorityTruth changed = normalizedSource == AUTHORITY_COUNTRY_OBSERVER ||
            normalizedCurrent == AUTHORITY_COUNTRY_OBSERVER ?
            (normalizedSource == normalizedCurrent ? AUTHORITY_TRUTH_TRUE : AUTHORITY_TRUTH_FALSE) :
            countries_equal(world, previousSource, source);
        if (changed == AUTHORITY_TRUTH_TRUE && previousSource == source) return;
    }
    if (snapshot && snapshot->cachedGrantKind == AUTHORITY_GRANT_SCRIPT &&
        snapshot->authenticatedMachineId == (uint64_t)(uint32_t)affected) {
        int32_t normalizedPrevious = previousSource == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : previousSource;
        int32_t normalizedCurrent = source == AUTH_OBSERVER_NATIVE ? AUTHORITY_COUNTRY_OBSERVER : source;
        AuthorityPolicyRebaseScriptGrants(&policy, (uint64_t)(uint32_t)affected,
            snapshot->authenticatedPeerGeneration, normalizedPrevious, normalizedCurrent);
    } else {
        AuthorityPolicyRevokeAffectedPeer(&policy, (uint64_t)(uint32_t)affected);
    }
}

static __attribute__((noinline)) void __fastcall guarded_execute(void *command) {
    CoveredClass *row = class_for(command);
    if (!row || !row->originalExecute) return;
    CommandProvenanceSnapshot snapshot;
    int hasRemoteProvenance = CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + row->vtableRva), &snapshot);
    int32_t affected = 0, previousSource = -1;
    int havePrevious = 0;
    if (row->kind == AUTHORITY_COMMAND_COUNTRY_CHANGE) {
        uint32_t affectedOffset = row->vtableRva == 0x295e368 ? 0x2c : 0x30;
        void *world = NULL;
        if (copy_from_process((u8 *)command + affectedOffset, &affected, sizeof(affected)) && affected > 0 &&
            copy_from_process(imageBase + 0x332f260, &world, sizeof(world)) && world && !load_in_progress(world))
            havePrevious = current_country_for_human(world, affected, &previousSource);
    }
    row->originalExecute(command);
    if (!active) return;
    if (row->kind == AUTHORITY_COMMAND_COOP_REQUEST) {
        issue_coop_grant_after_execute(row, command, hasRemoteProvenance ? &snapshot : NULL);
    } else if (row->kind == AUTHORITY_COMMAND_COUNTRY_CHANGE) {
        revoke_changed_assignment(row, command, havePrevious, previousSource,
            hasRemoteProvenance ? &snapshot : NULL);
    }
}

static __attribute__((noinline)) void *__fastcall guarded_load_task(void *task) {
    /* This vtable belongs to the native world-load task. Keep old command
       provenance so commands already queued across a load are recognized and
       denied by their captured epoch. The TBB scheduler invokes this task
       from outside the game image, so the vtable itself is the exact scope. */
    if (active) advance_session(0);
    return originalLoadTask ? originalLoadTask(task) : task;
}

static __attribute__((noinline)) void *__fastcall guarded_script_getter(void *effect,
    int32_t *outTag, void *scope) {
    void *value = originalScriptGetter ? originalScriptGetter(effect, outTag, scope) : NULL;
    uint32_t callerRva = 0;
    if (!active || !originalScriptGetter || !outTag || !scope ||
        !image_rva_of(AUTH_RETURN_ADDRESS(), &callerRva) || callerRva != 0x34f293) return value;
    int32_t source = AUTHORITY_COUNTRY_UNKNOWN, destination = AUTHORITY_COUNTRY_UNKNOWN;
    if (copy_from_process(outTag, &source, sizeof(source)) &&
        copy_from_process((u8 *)scope + 8, &destination, sizeof(destination)))
        issue_script_grants(source, destination, scope);
    return value;
}

static void log_message(const char *text) { if (logCallback) logCallback(text); }

static int verify_static_sites(void) {
    static const u8 methodReceive[16] = {0x48,0x8b,0xc4,0x48,0x89,0x58,0x08,0x4c,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x55};
    static const u8 methodSync[3] = {0xff,0x50,0x48};
    static const u8 methodLog[3] = {0xff,0x50,0x60};
    static const u8 methodAsk[3] = {0xff,0x50,0x50};
    return bytes_equal(0x23663f0, methodReceive, sizeof(methodReceive)) &&
        bytes_equal(0x2367959, methodSync, 3) && bytes_equal(0x22530ec, methodSync, 3) &&
        bytes_equal(0x22536dc, methodSync, 3) && bytes_equal(0x2250dba, methodSync, 3) &&
        bytes_equal(0x225381a, methodLog, 3) && bytes_equal(0x22534b4, methodLog, 3) &&
        bytes_equal(0x2252f6b, methodLog, 3) && bytes_equal(0x225348e, methodAsk, 3) &&
        bytes_equal(0x34f28d, (const u8[]){0xff,0x90,0xc8,0x00,0x00,0x00}, 6) &&
        bytes_equal(0x23e5cb0, (const u8[]){0x48,0x85,0xc9,0x74,0x0a,0x48,0x8b,0x01}, 8) &&
        bytes_equal(0x1f71b0, (const u8[]){0x48,0x83,0xec,0x28,0x48,0x8b,0x49,0x08,0xe8,0xa3,0x18,0xfd,0xff,0x33,0xc0,0x48}, 16) &&
        bytes_equal(0x1db8e0, (const u8[]){0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0x48,0x8b,0x0d,0xa8,0x3d,0x15,0x03}, 16) &&
        bytes_equal(0x221f310, (const u8[]){0x48,0x83,0xec,0x28,0x8b,0x01,0x3d,0x68,0x12,0x00,0x00,0x76,0x24,0x48,0x8b,0x05}, 16) &&
        bytes_equal(0xdb7a10, (const u8[]){0x40,0x53,0x48,0x83,0xec,0x30,0x41,0xb9,0x01,0x00,0x00,0x00,0x48,0x8b,0xda,0xe8}, 16) &&
        bytes_equal(0xbd1e20, (const u8[]){0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7c,0x24,0x18,0x41,0x56,0x48,0x83,0xec,0x20}, 16) &&
        bytes_equal(0x15f7e0, (const u8[]){0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x8b,0xfa,0x48,0x8b,0xd9,0x48}, 16) &&
        bytes_equal(0x1537970, (const u8[]){0x40,0x53,0x48,0x83,0xec,0x30,0x8b,0x44,0x24,0x60,0x41,0x0f,0xb6,0xd8,0x89,0x44}, 16) &&
        bytes_equal(0xbb48f0, (const u8[]){0x48,0x89,0x5c,0x24,0x10,0x57,0x48,0x83,0xec,0x30,0x80,0x3d,0x51,0xd2,0xa2,0x02}, 16) &&
        bytes_equal(0x6fcfa0, (const u8[]){0x83,0xb9,0x1c,0x04,0x00,0x00,0x01,0x0f,0x9c,0xc0,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc}, 16) &&
        bytes_equal(0x535e00, (const u8[]){0x48,0x83,0xec,0x28,0x48,0x83,0xc1,0x50,0x83,0x39,0x00,0x75,0x06,0x83,0x79,0x04}, 16) &&
        bytes_equal(0xbb52f0, (const u8[]){0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xec,0x30,0x80,0x3d,0x51,0xc8,0xa2,0x02}, 16) &&
        bytes_equal(0x1c9cd0, (const u8[]){0x4c,0x8b,0xc9,0x83,0xfa,0xfe,0x74,0x54,0x83,0xfa,0xff,0x74,0x38,0x48,0x63,0x81}, 16) &&
        bytes_equal(0xf6eb40, (const u8[]){0x48,0x8b,0x81,0x88,0x00,0x00,0x00,0x48,0x8b,0x90,0xf0,0x03,0x00,0x00,0x48,0x8b}, 16) &&
        bytes_equal(0xf6f430, (const u8[]){0x48,0x8b,0x89,0x88,0x00,0x00,0x00,0xe9,0x64,0xaa,0xc6,0xff,0xcc,0xcc,0xcc,0xcc}, 16) &&
        bytes_equal(0xf70990, (const u8[]){0x8b,0x05,0x9a,0x57,0x3c,0x02,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc}, 16) &&
        bytes_equal(0x1399890, (const u8[]){0x40,0x53,0x48,0x83,0xec,0x20,0x80,0x79,0x60,0x00,0x48,0x8b,0xda,0x75,0x0f,0x48}, 16);
}

int AuthorityGuardVerify(void) {
    if (!imageBase || !verify_static_sites()) { inc_stat(STAT_VERIFY_FAILURES); return 0; }
    int installedCount = 0;
    for (size_t i = 0; i < hookSetCount; ++i) {
        VtableHookStatus status;
        VtableHookGetStatus(&hookSets[i], &status);
        if (status.state == VTABLE_HOOK_INSTALLED) ++installedCount;
        else if (status.state != VTABLE_HOOK_PREPARED) return 0;
    }
    if (installedCount && (size_t)installedCount != hookSetCount) return 0;
    VtableHookStatus lifecycleStatus;
    VtableHookGetStatus(&lifecycleHookSet, &lifecycleStatus);
    int lifecycleInstalled = lifecycleStatus.state == VTABLE_HOOK_INSTALLED;
    if (lifecycleStatus.state != VTABLE_HOOK_INSTALLED && lifecycleStatus.state != VTABLE_HOOK_PREPARED)
        return 0;
    if (installedCount && !lifecycleInstalled) return 0;
    VtableHookStatus scriptStatus;
    VtableHookGetStatus(&scriptGetterHookSet, &scriptStatus);
    int scriptInstalled = scriptStatus.state == VTABLE_HOOK_INSTALLED;
    if (scriptStatus.state != VTABLE_HOOK_INSTALLED && scriptStatus.state != VTABLE_HOOK_PREPARED)
        return 0;
    if (installedCount && !scriptInstalled) return 0;
    void *loadTaskPointer = NULL;
    if (!copy_from_process(imageBase + 0x2723ca0 + 8, &loadTaskPointer, sizeof(loadTaskPointer)) ||
        loadTaskPointer != (lifecycleInstalled ? (void *)guarded_load_task : imageBase + 0x1f71b0)) return 0;
    void *scriptPointer = NULL;
    if (!copy_from_process(imageBase + 0x276f848 + 0xc8, &scriptPointer, sizeof(scriptPointer)) ||
        scriptPointer != (scriptInstalled ? (void *)guarded_script_getter : imageBase + 0x1399890)) return 0;
    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i) {
        CoveredClass *row = &classes[i];
        void *vtable = imageBase + row->vtableRva;
        void *dtor = NULL, *valid = NULL, *loggable = NULL;
        if (!copy_from_process(vtable, &dtor, sizeof(dtor)) || !copy_from_process((u8 *)vtable + 0x48, &valid, sizeof(valid)) ||
            !copy_from_process((u8 *)vtable + 0x60, &loggable, sizeof(loggable)) ||
            (installedCount ? (dtor != (void *)guarded_destructor || valid != (void *)guarded_is_valid ||
                loggable != (void *)guarded_loggable) :
                (dtor != imageBase + row->dtorRva || valid != imageBase + row->validRva || loggable != imageBase + row->logRva)))
            return 0;
        if (row->executeRva) {
            void *execute = NULL;
            if (!copy_from_process((u8 *)vtable + 0x50, &execute, sizeof(execute)) ||
                execute != (installedCount ? (void *)guarded_execute : imageBase + row->executeRva)) return 0;
        }
    }
    return 1;
}

int AuthorityGuardStart(AuthorityGuardLogger logger) {
    if (InterlockedCompareExchange(&stateValue, AUTHORITY_GUARD_VERIFYING, AUTHORITY_GUARD_STOPPED) != AUTHORITY_GUARD_STOPPED)
        return AuthorityGuardVerify();
    logCallback = logger;
    imageBase = (unsigned char *)GetModuleHandleW(NULL);
    if (!imageBase) goto fail;
    IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS64 nt;
    if (!copy_from_process(imageBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !copy_from_process(imageBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) goto fail;
    imageSize = nt.OptionalHeader.SizeOfImage;
    WCHAR path[32768]; DWORD pathLength = GetModuleFileNameW(NULL, path, (DWORD)(sizeof(path)/sizeof(path[0])));
    char digest[65];
    if (!pathLength || pathLength >= sizeof(path)/sizeof(path[0]) || !sha_file(path, digest) ||
        _stricmp(digest, GAME_SHA256) != 0 || !verify_static_sites()) goto fail;
    senderResolver = (SenderResolverFn)(imageBase + 0x23e5cb0);
    memset(peers, 0, sizeof(peers));
    trackedServer = 0; trackedContext = 0;
    AuthorityPolicyInit(&policy, current_epoch());
    CommandProvenanceInit(&provenance, current_epoch());
    VtableHookSpec specs[AUTH_MAX_HOOKS]; memset(specs, 0, sizeof(specs));
    size_t total = (sizeof(classes)/sizeof(classes[0])) * 3;
    for (size_t i = 0; i < sizeof(classes)/sizeof(classes[0]); ++i)
        if (classes[i].executeRva) ++total;
    if (total > sizeof(hookRefs)/sizeof(hookRefs[0])) goto fail;
    for (size_t i = 0; i < sizeof(classes)/sizeof(classes[0]); ++i) {
        CoveredClass *row = &classes[i];
        const char *hex[4] = {row->dtorBytes,row->validBytes,row->logBytes,row->executeBytes};
        uint32_t targets[4] = {row->dtorRva,row->validRva,row->logRva,row->executeRva};
        uint32_t offsets[4] = {0,0x48,0x60,0x50};
        void *wrappers[4] = {(void *)guarded_destructor,(void *)guarded_is_valid,(void *)guarded_loggable,(void *)guarded_execute};
        for (unsigned j = 0; j < 4; ++j) {
            if (j == 3 && !row->executeRva) continue;
            size_t index = hookRefCount++;
            unsigned originalSlot = j == 3 ? 3u : j;
            HookRef *ref = &hookRefs[index]; ref->classIndex = i; ref->slot = originalSlot;
            size_t fingerprintLength = j == 3 ? 16u : 12u;
            u8 bytes[16]; if (!decode_hex(hex[j], bytes, fingerprintLength)) goto fail;
            size_t batch = index / AUTH_MAX_HOOKS, entry = index % AUTH_MAX_HOOKS;
            specs[entry].slot_rva = row->vtableRva + offsets[j]; specs[entry].original_rva = targets[j];
            specs[entry].entry_length = (uint32_t)fingerprintLength;
            memcpy(specs[entry].expected_entry, bytes, fingerprintLength);
            specs[entry].wrapper = wrappers[j];
            if (entry + 1 == AUTH_MAX_HOOKS || index + 1 == total) {
                if (VtableHookPrepare(&hookSets[batch], specs, entry + 1) != VTABLE_HOOK_OK) goto fail;
                for (size_t k = 0; k <= entry; ++k) {
                    HookRef *r = &hookRefs[batch * AUTH_MAX_HOOKS + k];
                    CoveredClass *owner = &classes[r->classIndex];
                    void *fn = VtableHookOriginal(&hookSets[batch], k);
                    if (r->slot == 0) owner->originalDestructor = (DestructorFn)fn;
                    else if (r->slot == 1) owner->originalValid = (IsValidFn)fn;
                    else if (r->slot == 2) owner->originalLoggable = (LoggableFn)fn;
                    else owner->originalExecute = (ExecuteFn)fn;
                }
                ++hookSetCount; memset(specs, 0, sizeof(specs));
            }
        }
    }
    MemoryBarrier();
    for (size_t i = 0; i < hookSetCount; ++i)
        if (VtableHookInstall(&hookSets[i]) != VTABLE_HOOK_OK) goto fail;
    VtableHookSpec lifecycleSpec; memset(&lifecycleSpec, 0, sizeof(lifecycleSpec));
    lifecycleSpec.slot_rva = 0x2723ca0 + 8;
    lifecycleSpec.original_rva = 0x1f71b0;
    lifecycleSpec.entry_length = 16;
    memcpy(lifecycleSpec.expected_entry,
        (const u8[]){0x48,0x83,0xec,0x28,0x48,0x8b,0x49,0x08,0xe8,0xa3,0x18,0xfd,0xff,0x33,0xc0,0x48}, 16);
    lifecycleSpec.wrapper = (void *)guarded_load_task;
    if (VtableHookPrepare(&lifecycleHookSet, &lifecycleSpec, 1) != VTABLE_HOOK_OK) goto fail;
    originalLoadTask = (LoadTaskFn)VtableHookOriginal(&lifecycleHookSet, 0);
    MemoryBarrier();
    if (VtableHookInstall(&lifecycleHookSet) != VTABLE_HOOK_OK) goto fail;
    VtableHookSpec scriptSpec; memset(&scriptSpec, 0, sizeof(scriptSpec));
    scriptSpec.slot_rva = 0x276f848 + 0xc8;
    scriptSpec.original_rva = 0x1399890;
    scriptSpec.entry_length = 16;
    memcpy(scriptSpec.expected_entry,
        (const u8[]){0x40,0x53,0x48,0x83,0xec,0x20,0x80,0x79,0x60,0x00,0x48,0x8b,0xda,0x75,0x0f,0x48}, 16);
    scriptSpec.wrapper = (void *)guarded_script_getter;
    if (VtableHookPrepare(&scriptGetterHookSet, &scriptSpec, 1) != VTABLE_HOOK_OK) goto fail;
    originalScriptGetter = (ScriptGetterFn)VtableHookOriginal(&scriptGetterHookSet, 0);
    MemoryBarrier();
    if (VtableHookInstall(&scriptGetterHookSet) != VTABLE_HOOK_OK) goto fail;
    if (!AuthorityGuardVerify()) goto fail;
    InterlockedExchange(&active, 1);
    InterlockedExchange(&stateValue, AUTHORITY_GUARD_INSTALLED);
    log_message("AUTHORITY_GUARD_INSTALLED");
    return 1;
fail:
    inc_stat(STAT_INSTALL_FAILURES);
    InterlockedExchange(&stateValue, AUTHORITY_GUARD_FAILED);
    log_message("AUTHORITY_GUARD_FAILED_CLOSED");
    return 0;
}

void AuthorityGuardStop(void) { InterlockedExchange(&stopped, 1); InterlockedExchange(&active, 0); }
int AuthorityGuardInstalled(void) { return InterlockedCompareExchange(&stateValue,0,0) == AUTHORITY_GUARD_INSTALLED; }
AuthorityGuardState AuthorityGuardGetState(void) { return (AuthorityGuardState)InterlockedCompareExchange(&stateValue,0,0); }
void AuthorityGuardGetStats(AuthorityGuardStats *out) {
    if (!out) return;
    uint64_t *values = (uint64_t *)out;
    for (size_t i = 0; i < sizeof(*out)/sizeof(uint64_t) && i < 16; ++i)
        values[i] = (uint64_t)InterlockedCompareExchange64(&stats[i],0,0);
}

static size_t append_text(char *buffer, size_t offset, const char *text) {
    while (*text) buffer[offset++] = *text++;
    return offset;
}

static size_t append_decimal(char *buffer, size_t offset, uint64_t value) {
    char digits[24]; size_t count = 0;
    do { digits[count++] = (char)('0' + (value % 10)); value /= 10; } while (value && count < sizeof(digits));
    while (count) buffer[offset++] = digits[--count];
    return offset;
}

void AuthorityGuardFlushDiagnostics(void) {
    static const char *reasonNames[] = {
        "none", "native_invalid", "facts_unknown", "peer_invalid", "session_mismatch",
        "unreviewed", "actor_not_controlled", "requester_mismatch", "host_only_remote",
        "country_change_unauthorized", "assignment_locked", "grant_used", "grant_capacity", "grant_invalid",
        "equipment_level_invalid", "idea_mutation_invalid", "event_payload_invalid",
        "factory_payload_invalid", "mio_reference_invalid", "mio_owner_not_controlled"
    };
    _Static_assert(sizeof(reasonNames) / sizeof(reasonNames[0]) ==
        AUTHORITY_REASON_MIO_OWNER_NOT_CONTROLLED + 1,
        "diagnostic reason names must cover every AuthorityReason");
    if (!logCallback) return;
    for (size_t i = 1; i < sizeof(reasonNames) / sizeof(reasonNames[0]); ++i) {
        uint64_t count = (uint64_t)InterlockedExchange64(&rejectionReasons[i], 0);
        if (!count) continue;
        char line[128]; size_t end = 0;
        end = append_text(line, end, "AUTHORIZATION_REJECTED reason=");
        end = append_text(line, end, reasonNames[i]);
        end = append_text(line, end, " count=");
        end = append_decimal(line, end, count);
        line[end] = '\0';
        logCallback(line);
    }
}

#ifdef AUTHORITY_GUARD_TEST
int AuthorityGuardTestEvaluate(AuthorityPolicy *testPolicy, CommandProvenanceStore *testStore,
    CommandProvenanceSnapshot *snapshot, AuthorityFacts *facts,
    int (*nativeValid)(void *), void *command, uint64_t now, int commit) {
    if (!nativeValid || !snapshot || !facts) return 0;
    int valid = nativeValid(command);
    if (!valid) return 0;
    if (snapshot->sessionEpoch != facts->sessionEpoch) return 0;
    int cached = 0;
    if (CommandProvenanceGetDecision(testStore, snapshot, 1, &cached) == COMMAND_PROVENANCE_DECISION_OK)
        return cached;
    facts->nativeValid = 1; facts->commit = commit;
    AuthorityResult result = AuthorityPolicyEvaluate(testPolicy, facts, now);
    if (commit && (result.decision == AUTHORITY_DECISION_ALLOW || result.decision == AUTHORITY_DECISION_DENY))
        CommandProvenanceCommitDecision(testStore, snapshot, 1, result.decision == AUTHORITY_DECISION_ALLOW);
    return result.decision != AUTHORITY_DECISION_DENY;
}
int AuthorityGuardTestDestroy(CommandProvenanceStore *testStore,
    const CommandProvenanceSnapshot *snapshot, void (*nativeDestroy)(void *), void *command) {
    int removed = CommandProvenanceRemove(testStore, snapshot);
    if (nativeDestroy) nativeDestroy(command);
    return removed;
}
#endif
