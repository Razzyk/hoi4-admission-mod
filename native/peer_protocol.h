#ifndef HOI4_PEER_PROTOCOL_H
#define HOI4_PEER_PROTOCOL_H

#include "protocol.h"

#define PEER_PROTOCOL_VERSION 1u
#define PEER_OFFER_BYTES 112u
#define PEER_MESSAGE_BYTES 152u
#define PEER_MAX_PACKET 65536u
#define PEER_STATE_CAPACITY 64u
#define PEER_REPLAY_CAPACITY 128u
#define PEER_LIFETIME_MS 10000u
#define PEER_MESSAGE_CHALLENGE 0x48345043u
#define PEER_MESSAGE_RESPONSE 0x48345052u

#pragma pack(push, 1)
typedef struct PeerOfferWire {
    unsigned char magic[8];
    uint32_t version;
    uint32_t originalLength;
    unsigned char clientNonce[32];
    unsigned char dllHash[32];
    unsigned char manifestHash[32];
} PeerOfferWire;

typedef struct PeerMessageWire {
    uint32_t type;
    uint32_t reserved;
    unsigned char magic[8];
    uint32_t version;
    uint32_t joinType;
    unsigned char clientNonce[32];
    unsigned char hostNonce[32];
    unsigned char packetHash[32];
    unsigned char proof[32];
} PeerMessageWire;
#pragma pack(pop)

_Static_assert(sizeof(PeerOfferWire) == PEER_OFFER_BYTES, "Peer offer wire layout mismatch");
_Static_assert(sizeof(PeerMessageWire) == PEER_MESSAGE_BYTES, "Peer message wire layout mismatch");

typedef struct PeerClientSlot {
    int active;
    uintptr_t server;
    uintptr_t connection;
    uint32_t joinType;
    uint64_t issuedAt;
    unsigned char packetHash[32];
    unsigned char clientNonce[32];
} PeerClientSlot;

typedef struct PeerClientState {
    unsigned char dllHash[32];
    unsigned char manifestHash[32];
    PeerClientSlot slots[PEER_STATE_CAPACITY];
    SRWLOCK lock;
} PeerClientState;

typedef struct PeerHostSlot {
    int active;
    uintptr_t server;
    uintptr_t connection;
    uint32_t joinType;
    uint64_t issuedAt;
    unsigned char clientNonce[32];
    unsigned char hostNonce[32];
    unsigned char packetHash[32];
    unsigned char challenge[PEER_MESSAGE_BYTES];
    unsigned char *originalPacket;
    uint32_t originalLength;
} PeerHostSlot;

typedef struct PeerReplayEntry {
    int active;
    uintptr_t server;
    uintptr_t connection;
    uint64_t issuedAt;
    unsigned char clientNonce[32];
} PeerReplayEntry;

typedef struct PeerHostState {
    unsigned char dllHash[32];
    unsigned char manifestHash[32];
    PeerHostSlot slots[PEER_STATE_CAPACITY];
    PeerReplayEntry replay[PEER_REPLAY_CAPACITY];
    uint64_t replayBlockedUntil;
    SRWLOCK lock;
} PeerHostState;

// These checks establish only protocol compatibility. The proof is public SHA-256,
// not a credential, signature, remote attestation, or anti-tamper guarantee.
void PeerClientInit(PeerClientState *state, const unsigned char dllHash[32], const unsigned char manifestHash[32]);
void PeerClientDestroy(PeerClientState *state);
// Each call represents a new outgoing join and receives a fresh nonce. Retransmit the
// returned wire bytes unchanged to get the host's idempotent cached challenge.
int PeerClientMakeOffer(PeerClientState *state, uintptr_t server, uint32_t joinType,
    const void *packet, uint32_t packetLength, uint64_t nowMs,
    void *output, uint32_t outputCapacity, uint32_t *outputLength);
int PeerClientAnswer(PeerClientState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *challenge, uint32_t challengeLength,
    void *response, uint32_t responseCapacity);

void PeerHostInit(PeerHostState *state, const unsigned char dllHash[32], const unsigned char manifestHash[32]);
int PeerHostChallenge(PeerHostState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *offeredPacket, uint32_t offeredLength,
    void *challenge, uint32_t challengeCapacity);
int PeerHostAccept(PeerHostState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *response, uint32_t responseLength,
    void *originalPacket, uint32_t originalCapacity, uint32_t *originalLength);
void PeerHostDestroy(PeerHostState *state);
void PeerHostClear(PeerHostState *state);

#endif
