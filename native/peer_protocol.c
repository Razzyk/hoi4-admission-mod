#include "peer_protocol.h"
#include <stdlib.h>

static const unsigned char peer_magic[8] = {'H','4','P','E','E','R','1',0};
static const unsigned char proof_domain[] = "HOI4-PEER-PROOF-V1";

static uint32_t read32(const void *p) { uint32_t value; memcpy(&value, p, sizeof(value)); return value; }
static void write32(void *p, uint32_t value) { memcpy(p, &value, sizeof(value)); }
static int join_type(uint32_t type) { return type == 8u || type == 9u || type == 14u; }
static int all_zero(const unsigned char *p, size_t length) {
    unsigned char value = 0;
    for (size_t i = 0; i < length; ++i) value |= p[i];
    return value == 0;
}
static int same(const void *a, const void *b, size_t length) { return memcmp(a, b, length) == 0; }
static int fresh(uint64_t issued, uint64_t now) { return now >= issued && now - issued < PEER_LIFETIME_MS; }
static int random_bytes(unsigned char *out, ULONG length) {
    return BCryptGenRandom(NULL, out, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}
static int digest_bytes(const void *bytes, size_t length, unsigned char digest[32]) {
    char hex[65];
    return sha_bytes(bytes, length, hex) && hex_decode(hex, digest, 32);
}
static int proof_for(const PeerMessageWire *message, const unsigned char dllHash[32],
    const unsigned char manifestHash[32], unsigned char proof[32]) {
    unsigned char input[(sizeof(proof_domain) - 1u) + 120u + 64u];
    size_t offset = 0;
    memcpy(input + offset, proof_domain, sizeof(proof_domain) - 1u); offset += sizeof(proof_domain) - 1u;
    memcpy(input + offset, message, 120u);
    write32(input + offset, PEER_MESSAGE_CHALLENGE);
    offset += 120u;
    memcpy(input + offset, dllHash, 32u); offset += 32u;
    memcpy(input + offset, manifestHash, 32u); offset += 32u;
    int ok = digest_bytes(input, offset, proof);
    SecureZeroMemory(input, sizeof(input));
    return ok;
}
static int valid_message(const PeerMessageWire *m, uint32_t expectedType) {
    return read32(&m->type) == expectedType && read32(&m->reserved) == 0 &&
        same(m->magic, peer_magic, sizeof(peer_magic)) && read32(&m->version) == PEER_PROTOCOL_VERSION &&
        join_type(read32(&m->joinType)) && !all_zero(m->clientNonce, 32) && !all_zero(m->hostNonce, 32);
}
static void clear_client_slot(PeerClientSlot *slot) { SecureZeroMemory(slot, sizeof(*slot)); }
static void clear_host_slot(PeerHostSlot *slot) {
    if (slot->originalPacket) {
        SecureZeroMemory(slot->originalPacket, slot->originalLength);
        HeapFree(GetProcessHeap(), 0, slot->originalPacket);
    }
    SecureZeroMemory(slot, sizeof(*slot));
}
static void prune_client(PeerClientState *state, uint64_t now) {
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i)
        if (state->slots[i].active && !fresh(state->slots[i].issuedAt, now)) clear_client_slot(&state->slots[i]);
}
static void prune_replay(PeerHostState *state, uint64_t now) {
    for (size_t i = 0; i < PEER_REPLAY_CAPACITY; ++i)
        if (state->replay[i].active && !fresh(state->replay[i].issuedAt, now)) SecureZeroMemory(&state->replay[i], sizeof(state->replay[i]));
}
static void prune_host(PeerHostState *state, uint64_t now) {
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i)
        if (state->slots[i].active && !fresh(state->slots[i].issuedAt, now)) clear_host_slot(&state->slots[i]);
    prune_replay(state, now);
}
static int replayed(PeerHostState *state, uintptr_t server, uintptr_t connection, const unsigned char nonce[32]) {
    for (size_t i = 0; i < PEER_REPLAY_CAPACITY; ++i) {
        PeerReplayEntry *entry = &state->replay[i];
        if (entry->active && entry->server == server && entry->connection == connection &&
            same(entry->clientNonce, nonce, 32)) return 1;
    }
    return 0;
}
static int burn_nonce(PeerHostState *state, const PeerHostSlot *slot) {
    for (size_t i = 0; i < PEER_REPLAY_CAPACITY; ++i) {
        PeerReplayEntry *entry = &state->replay[i];
        if (!entry->active) {
            entry->active = 1; entry->server = slot->server; entry->connection = slot->connection;
            entry->issuedAt = slot->issuedAt; memcpy(entry->clientNonce, slot->clientNonce, 32);
            return 1;
        }
    }
    // Losing replay memory would make a previously consumed offer usable again.
    // Stop processing offers until the unrecordable nonce reaches its expiry.
    state->replayBlockedUntil = slot->issuedAt > UINT64_MAX - PEER_LIFETIME_MS ? UINT64_MAX : slot->issuedAt + PEER_LIFETIME_MS;
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) clear_host_slot(&state->slots[i]);
    return 0;
}

void PeerClientInit(PeerClientState *state, const unsigned char dllHash[32], const unsigned char manifestHash[32]) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    InitializeSRWLock(&state->lock);
    if (dllHash) memcpy(state->dllHash, dllHash, 32);
    if (manifestHash) memcpy(state->manifestHash, manifestHash, 32);
}

void PeerClientDestroy(PeerClientState *state) {
    if (!state) return;
    AcquireSRWLockExclusive(&state->lock);
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) clear_client_slot(&state->slots[i]);
    SecureZeroMemory(state->dllHash, sizeof(state->dllHash));
    SecureZeroMemory(state->manifestHash, sizeof(state->manifestHash));
    ReleaseSRWLockExclusive(&state->lock);
}

int PeerClientMakeOffer(PeerClientState *state, uintptr_t server, uint32_t type,
    const void *packet, uint32_t packetLength, uint64_t nowMs,
    void *output, uint32_t outputCapacity, uint32_t *outputLength) {
    if (outputLength) *outputLength = 0;
    if (!state || !server || !packet || !output || !outputLength || !join_type(type) ||
        packetLength < 8u || packetLength > PEER_MAX_PACKET - PEER_OFFER_BYTES ||
        read32(packet) != type || outputCapacity < packetLength + PEER_OFFER_BYTES) return 0;

    unsigned char packetHash[32], nonce[32];
    if (!digest_bytes(packet, packetLength, packetHash) || !random_bytes(nonce, sizeof(nonce))) return 0;
    AcquireSRWLockExclusive(&state->lock);
    prune_client(state, nowMs);
    PeerClientSlot *slot = NULL;
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i)
        if (!state->slots[i].active) { slot = &state->slots[i]; break; }
    if (!slot) { ReleaseSRWLockExclusive(&state->lock); SecureZeroMemory(nonce, sizeof(nonce)); return 0; }
    clear_client_slot(slot);
    slot->active = 1;
    slot->server = server;
    slot->joinType = type;
    slot->issuedAt = nowMs;
    memcpy(slot->packetHash, packetHash, 32);
    memcpy(slot->clientNonce, nonce, 32);
    memcpy(output, packet, packetLength);
    PeerOfferWire offer;
    memset(&offer, 0, sizeof(offer));
    memcpy(offer.magic, peer_magic, sizeof(peer_magic));
    offer.version = PEER_PROTOCOL_VERSION;
    offer.originalLength = packetLength;
    memcpy(offer.clientNonce, slot->clientNonce, 32);
    memcpy(offer.dllHash, state->dllHash, 32);
    memcpy(offer.manifestHash, state->manifestHash, 32);
    memcpy((unsigned char *)output + packetLength, &offer, sizeof(offer));
    *outputLength = packetLength + PEER_OFFER_BYTES;
    ReleaseSRWLockExclusive(&state->lock);
    SecureZeroMemory(packetHash, sizeof(packetHash));
    SecureZeroMemory(nonce, sizeof(nonce));
    return 1;
}

int PeerClientAnswer(PeerClientState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *challenge, uint32_t challengeLength,
    void *response, uint32_t responseCapacity) {
    if (!state || !server || !connection || !challenge || !response ||
        challengeLength != PEER_MESSAGE_BYTES || responseCapacity < PEER_MESSAGE_BYTES) return 0;
    const PeerMessageWire *incoming = (const PeerMessageWire *)challenge;
    if (!valid_message(incoming, PEER_MESSAGE_CHALLENGE) || !all_zero(incoming->proof, 32)) return 0;

    AcquireSRWLockExclusive(&state->lock);
    prune_client(state, nowMs);
    PeerClientSlot *slot = NULL;
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) {
        PeerClientSlot *candidate = &state->slots[i];
        if (candidate->active && candidate->server == server && candidate->joinType == read32(&incoming->joinType) &&
            same(candidate->clientNonce, incoming->clientNonce, 32) && same(candidate->packetHash, incoming->packetHash, 32)) {
            slot = candidate; break;
        }
    }
    if (!slot || !same(incoming->magic, peer_magic, 8) || all_zero(incoming->hostNonce, 32)) {
        ReleaseSRWLockExclusive(&state->lock); return 0;
    }
    // The host independently validates both offer hashes against its configured build.
    if (slot->connection && slot->connection != connection) { ReleaseSRWLockExclusive(&state->lock); return 0; }
    if (!slot->connection) slot->connection = connection;
    PeerMessageWire answer = *incoming;
    answer.type = PEER_MESSAGE_RESPONSE;
    int ok = proof_for(incoming, state->dllHash, state->manifestHash, answer.proof);
    if (ok) memcpy(response, &answer, sizeof(answer));
    ReleaseSRWLockExclusive(&state->lock);
    SecureZeroMemory(&answer, sizeof(answer));
    return ok;
}

void PeerHostInit(PeerHostState *state, const unsigned char dllHash[32], const unsigned char manifestHash[32]) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    InitializeSRWLock(&state->lock);
    if (dllHash) memcpy(state->dllHash, dllHash, 32);
    if (manifestHash) memcpy(state->manifestHash, manifestHash, 32);
}

int PeerHostChallenge(PeerHostState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *offeredPacket, uint32_t offeredLength,
    void *challenge, uint32_t challengeCapacity) {
    if (!state || !server || !connection || !offeredPacket || !challenge ||
        offeredLength < 8u + PEER_OFFER_BYTES || offeredLength > PEER_MAX_PACKET ||
        challengeCapacity < PEER_MESSAGE_BYTES) return 0;
    const unsigned char *bytes = (const unsigned char *)offeredPacket;
    const PeerOfferWire *offer = (const PeerOfferWire *)(bytes + offeredLength - PEER_OFFER_BYTES);
    uint32_t originalLength = read32(&offer->originalLength), type = read32(bytes);
    if (!same(offer->magic, peer_magic, 8) || read32(&offer->version) != PEER_PROTOCOL_VERSION ||
        !join_type(type) || originalLength < 8u || originalLength != offeredLength - PEER_OFFER_BYTES ||
        originalLength > PEER_MAX_PACKET - PEER_OFFER_BYTES || !same(offer->dllHash, state->dllHash, 32) ||
        !same(offer->manifestHash, state->manifestHash, 32) || all_zero(offer->clientNonce, 32)) return 0;
    unsigned char packetHash[32], hostNonce[32];
    if (!digest_bytes(bytes, originalLength, packetHash) || !random_bytes(hostNonce, sizeof(hostNonce))) return 0;

    AcquireSRWLockExclusive(&state->lock);
    prune_host(state, nowMs);
    if (state->replayBlockedUntil && nowMs < state->replayBlockedUntil) {
        ReleaseSRWLockExclusive(&state->lock);
        SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce));
        return 0;
    }
    if (state->replayBlockedUntil) state->replayBlockedUntil = 0;
    if (replayed(state, server, connection, offer->clientNonce)) {
        ReleaseSRWLockExclusive(&state->lock);
        SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce));
        return 0;
    }
    PeerHostSlot *slot = NULL, *replacement = NULL, *freeSlot = NULL, *duplicate = NULL;
    int nonceCollision = 0;
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) {
        PeerHostSlot *candidate = &state->slots[i];
        if (!candidate->active) { if (!freeSlot) freeSlot = candidate; continue; }
        if (candidate->server != server || candidate->connection != connection) continue;
        if (same(candidate->clientNonce, offer->clientNonce, 32)) {
            if (candidate->joinType == type && same(candidate->packetHash, packetHash, 32)) duplicate = candidate;
            else nonceCollision = 1;
        }
        if (candidate->joinType == type) {
            // A fresh offer on this connection supersedes its previous pending join.
            if (!replacement) replacement = candidate;
        }
    }
    if (nonceCollision) {
        ReleaseSRWLockExclusive(&state->lock);
        SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce));
        return 0;
    }
    if (duplicate) {
        memcpy(challenge, duplicate->challenge, PEER_MESSAGE_BYTES);
        ReleaseSRWLockExclusive(&state->lock);
        SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce));
        return 1;
    }
    slot = replacement;
    if (!slot) slot = freeSlot;
    if (!slot) { ReleaseSRWLockExclusive(&state->lock); SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce)); return 0; }
    clear_host_slot(slot);
    unsigned char *copy = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, originalLength);
    if (!copy) { ReleaseSRWLockExclusive(&state->lock); SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce)); return 0; }
    memcpy(copy, bytes, originalLength);
    PeerMessageWire message;
    memset(&message, 0, sizeof(message));
    message.type = PEER_MESSAGE_CHALLENGE;
    memcpy(message.magic, peer_magic, 8);
    message.version = PEER_PROTOCOL_VERSION;
    message.joinType = type;
    memcpy(message.clientNonce, offer->clientNonce, 32);
    memcpy(message.hostNonce, hostNonce, 32);
    memcpy(message.packetHash, packetHash, 32);
    slot->active = 1; slot->server = server; slot->connection = connection; slot->joinType = type;
    slot->issuedAt = nowMs; memcpy(slot->clientNonce, offer->clientNonce, 32);
    memcpy(slot->hostNonce, hostNonce, 32); memcpy(slot->packetHash, packetHash, 32);
    slot->originalPacket = copy; slot->originalLength = originalLength;
    memcpy(slot->challenge, &message, sizeof(message));
    memcpy(challenge, &message, sizeof(message));
    ReleaseSRWLockExclusive(&state->lock);
    SecureZeroMemory(packetHash, sizeof(packetHash)); SecureZeroMemory(hostNonce, sizeof(hostNonce));
    SecureZeroMemory(&message, sizeof(message));
    return 1;
}

int PeerHostAccept(PeerHostState *state, uintptr_t server, uintptr_t connection,
    uint64_t nowMs, const void *response, uint32_t responseLength,
    void *originalPacket, uint32_t originalCapacity, uint32_t *originalLength) {
    if (originalLength) *originalLength = 0;
    if (!state || !server || !connection || !response || !originalPacket || !originalLength || responseLength < 56u) return 0;
    const PeerMessageWire *incoming = (const PeerMessageWire *)response;
    // The client nonce is the lookup key. A matching response consumes its pending slot
    // before any other response field or proof is inspected, including malformed replies.
    AcquireSRWLockExclusive(&state->lock);
    prune_replay(state, nowMs);
    PeerHostSlot consumed;
    memset(&consumed, 0, sizeof(consumed));
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) {
        PeerHostSlot *candidate = &state->slots[i];
        if (candidate->active && candidate->server == server && candidate->connection == connection &&
            same(candidate->clientNonce, incoming->clientNonce, 32)) {
            (void)burn_nonce(state, candidate);
            consumed = *candidate;
            candidate->originalPacket = NULL;
            SecureZeroMemory(candidate, sizeof(*candidate));
            break;
        }
    }
    ReleaseSRWLockExclusive(&state->lock);
    if (!consumed.active) return 0;
    int ok = responseLength == PEER_MESSAGE_BYTES && fresh(consumed.issuedAt, nowMs) && valid_message(incoming, PEER_MESSAGE_RESPONSE) &&
        read32(&incoming->joinType) == consumed.joinType &&
        same(incoming->clientNonce, consumed.clientNonce, 32) &&
        same(incoming->hostNonce, consumed.hostNonce, 32) &&
        same(incoming->packetHash, consumed.packetHash, 32) &&
        consumed.originalLength <= originalCapacity;
    unsigned char expected[32];
    if (ok) ok = proof_for(incoming, state->dllHash, state->manifestHash, expected) && same(expected, incoming->proof, 32);
    SecureZeroMemory(expected, sizeof(expected));
    if (ok) {
        memcpy(originalPacket, consumed.originalPacket, consumed.originalLength);
        *originalLength = consumed.originalLength;
    }
    clear_host_slot(&consumed);
    return ok;
}

void PeerHostClear(PeerHostState *state) {
    if (!state) return;
    AcquireSRWLockExclusive(&state->lock);
    for (size_t i = 0; i < PEER_STATE_CAPACITY; ++i) clear_host_slot(&state->slots[i]);
    SecureZeroMemory(state->replay, sizeof(state->replay));
    state->replayBlockedUntil = 0;
    ReleaseSRWLockExclusive(&state->lock);
}

void PeerHostDestroy(PeerHostState *state) {
    if (!state) return;
    PeerHostClear(state);
    AcquireSRWLockExclusive(&state->lock);
    SecureZeroMemory(state->dllHash, sizeof(state->dllHash));
    SecureZeroMemory(state->manifestHash, sizeof(state->manifestHash));
    ReleaseSRWLockExclusive(&state->lock);
}
