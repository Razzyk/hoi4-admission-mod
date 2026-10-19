#include "../native/peer_protocol.c"
#include <process.h>

static unsigned assertions;
static void check(int condition, const char *name, unsigned line) {
    ++assertions;
    if (!condition) { fprintf(stderr, "FAIL line %u: %s\n", line, name); exit(1); }
}
#define CHECK(x) check(!!(x), #x, __LINE__)

static unsigned char dllHash[32], manifestHash[32];
static unsigned char packet[512], offered[512 + PEER_OFFER_BYTES];
static unsigned char challenge[PEER_MESSAGE_BYTES], response[PEER_MESSAGE_BYTES];
static unsigned char restored[PEER_MAX_PACKET];

static void make_packet(uint32_t type, unsigned seed) {
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &type, sizeof(type));
    for (size_t i = 4; i < sizeof(packet); ++i) packet[i] = (unsigned char)(seed + i * 17u);
}
static uint32_t make_offer(PeerClientState *client, uintptr_t server, uint32_t type,
    const unsigned char *input, uint32_t inputLength, uint64_t now) {
    uint32_t length = 0;
    CHECK(PeerClientMakeOffer(client, server, type, input, inputLength, now, offered, sizeof(offered), &length));
    CHECK(length == inputLength + PEER_OFFER_BYTES);
    return length;
}
static void handshake(PeerClientState *client, PeerHostState *host, uintptr_t server,
    uintptr_t connection, uint64_t now, const unsigned char *input, uint32_t inputLength) {
    uint32_t offerLength = make_offer(client, server, *(const uint32_t *)input, input, inputLength, now);
    CHECK(PeerHostChallenge(host, server, connection, now, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(client, server, connection, now, challenge, sizeof(challenge), response, sizeof(response)));
    uint32_t restoredLength = 0;
    CHECK(PeerHostAccept(host, server, connection, now, response, sizeof(response), restored, sizeof(restored), &restoredLength));
    CHECK(restoredLength == inputLength);
    CHECK(memcmp(restored, input, inputLength) == 0);
}

typedef struct RaceArg { PeerHostState *host; uintptr_t server, connection; const unsigned char *response; volatile LONG *accepted; } RaceArg;
static unsigned __stdcall race_consume(void *value) {
    RaceArg *arg = (RaceArg *)value;
    uint32_t length = 0;
    if (PeerHostAccept(arg->host, arg->server, arg->connection, 100, arg->response,
        PEER_MESSAGE_BYTES, restored, sizeof(restored), &length)) InterlockedIncrement(arg->accepted);
    return 0;
}

int main(void) {
    memset(dllHash, 0x31, sizeof(dllHash)); memset(manifestHash, 0x72, sizeof(manifestHash));
    uint32_t offerLength = 0, outputLength = 0;
    PeerClientState client; PeerHostState host;
    PeerClientInit(&client, dllHash, manifestHash); PeerHostInit(&host, dllHash, manifestHash);
    make_packet(8, 1);
    handshake(&client, &host, 11, 101, 100, packet, sizeof(packet));

    // Consumed offers are tombstoned; a distinct new send uses a fresh nonce.
    make_packet(8, 15);
    offerLength = make_offer(&client, 22, 8, packet, sizeof(packet), 150);
    unsigned char savedOffer[sizeof(offered)]; memcpy(savedOffer, offered, offerLength);
    CHECK(PeerHostChallenge(&host, 22, 130, 150, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 22, 130, 150, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(PeerHostAccept(&host, 22, 130, 151, response, sizeof(response), restored, sizeof(restored), &outputLength));
    CHECK(!PeerHostChallenge(&host, 22, 130, 152, savedOffer, offerLength, challenge, sizeof(challenge)));
    offerLength = make_offer(&client, 22, 8, packet, sizeof(packet), 152);
    CHECK(memcmp(savedOffer + sizeof(packet) + 16, offered + sizeof(packet) + 16, 32) != 0);
    CHECK(PeerHostChallenge(&host, 22, 130, 152, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 22, 130, 152, challenge, sizeof(challenge), response, sizeof(response)));
    PeerMessageWire badProof; memcpy(&badProof, response, sizeof(badProof)); badProof.proof[0] ^= 0x80;
    CHECK(!PeerHostAccept(&host, 22, 130, 153, &badProof, sizeof(badProof), restored, sizeof(restored), &outputLength));
    CHECK(!PeerHostChallenge(&host, 22, 130, 154, offered, offerLength, challenge, sizeof(challenge)));

    // Exact duplicate offers on the same connection produce the exact cached challenge.
    make_packet(8, 2);
    offerLength = make_offer(&client, 11, 8, packet, sizeof(packet), 200);
    CHECK(PeerHostChallenge(&host, 11, 101, 200, offered, offerLength, challenge, sizeof(challenge)));
    unsigned char firstChallenge[PEER_MESSAGE_BYTES]; memcpy(firstChallenge, challenge, sizeof(challenge));
    CHECK(PeerHostChallenge(&host, 11, 101, 205, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(memcmp(firstChallenge, challenge, sizeof(challenge)) == 0);
    CHECK(PeerClientAnswer(&client, 11, 101, 205, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(PeerHostAccept(&host, 11, 101, 205, response, sizeof(response), restored, sizeof(restored), &outputLength));
    CHECK(outputLength == sizeof(packet) && memcmp(restored, packet, sizeof(packet)) == 0);
    CHECK(!PeerHostAccept(&host, 11, 101, 205, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // A changed response bound to the right nonce burns that connection's pending entry.
    make_packet(9, 3);
    offerLength = make_offer(&client, 11, 9, packet, sizeof(packet), 300);
    CHECK(PeerHostChallenge(&host, 11, 102, 300, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 11, 102, 300, challenge, sizeof(challenge), response, sizeof(response)));
    PeerMessageWire corrupt; memcpy(&corrupt, response, sizeof(corrupt)); corrupt.reserved = 1;
    CHECK(!PeerHostAccept(&host, 11, 102, 301, &corrupt, sizeof(corrupt), restored, sizeof(restored), &outputLength));
    CHECK(!PeerHostAccept(&host, 11, 102, 301, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // A syntactically truncated matching response also burns its nonce slot.
    make_packet(8, 31);
    offerLength = make_offer(&client, 111, 8, packet, sizeof(packet), 310);
    CHECK(PeerHostChallenge(&host, 111, 112, 310, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 111, 112, 310, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(!PeerHostAccept(&host, 111, 112, 311, response, 56, restored, sizeof(restored), &outputLength));
    CHECK(!PeerHostAccept(&host, 111, 112, 311, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // A reply from the wrong connection cannot consume the rightful connection's slot.
    make_packet(14, 4);
    offerLength = make_offer(&client, 12, 14, packet, sizeof(packet), 400);
    CHECK(PeerHostChallenge(&host, 12, 103, 400, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 12, 103, 400, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(!PeerHostAccept(&host, 12, 104, 401, response, sizeof(response), restored, sizeof(restored), &outputLength));
    CHECK(PeerHostAccept(&host, 12, 103, 401, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // Changing the offered build is rejected by the host before it creates state.
    unsigned char wrongDll[32]; memset(wrongDll, 0xa4, sizeof(wrongDll));
    PeerClientState wrongClient; PeerClientInit(&wrongClient, wrongDll, manifestHash);
    make_packet(8, 5);
    offerLength = make_offer(&wrongClient, 13, 8, packet, sizeof(packet), 500);
    CHECK(!PeerHostChallenge(&host, 13, 105, 500, offered, offerLength, challenge, sizeof(challenge)));
    PeerClientDestroy(&wrongClient);

    // A new request of the same type/connection displaces the old pending request.
    make_packet(8, 6);
    offerLength = make_offer(&client, 14, 8, packet, sizeof(packet), 600);
    CHECK(PeerHostChallenge(&host, 14, 106, 600, offered, offerLength, challenge, sizeof(challenge)));
    unsigned char oldResponse[PEER_MESSAGE_BYTES];
    CHECK(PeerClientAnswer(&client, 14, 106, 600, challenge, sizeof(challenge), oldResponse, sizeof(oldResponse)));
    make_packet(8, 7);
    offerLength = make_offer(&client, 14, 8, packet, sizeof(packet), 601);
    CHECK(PeerHostChallenge(&host, 14, 106, 601, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(!PeerHostAccept(&host, 14, 106, 602, oldResponse, sizeof(oldResponse), restored, sizeof(restored), &outputLength));

    // Expiry is ten seconds, checked at the exact boundary. A backwards clock fails closed.
    make_packet(9, 8);
    offerLength = make_offer(&client, 15, 9, packet, sizeof(packet), 1000);
    CHECK(PeerHostChallenge(&host, 15, 107, 1000, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 15, 107, 1000, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(!PeerHostAccept(&host, 15, 107, 11000, response, sizeof(response), restored, sizeof(restored), &outputLength));
    make_packet(9, 9);
    offerLength = make_offer(&client, 16, 9, packet, sizeof(packet), 2000);
    CHECK(PeerHostChallenge(&host, 16, 108, 2000, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 16, 108, 2000, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(!PeerHostAccept(&host, 16, 108, 1999, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // Cross-server and changed-packet challenges cannot be answered by a cached client offer.
    make_packet(8, 10);
    offerLength = make_offer(&client, 17, 8, packet, sizeof(packet), 3000);
    CHECK(PeerHostChallenge(&host, 17, 109, 3000, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(!PeerClientAnswer(&client, 18, 109, 3000, challenge, sizeof(challenge), response, sizeof(response)));
    PeerMessageWire altered; memcpy(&altered, challenge, sizeof(altered)); altered.packetHash[0] ^= 1;
    CHECK(!PeerClientAnswer(&client, 17, 109, 3000, &altered, sizeof(altered), response, sizeof(response)));

    // A client binds the cached offer to the first challenged connection.
    make_packet(8, 11);
    offerLength = make_offer(&client, 20, 8, packet, sizeof(packet), 3500);
    CHECK(PeerHostChallenge(&host, 20, 120, 3500, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 20, 120, 3500, challenge, sizeof(challenge), response, sizeof(response)));
    CHECK(PeerHostChallenge(&host, 20, 121, 3501, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(!PeerClientAnswer(&client, 20, 121, 3501, challenge, sizeof(challenge), response, sizeof(response)));

    // Reusing one nonce for another type or packet on the same connection is rejected
    // without consuming the original pending handshake.
    make_packet(8, 13);
    offerLength = make_offer(&client, 30, 8, packet, sizeof(packet), 3700);
    unsigned char reusedNonceOffer[sizeof(offered)]; memcpy(reusedNonceOffer, offered, offerLength);
    CHECK(PeerHostChallenge(&host, 30, 1300, 3700, offered, offerLength, challenge, sizeof(challenge)));
    PeerMessageWire originalChallenge; memcpy(&originalChallenge, challenge, sizeof(originalChallenge));
    uint32_t otherType = 9;
    memcpy(reusedNonceOffer, &otherType, sizeof(otherType));
    CHECK(!PeerHostChallenge(&host, 30, 1300, 3701, reusedNonceOffer, offerLength, challenge, sizeof(challenge)));
    memcpy(reusedNonceOffer, offered, offerLength);
    reusedNonceOffer[19] ^= 0x40;
    CHECK(!PeerHostChallenge(&host, 30, 1300, 3701, reusedNonceOffer, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 30, 1300, 3701, &originalChallenge, sizeof(originalChallenge), response, sizeof(response)));
    CHECK(PeerHostAccept(&host, 30, 1300, 3702, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // A nonce collision in a later slot must be found even when an earlier slot is
    // already a replacement candidate for the incoming join type.
    PeerClientState collisionClient; PeerClientInit(&collisionClient, dllHash, manifestHash);
    make_packet(8, 40);
    uint32_t offerA = make_offer(&collisionClient, 31, 8, packet, sizeof(packet), 3800);
    unsigned char savedA[sizeof(offered)]; memcpy(savedA, offered, offerA);
    CHECK(PeerHostChallenge(&host, 31, 1310, 3800, offered, offerA, challenge, sizeof(challenge)));
    PeerMessageWire challengeA; memcpy(&challengeA, challenge, sizeof(challenge));
    make_packet(14, 41);
    uint32_t offerB = make_offer(&collisionClient, 31, 14, packet, sizeof(packet), 3801);
    unsigned char savedB[sizeof(offered)]; memcpy(savedB, offered, offerB);
    CHECK(PeerHostChallenge(&host, 31, 1310, 3801, offered, offerB, challenge, sizeof(challenge)));
    PeerMessageWire challengeB; memcpy(&challengeB, challenge, sizeof(challenge));
    uint32_t forgedType = 8;
    memcpy(savedB, &forgedType, sizeof(forgedType));
    CHECK(!PeerHostChallenge(&host, 31, 1310, 3802, savedB, offerB, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&collisionClient, 31, 1310, 3802, &challengeA, sizeof(challengeA), response, sizeof(response)));
    CHECK(PeerHostAccept(&host, 31, 1310, 3803, response, sizeof(response), restored, sizeof(restored), &outputLength));
    CHECK(PeerClientAnswer(&collisionClient, 31, 1310, 3802, &challengeB, sizeof(challengeB), response, sizeof(response)));
    CHECK(PeerHostAccept(&host, 31, 1310, 3803, response, sizeof(response), restored, sizeof(restored), &outputLength));
    PeerClientDestroy(&collisionClient);

    // Capacity is bounded and live slots are not evicted to make room.
    PeerClientState boundedClient, hostClient; PeerHostState boundedHost;
    PeerClientInit(&boundedClient, dllHash, manifestHash); PeerClientInit(&hostClient, dllHash, manifestHash);
    PeerHostInit(&boundedHost, dllHash, manifestHash);
    for (unsigned i = 0; i < PEER_STATE_CAPACITY; ++i) {
        make_packet(8, 20u + i);
        CHECK(make_offer(&boundedClient, 1000u + i, 8, packet, sizeof(packet), 4000) != 0);
    }
    make_packet(8, 200);
    uint32_t noLength = 0;
    CHECK(!PeerClientMakeOffer(&boundedClient, 9000, 8, packet, sizeof(packet), 4000, offered, sizeof(offered), &noLength));
    for (unsigned i = 0; i < PEER_STATE_CAPACITY; ++i) {
        make_packet(8, 50u + i);
        offerLength = make_offer(&hostClient, 2000u + i, 8, packet, sizeof(packet), 5000);
        CHECK(PeerHostChallenge(&boundedHost, 2000u + i, 3000u + i, 5000, offered, offerLength, challenge, sizeof(challenge)));
    }
    CHECK(!PeerHostChallenge(&boundedHost, 30000, 30001, 5000, offered, offerLength, challenge, sizeof(challenge)));

    // Replay-cache exhaustion consumes the matching entry, then fails the host closed.
    PeerHostState overflowHost; PeerHostInit(&overflowHost, dllHash, manifestHash);
    int overflowRejected = 0;
    for (unsigned i = 0; i <= PEER_REPLAY_CAPACITY; ++i) {
        PeerClientState oneShot; PeerClientInit(&oneShot, dllHash, manifestHash);
        make_packet(8, 80u + i);
        offerLength = make_offer(&oneShot, 40000u + i, 8, packet, sizeof(packet), 6000u + i);
        CHECK(PeerHostChallenge(&overflowHost, 40000u + i, 50000u + i, 6000u + i,
            offered, offerLength, challenge, sizeof(challenge)));
        CHECK(PeerClientAnswer(&oneShot, 40000u + i, 50000u + i, 6000u + i,
            challenge, sizeof(challenge), response, sizeof(response)));
        int accepted = PeerHostAccept(&overflowHost, 40000u + i, 50000u + i, 6000u + i,
            response, sizeof(response), restored, sizeof(restored), &outputLength);
        if (i < PEER_REPLAY_CAPACITY) CHECK(accepted);
        else { CHECK(!accepted); overflowRejected = 1; }
        PeerClientDestroy(&oneShot);
    }
    CHECK(overflowRejected);
    make_packet(8, 220);
    PeerClientState overflowProbe; PeerClientInit(&overflowProbe, dllHash, manifestHash);
    offerLength = make_offer(&overflowProbe, 60000, 8, packet, sizeof(packet), 7000);
    CHECK(!PeerHostChallenge(&overflowHost, 60000, 60001, 7000, offered, offerLength, challenge, sizeof(challenge)));
    make_packet(8, 221);
    offerLength = make_offer(&overflowProbe, 60001, 8, packet, sizeof(packet), 16128);
    CHECK(PeerHostChallenge(&overflowHost, 60001, 60002, 16128, offered, offerLength, challenge, sizeof(challenge)));
    PeerClientDestroy(&overflowProbe);
    PeerHostDestroy(&overflowHost);

    // Clearing volatile host state (including a process restart) invalidates pending replies.
    make_packet(8, 252);
    offerLength = make_offer(&client, 21, 8, packet, sizeof(packet), 5100);
    CHECK(PeerHostChallenge(&host, 21, 122, 5100, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 21, 122, 5100, challenge, sizeof(challenge), response, sizeof(response)));
    PeerHostClear(&host);
    CHECK(!PeerHostAccept(&host, 21, 122, 5101, response, sizeof(response), restored, sizeof(restored), &outputLength));

    // Competing responses consume a host slot exactly once.
    make_packet(8, 251);
    offerLength = make_offer(&client, 19, 8, packet, sizeof(packet), 100);
    CHECK(PeerHostChallenge(&host, 19, 110, 100, offered, offerLength, challenge, sizeof(challenge)));
    CHECK(PeerClientAnswer(&client, 19, 110, 100, challenge, sizeof(challenge), response, sizeof(response)));
    volatile LONG successes = 0;
    RaceArg args = { &host, 19, 110, response, &successes };
    HANDLE threads[8];
    for (size_t i = 0; i < 8; ++i) { uintptr_t t = _beginthreadex(NULL, 0, race_consume, &args, 0, NULL); CHECK(t != 0); threads[i] = (HANDLE)t; }
    WaitForMultipleObjects(8, threads, TRUE, INFINITE);
    for (size_t i = 0; i < 8; ++i) CloseHandle(threads[i]);
    CHECK(successes == 1);

    PeerHostDestroy(&host); PeerHostDestroy(&boundedHost);
    PeerClientDestroy(&client); PeerClientDestroy(&boundedClient); PeerClientDestroy(&hostClient);
    printf("%u peer protocol checks passed.\n", assertions);
    return 0;
}
