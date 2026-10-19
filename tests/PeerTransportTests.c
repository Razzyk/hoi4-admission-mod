#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../native/peer_protocol.h"

#define FRAME_LIMIT 512u
#define RECEIVE_TIMEOUT_MS 5000u
#define TEST_JOIN_TYPE 8u

enum FrameType {
    FRAME_OFFER = 1,
    FRAME_CHALLENGE = 2,
    FRAME_RESPONSE = 3,
    FRAME_STATUS = 4
};
enum StatusCode {
    STATUS_BUILD_MISMATCH_REFUSED = 1,
    STATUS_ADMITTED = 2,
    STATUS_REPLAY_OFFER_REFUSED = 3,
    STATUS_REPLAY_RESPONSE_REFUSED = 4
};

#pragma pack(push, 1)
typedef struct TestFrameHeader {
    uint32_t type;
    uint32_t length;
} TestFrameHeader;
#pragma pack(pop)

static const unsigned char fixture_dll_hash[32] = {
    0x12,0x41,0x98,0x27,0x53,0x64,0x75,0x86,0x97,0xa8,0xb9,0xca,0xdb,0xec,0xfd,0x0e,
    0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f,0x10
};
static const unsigned char fixture_manifest_hash[32] = {
    0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f,0x10,
    0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f,0x01
};
static const unsigned char fixture_packet[40] = {
    8,0,0,0, 0,0,0,0,
    'p','e','e','r','-','u','d','p','-','d','e','l','a','y','e','d','-','j','o','i','n',0,
    0x31,0x42,0x53,0x64,0x75,0x86,0x97,0xa8
};

static void fail(const char *message) {
    fprintf(stderr, "FAIL pid=%lu: %s (WSA=%d, Win32=%lu)\n",
        (unsigned long)GetCurrentProcessId(), message, WSAGetLastError(), (unsigned long)GetLastError());
}

static int pause_before_send(void) {
    Sleep(150);
    return 1;
}

static int send_frame(SOCKET socket_handle, const struct sockaddr_in *destination,
    uint32_t type, const void *payload, uint32_t payload_length) {
    unsigned char bytes[FRAME_LIMIT];
    TestFrameHeader header;
    if (payload_length > sizeof(bytes) - sizeof(header) || (payload_length && !payload)) return 0;
    header.type = type;
    header.length = payload_length;
    memcpy(bytes, &header, sizeof(header));
    if (payload_length) memcpy(bytes + sizeof(header), payload, payload_length);
    pause_before_send();
    int sent = sendto(socket_handle, (const char *)bytes, (int)(sizeof(header) + payload_length), 0,
        (const struct sockaddr *)destination, sizeof(*destination));
    SecureZeroMemory(bytes, sizeof(bytes));
    return sent == (int)(sizeof(header) + payload_length);
}

static int receive_frame(SOCKET socket_handle, struct sockaddr_in *source,
    uint32_t *type, void *payload, uint32_t capacity, uint32_t *payload_length) {
    unsigned char bytes[FRAME_LIMIT];
    int source_length = sizeof(*source);
    int received = recvfrom(socket_handle, (char *)bytes, sizeof(bytes), 0,
        (struct sockaddr *)source, &source_length);
    if (received < (int)sizeof(TestFrameHeader) || source_length != sizeof(*source)) return 0;
    TestFrameHeader header;
    memcpy(&header, bytes, sizeof(header));
    if (header.length != (uint32_t)received - (uint32_t)sizeof(header) || header.length > capacity ||
        (header.length && !payload) || source->sin_family != AF_INET || source->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) return 0;
    if (header.length) memcpy(payload, bytes + sizeof(header), header.length);
    *type = header.type;
    *payload_length = header.length;
    SecureZeroMemory(bytes, sizeof(bytes));
    return 1;
}

static SOCKET open_udp_socket(void) {
    SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) return INVALID_SOCKET;
    DWORD timeout = RECEIVE_TIMEOUT_MS;
    if (setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        closesocket(socket_handle);
        return INVALID_SOCKET;
    }
    return socket_handle;
}

static uintptr_t context_id(DWORD process_id, uint32_t role) {
    return ((uintptr_t)process_id << 32) | (uintptr_t)role;
}

static int host_run(void) {
    WSADATA winsock;
    SOCKET socket_handle = INVALID_SOCKET;
    PeerHostState state;
    int state_ready = 0, admitted = 0, ok = 0;
    struct sockaddr_in bind_address, client_address;
    unsigned char offer[FRAME_LIMIT], challenge[PEER_MESSAGE_BYTES], response[FRAME_LIMIT];
    unsigned char restored[FRAME_LIMIT];
    uint32_t frame_type, payload_length, restored_length = 0;
    DWORD pid = GetCurrentProcessId();
    uintptr_t host_context = context_id(pid, 0x484f5354u);
    uintptr_t host_connection = host_context ^ (uintptr_t)0x1111u;
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) { fail("WSAStartup"); return 1; }
    socket_handle = open_udp_socket();
    if (socket_handle == INVALID_SOCKET) { fail("host socket setup"); goto done; }
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_address.sin_port = 0;
    if (bind(socket_handle, (const struct sockaddr *)&bind_address, sizeof(bind_address)) == SOCKET_ERROR) {
        fail("host bind loopback ephemeral port"); goto done;
    }
    int address_length = sizeof(bind_address);
    if (getsockname(socket_handle, (struct sockaddr *)&bind_address, &address_length) == SOCKET_ERROR || address_length != sizeof(bind_address)) {
        fail("host getsockname"); goto done;
    }
    PeerHostInit(&state, fixture_dll_hash, fixture_manifest_hash);
    state_ready = 1;
    printf("READY %u %lu %llu\n", (unsigned)ntohs(bind_address.sin_port), (unsigned long)pid,
        (unsigned long long)host_context);
    fflush(stdout);

    // The first client deliberately advertises a different module hash.
    if (!receive_frame(socket_handle, &client_address, &frame_type, offer, sizeof(offer), &payload_length) ||
        frame_type != FRAME_OFFER || !payload_length) { fail("receive mismatched-build offer"); goto done; }
    if (PeerHostChallenge(&state, host_context, host_connection, GetTickCount64(), offer, payload_length,
        challenge, sizeof(challenge))) { fail("mismatched build unexpectedly got a challenge"); goto done; }
    uint32_t status = STATUS_BUILD_MISMATCH_REFUSED;
    if (!send_frame(socket_handle, &client_address, FRAME_STATUS, &status, sizeof(status))) { fail("send mismatch refusal"); goto done; }

    if (!receive_frame(socket_handle, &client_address, &frame_type, offer, sizeof(offer), &payload_length) ||
        frame_type != FRAME_OFFER || !payload_length) { fail("receive matching-build offer"); goto done; }
    if (!PeerHostChallenge(&state, host_context, host_connection, GetTickCount64(), offer, payload_length,
        challenge, sizeof(challenge))) { fail("matching build offer was refused"); goto done; }
    if (!send_frame(socket_handle, &client_address, FRAME_CHALLENGE, challenge, sizeof(challenge))) { fail("send challenge"); goto done; }

    if (!receive_frame(socket_handle, &client_address, &frame_type, response, sizeof(response), &payload_length) ||
        frame_type != FRAME_RESPONSE) { fail("receive response"); goto done; }
    int accepted = PeerHostAccept(&state, host_context, host_connection, GetTickCount64(), response,
        payload_length, restored, sizeof(restored), &restored_length);
    if (!accepted || restored_length != sizeof(fixture_packet) || memcmp(restored, fixture_packet, sizeof(fixture_packet))) {
        fail("host did not restore exactly the original request"); goto done;
    }
    // This callback stands in for the native admission callback. No shared roster exists in this fixture.
    ++admitted;
    if (admitted != 1) { fail("native admission callback count"); goto done; }
    status = STATUS_ADMITTED;
    if (!send_frame(socket_handle, &client_address, FRAME_STATUS, &status, sizeof(status))) { fail("send accepted status"); goto done; }

    if (!receive_frame(socket_handle, &client_address, &frame_type, offer, sizeof(offer), &payload_length) || frame_type != FRAME_OFFER) {
        fail("receive offer replay"); goto done;
    }
    if (PeerHostChallenge(&state, host_context, host_connection, GetTickCount64(), offer, payload_length,
        challenge, sizeof(challenge))) { fail("accepted offer replay was challenged"); goto done; }
    status = STATUS_REPLAY_OFFER_REFUSED;
    if (!send_frame(socket_handle, &client_address, FRAME_STATUS, &status, sizeof(status))) { fail("send replay-offer refusal"); goto done; }

    if (!receive_frame(socket_handle, &client_address, &frame_type, response, sizeof(response), &payload_length) || frame_type != FRAME_RESPONSE) {
        fail("receive response replay"); goto done;
    }
    if (PeerHostAccept(&state, host_context, host_connection, GetTickCount64(), response,
        payload_length, restored, sizeof(restored), &restored_length)) { fail("accepted response replay"); goto done; }
    status = STATUS_REPLAY_RESPONSE_REFUSED;
    if (!send_frame(socket_handle, &client_address, FRAME_STATUS, &status, sizeof(status))) { fail("send replay-response refusal"); goto done; }
    if (admitted != 1) { fail("admission callback was not exactly once"); goto done; }
    printf("PASS host pid=%lu context=%llu admitted=%d mismatch-refused replay-offer-refused replay-response-refused\n",
        (unsigned long)pid, (unsigned long long)host_context, admitted);
    ok = 1;
done:
    SecureZeroMemory(offer, sizeof(offer)); SecureZeroMemory(challenge, sizeof(challenge));
    SecureZeroMemory(response, sizeof(response)); SecureZeroMemory(restored, sizeof(restored));
    if (state_ready) PeerHostDestroy(&state);
    if (socket_handle != INVALID_SOCKET) closesocket(socket_handle);
    WSACleanup();
    return ok ? 0 : 1;
}

static int expect_status(SOCKET socket_handle, const struct sockaddr_in *host,
    uint32_t expected_status) {
    unsigned char payload[16];
    struct sockaddr_in source;
    uint32_t type, length;
    if (!receive_frame(socket_handle, &source, &type, payload, sizeof(payload), &length) ||
        source.sin_port != host->sin_port || type != FRAME_STATUS || length != sizeof(uint32_t)) return 0;
    uint32_t actual;
    memcpy(&actual, payload, sizeof(actual));
    return actual == expected_status;
}

static int client_run(int argc, char **argv) {
    WSADATA winsock;
    SOCKET socket_handle = INVALID_SOCKET;
    PeerClientState state;
    int state_ready = 0, ok = 0;
    unsigned char offer[sizeof(fixture_packet) + PEER_OFFER_BYTES];
    unsigned char challenge[PEER_MESSAGE_BYTES], response[PEER_MESSAGE_BYTES], wrong_hash[32];
    struct sockaddr_in host_address, local_address;
    uint32_t offer_length = 0, frame_type, payload_length;
    unsigned char received[FRAME_LIMIT];
    struct sockaddr_in source;
    if (argc != 5) { fail("client expects port, host PID and host context"); return 1; }
    unsigned short port = (unsigned short)strtoul(argv[2], NULL, 10);
    DWORD host_pid = (DWORD)strtoul(argv[3], NULL, 10);
    uintptr_t host_context = (uintptr_t)_strtoui64(argv[4], NULL, 10);
    DWORD pid = GetCurrentProcessId();
    uintptr_t client_context = context_id(pid, 0x434c4e54u);
    uintptr_t client_connection = client_context ^ (uintptr_t)0x2222u;
    if (!port || !host_pid || !host_context || host_pid == pid || host_context == client_context ||
        client_connection == (host_context ^ (uintptr_t)0x1111u)) {
        fprintf(stderr, "FAIL context check: client pid=%lu context=%llu connection=%llu host pid=%lu context=%llu connection=%llu\n",
            (unsigned long)pid, (unsigned long long)client_context, (unsigned long long)client_connection,
            (unsigned long)host_pid, (unsigned long long)host_context,
            (unsigned long long)(host_context ^ (uintptr_t)0x1111u));
        return 1;
    }
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) { fail("WSAStartup"); return 1; }
    socket_handle = open_udp_socket();
    if (socket_handle == INVALID_SOCKET) { fail("client socket setup"); goto done; }
    memset(&host_address, 0, sizeof(host_address));
    host_address.sin_family = AF_INET;
    host_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    host_address.sin_port = htons(port);
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local_address.sin_port = 0;
    if (bind(socket_handle, (const struct sockaddr *)&local_address, sizeof(local_address)) == SOCKET_ERROR) {
        fail("client bind loopback ephemeral port"); goto done;
    }

    memcpy(wrong_hash, fixture_dll_hash, sizeof(wrong_hash));
    wrong_hash[0] ^= 0xffu;
    PeerClientInit(&state, wrong_hash, fixture_manifest_hash);
    state_ready = 1;
    if (!PeerClientMakeOffer(&state, client_context, TEST_JOIN_TYPE, fixture_packet, sizeof(fixture_packet),
        GetTickCount64(), offer, sizeof(offer), &offer_length) ||
        !send_frame(socket_handle, &host_address, FRAME_OFFER, offer, offer_length) ||
        !expect_status(socket_handle, &host_address, STATUS_BUILD_MISMATCH_REFUSED)) {
        fail("plain/different-build offer was not refused"); goto done;
    }
    PeerClientDestroy(&state);
    state_ready = 0;

    PeerClientInit(&state, fixture_dll_hash, fixture_manifest_hash);
    state_ready = 1;
    if (!PeerClientMakeOffer(&state, client_context, TEST_JOIN_TYPE, fixture_packet, sizeof(fixture_packet),
        GetTickCount64(), offer, sizeof(offer), &offer_length) ||
        !send_frame(socket_handle, &host_address, FRAME_OFFER, offer, offer_length)) {
        fail("matching-build offer setup/send"); goto done;
    }
    if (!receive_frame(socket_handle, &source, &frame_type, challenge, sizeof(challenge), &payload_length) ||
        source.sin_port != host_address.sin_port || frame_type != FRAME_CHALLENGE || payload_length != sizeof(challenge) ||
        !PeerClientAnswer(&state, client_context, client_connection, GetTickCount64(), challenge, payload_length,
            response, sizeof(response))) {
        fail("challenge did not produce a client response"); goto done;
    }
    if (!send_frame(socket_handle, &host_address, FRAME_RESPONSE, response, sizeof(response)) ||
        !expect_status(socket_handle, &host_address, STATUS_ADMITTED)) {
        fail("host did not confirm delayed offer/response round trip"); goto done;
    }
    if (!send_frame(socket_handle, &host_address, FRAME_OFFER, offer, offer_length) ||
        !expect_status(socket_handle, &host_address, STATUS_REPLAY_OFFER_REFUSED)) {
        fail("accepted offer replay was not refused"); goto done;
    }
    if (!send_frame(socket_handle, &host_address, FRAME_RESPONSE, response, sizeof(response)) ||
        !expect_status(socket_handle, &host_address, STATUS_REPLAY_RESPONSE_REFUSED)) {
        fail("accepted response replay was not refused"); goto done;
    }
    printf("PASS client pid=%lu context=%llu host-pid=%lu host-context=%llu separate-process-contexts\n",
        (unsigned long)pid, (unsigned long long)client_context, (unsigned long)host_pid, (unsigned long long)host_context);
    ok = 1;
done:
    SecureZeroMemory(offer, sizeof(offer)); SecureZeroMemory(challenge, sizeof(challenge));
    SecureZeroMemory(response, sizeof(response)); SecureZeroMemory(wrong_hash, sizeof(wrong_hash));
    SecureZeroMemory(received, sizeof(received));
    if (state_ready) PeerClientDestroy(&state);
    if (socket_handle != INVALID_SOCKET) closesocket(socket_handle);
    WSACleanup();
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--host") == 0) return host_run();
    if (argc == 5 && strcmp(argv[1], "--client") == 0) return client_run(argc, argv);
    fprintf(stderr, "Usage: PeerTransportTests.exe --host | --client <port> <host-pid> <host-context>\n");
    return 2;
}
