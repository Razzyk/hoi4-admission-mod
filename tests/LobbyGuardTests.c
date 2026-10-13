#define LOBBY_GUARD_TEST 1
#include "../native/lobby_guard.c"

int (*lobby_guard_test_control)(const char *, char [256]);

static const char *case_name;
static unsigned assertions, cases;
static volatile LONG test_eligible;
static unsigned send_calls, receive_calls, deny_calls, issue_calls, check_calls;
static uint32_t sent_length, received_length;
static uintptr_t sent_connection, received_connection, denied_connection;
static int received_channel, denied_type, service_available, issuer_live, ticket_expired;
static int malformed_issue_reply, malformed_check_reply;
static const void *received_packet;
static void *received_server, *sent_server, *denied_server;
static unsigned char sent_bytes[JOIN_MAX_PACKET], received_bytes[JOIN_MAX_PACKET];
static char last_event[256];
static char ticket[65], ticket_hash[65];
static uint32_t ticket_type;
static unsigned ticket_sequence;
static int ticket_used;
static uintptr_t bound_connection;
static int broker_binding_set;
static int test_server_marker;

static void require(int condition, const char *description, unsigned line) {
    ++assertions;
    if (!condition) {
        fprintf(stderr, "FAIL %s at line %u: %s\n", case_name, line, description);
        exit(1);
    }
}
#define CHECK(condition) require(!!(condition), #condition, __LINE__)

static size_t fields(char *text, char *out[10]) {
    size_t count = 0;
    for (;;) {
        if (count == 10u) return 0;
        out[count++] = text;
        char *next = strchr(text, '|');
        if (!next) return count;
        *next = 0;
        text = next + 1;
    }
}
static unsigned long long number(const char *text) {
    char *end;
    CHECK(*text != 0);
    unsigned long long value = strtoull(text, &end, 10);
    CHECK(*end == 0);
    return value;
}

/* This broker exercises the real native command encoder and trailer parser.
 * It independently authorizes the original packet digest and consumes one
 * ticket once. The production service separately checks live pipe PID/module
 * and process creation; these unit tests model those decisions. */
static int mock_control(const char *command, char response[256]) {
    char copy[512], *part[10];
    CHECK(strlen(command) < sizeof(copy));
    strcpy(copy, command);
    size_t count = fields(copy, part);
    CHECK(count == 7u || count == 9u);
    CHECK(number(part[1]) == ADMISSION_PROTOCOL);
    CHECK(!strcmp(part[2], guard_config.session));
    CHECK(number(part[3]) == GetCurrentProcessId());
    CHECK(number(part[4]) == creation_time);
    uint32_t type = (uint32_t)number(part[5]);
    CHECK(join_type(type));
    CHECK(strlen(part[6]) == 64u);
    if (!strcmp(part[0], "JOIN_ISSUE")) {
        CHECK(count == 7u);
        ++issue_calls;
        if (!service_available) return 0;
        if (!issuer_live) { strcpy(response, "JOIN_REJECT|CLIENT_NOT_VERIFIED"); return 1; }
        ++ticket_sequence;
        int length = snprintf(ticket, sizeof(ticket), "%064u", ticket_sequence);
        CHECK(length == 64);
        strcpy(ticket_hash, part[6]);
        ticket_type = type;
        ticket_used = 0;
        if (malformed_issue_reply == 1) strcpy(response, "TICKET|short");
        else if (malformed_issue_reply == 2) { strcpy(response, "TICKET|"); memset(response + 7, 'G', 64); response[71] = 0; }
        else if (malformed_issue_reply == 3) strcpy(response, "ACCEPT|");
        else { strcpy(response, "TICKET|"); strcat(response, ticket); }
        return 1;
    }
    CHECK(!strcmp(part[0], "JOIN_CHECK"));
    CHECK(count == 9u);
    ++check_calls;
    if (!service_available) return 0;
    if (malformed_check_reply) { strcpy(response, "JOIN_ACCEPT|unexpected"); return 1; }
    uintptr_t connection = (uintptr_t)number(part[8]);
    const char *reason = NULL;
    if (!issuer_live) reason = "CLIENT_NOT_VERIFIED";
    else if (ticket_expired) reason = "TICKET_EXPIRED";
    else if (ticket_used) reason = "TICKET_USED";
    else if (strcmp(ticket, part[7])) reason = "TICKET_UNKNOWN";
    else if (ticket_type != type || strcmp(ticket_hash, part[6])) reason = "TICKET_PACKET_MISMATCH";
    else if (!connection || (broker_binding_set && connection != bound_connection)) reason = "CONNECTION_BINDING_MISMATCH";
    if (reason) { strcpy(response, "JOIN_REJECT|"); strcat(response, reason); return 1; }
    ticket_used = 1;
    bound_connection = connection;
    broker_binding_set = 1;
    strcpy(response, "JOIN_ACCEPT");
    return 1;
}
static void send_stub(void *server, const void *packet, uint32_t length, uintptr_t connection) {
    ++send_calls;
    sent_server = server;
    sent_connection = connection;
    sent_length = length;
    if (packet && length <= sizeof(sent_bytes)) memcpy(sent_bytes, packet, length);
}
static void receive_stub(void *server, const void *packet, uint32_t length, uintptr_t connection, int channel) {
    ++receive_calls;
    received_server = server;
    received_packet = packet;
    received_connection = connection;
    received_channel = channel;
    received_length = length;
    if (packet && length <= sizeof(received_bytes)) memcpy(received_bytes, packet, length);
}
static void deny_stub(void *server, int type, uintptr_t connection) {
    ++deny_calls;
    denied_server = server;
    denied_type = type;
    denied_connection = connection;
}
static void log_stub(const char *message) {
    CHECK(strlen(message) < sizeof(last_event));
    strcpy(last_event, message);
}
static void reset(const char *name) {
    ++cases;
    case_name = name;
    test_eligible = 1;
    client_eligible = &test_eligible;
    stopped = 0;
    rejected = accepted = decorated = 0;
    send_calls = receive_calls = deny_calls = issue_calls = check_calls = 0;
    sent_length = received_length = 0;
    sent_connection = received_connection = denied_connection = 0;
    received_packet = NULL;
    received_server = sent_server = denied_server = NULL;
    received_channel = denied_type = 0;
    service_available = issuer_live = 1;
    ticket_expired = malformed_issue_reply = malformed_check_reply = ticket_used = 0;
    broker_binding_set = 0;
    bound_connection = 0;
    last_event[0] = ticket[0] = ticket_hash[0] = 0;
    ticket_type = 0;
    memset(&guard_config, 0, sizeof(guard_config));
    strcpy(guard_config.session, "native-local-test-session");
    creation_time = 123456789012345u;
    guard_log = log_stub;
    original_send = send_stub;
    original_receive = receive_stub;
    native_deny = deny_stub;
    lobby_guard_test_control = mock_control;
}
static void request(unsigned char *packet, uint32_t length, uint32_t type) {
    CHECK(length >= 8u);
    for (uint32_t i = 0; i < length; ++i) packet[i] = (unsigned char)(i * 37u + 11u);
    put32(packet, type);
    put32(packet + 4, 0x12345678u);
}
static void issue(unsigned char *packet, uint32_t length, uint32_t type) {
    request(packet, length, type);
    guarded_send(&test_server_marker, packet, length, 0);
    CHECK(send_calls == 1u);
    CHECK(issue_calls == 1u);
    CHECK(sent_length == length + JOIN_TRAILER_BYTES);
    CHECK(sent_server == &test_server_marker);
    CHECK(sent_connection == 0);
    CHECK(!memcmp(sent_bytes, packet, length));
    CHECK(decorated == 1);
    CHECK(!strstr(last_event, ticket));
}
static void denied(uint32_t type, uintptr_t connection) {
    CHECK(deny_calls == 1u);
    CHECK(denied_type == (type == 9u ? 11 : type == 14u ? 16 : 33));
    CHECK(denied_server == &test_server_marker);
    CHECK(denied_connection == connection);
    CHECK(receive_calls == 0u);
    CHECK(rejected == 1);
    CHECK(accepted == 0);
}

int main(void) {
    static const uint32_t types[] = {8, 9, 14};
    unsigned char packet[32], changed[32 + JOIN_TRAILER_BYTES];
    const uintptr_t connection = 0x7654321u;
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        uint32_t type = types[i];
        reset("plain client native denial");
        request(packet, sizeof(packet), type);
        guarded_receive(&test_server_marker, packet, sizeof(packet), connection, 1);
        denied(type, connection);
        CHECK(check_calls == 0u);

        reset("verified ticket allows exact original packet");
        issue(packet, sizeof(packet), type);
        const unsigned char *trailer = sent_bytes + sizeof(packet);
        CHECK(!memcmp(trailer, "H4ADMIT2", 8));
        CHECK(get32(trailer + 8) == ADMISSION_PROTOCOL);
        CHECK(get32(trailer + 12) == sizeof(packet));
        CHECK(!memcmp(trailer + 16, ticket, 64));
        CHECK(get32(trailer + 80) == type);
        CHECK(get32(trailer + 84) == 1u);
        for (size_t j = 88; j < JOIN_TRAILER_BYTES; ++j) CHECK(trailer[j] == 0);
        guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
        CHECK(receive_calls == 1u);
        CHECK(deny_calls == 0u);
        CHECK(check_calls == 1u);
        CHECK(received_length == sizeof(packet));
        CHECK(received_packet == sent_bytes);
        CHECK(received_server == &test_server_marker);
        CHECK(received_connection == connection);
        CHECK(received_channel == 1);
        CHECK(!memcmp(received_bytes, packet, sizeof(packet)));
        CHECK(accepted == 1);
        CHECK(!strstr(last_event, ticket));

        reset("known join truncated header denied");
        request(packet, sizeof(packet), type);
        guarded_receive(&test_server_marker, packet, 4, connection, 1);
        denied(type, connection);
        guarded_send(&test_server_marker, packet, 7, connection);
        CHECK(send_calls == 0u);
        CHECK(issue_calls == 0u);
    }

    reset("consumed ticket replay denied");
    issue(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    CHECK(receive_calls == 1u);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    CHECK(receive_calls == 1u && deny_calls == 1u && rejected == 1 && accepted == 1);
    CHECK(strstr(last_event, "TICKET_USED") != NULL);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection + 1u, 1);
    CHECK(receive_calls == 1u && deny_calls == 2u);

    reset("fresh ticket cannot migrate existing issuer binding");
    issue(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    guarded_send(&test_server_marker, packet, sizeof(packet), 0);
    CHECK(send_calls == 2u && issue_calls == 2u);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection + 1u, 1);
    CHECK(receive_calls == 1u && deny_calls == 1u);
    CHECK(strstr(last_event, "CONNECTION_BINDING_MISMATCH") != NULL);

    reset("changed original packet denied by digest");
    issue(packet, sizeof(packet), 8);
    memcpy(changed, sent_bytes, sent_length);
    changed[10] ^= 1;
    guarded_receive(&test_server_marker, changed, sent_length, connection, 1);
    denied(8, connection);
    CHECK(check_calls == 1u);
    CHECK(strstr(last_event, "TICKET_PACKET_MISMATCH") != NULL);

    reset("changed request type denied by broker");
    issue(packet, sizeof(packet), 8);
    put32(sent_bytes, 9);
    put32(sent_bytes + sizeof(packet) + 80, 9);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(9, connection);
    CHECK(strstr(last_event, "TICKET_PACKET_MISMATCH") != NULL);

    static const size_t corrupt_offsets[] = {0, 8, 12, 80, 84, 88, 95, 16};
    for (size_t i = 0; i < sizeof(corrupt_offsets) / sizeof(corrupt_offsets[0]); ++i) {
        reset("malformed trailer rejected before broker");
        issue(packet, sizeof(packet), 8);
        size_t offset = sizeof(packet) + corrupt_offsets[i];
        if (corrupt_offsets[i] == 16u) sent_bytes[offset] = 'z';
        else sent_bytes[offset] ^= 0x80;
        guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
        denied(8, connection);
        CHECK(check_calls == 0u);
    }

    reset("unknown but valid format token denied");
    issue(packet, sizeof(packet), 8);
    sent_bytes[sizeof(packet) + 16] = 'f';
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    CHECK(check_calls == 1u && strstr(last_event, "TICKET_UNKNOWN") != NULL);

    reset("expired ticket denied");
    issue(packet, sizeof(packet), 14);
    ticket_expired = 1;
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(14, connection);
    CHECK(strstr(last_event, "TICKET_EXPIRED") != NULL);

    reset("issuing process lease lost before consume");
    issue(packet, sizeof(packet), 8);
    issuer_live = 0;
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    CHECK(strstr(last_event, "CLIENT_NOT_VERIFIED") != NULL);

    reset("service unavailable on outgoing request");
    service_available = 0;
    request(packet, sizeof(packet), 8);
    guarded_send(&test_server_marker, packet, sizeof(packet), 0);
    CHECK(send_calls == 0u && issue_calls == 1u && decorated == 0);

    reset("service unavailable on incoming request");
    issue(packet, sizeof(packet), 8);
    service_available = 0;
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    CHECK(strstr(last_event, "VERIFICATION_SERVICE_UNAVAILABLE") != NULL);

    for (int reply = 1; reply <= 3; ++reply) {
        reset("malformed issue response blocks outgoing request");
        malformed_issue_reply = reply;
        request(packet, sizeof(packet), 8);
        guarded_send(&test_server_marker, packet, sizeof(packet), 0);
        CHECK(send_calls == 0u && issue_calls == 1u && decorated == 0);
    }
    reset("unexpected check response denied");
    issue(packet, sizeof(packet), 8);
    malformed_check_reply = 1;
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    CHECK(strstr(last_event, "SERVICE_RESPONSE_INVALID") != NULL);

    reset("client not eligible cannot send join");
    test_eligible = 0;
    request(packet, sizeof(packet), 8);
    guarded_send(&test_server_marker, packet, sizeof(packet), 0);
    CHECK(send_calls == 0u && issue_calls == 0u);

    reset("host not eligible cannot consume valid ticket");
    issue(packet, sizeof(packet), 8);
    test_eligible = 0;
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    CHECK(check_calls == 0u);

    reset("stop keeps resident guard fail closed");
    issue(packet, sizeof(packet), 8);
    LobbyGuardStop();
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    denied(8, connection);
    guarded_send(&test_server_marker, packet, sizeof(packet), 0);
    CHECK(send_calls == 1u && issue_calls == 1u && check_calls == 0u);

    reset("missing eligibility pointer denies");
    request(packet, sizeof(packet), 9);
    client_eligible = NULL;
    guarded_send(&test_server_marker, packet, sizeof(packet), 0);
    guarded_receive(&test_server_marker, packet, sizeof(packet), connection, 1);
    denied(9, connection);
    CHECK(send_calls == 0u && issue_calls == 0u);

    reset("trailer truncation rejected");
    issue(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, sent_bytes, sent_length - 1u, connection, 1);
    denied(8, connection);
    CHECK(check_calls == 0u);

    reset("missing or undersized trailer rejected");
    request(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, packet, 8, connection, 1);
    denied(8, connection);

    reset("overflow declared outgoing length blocks before reading payload");
    request(packet, sizeof(packet), 8);
    guarded_send(&test_server_marker, packet, UINT32_MAX, 0);
    CHECK(send_calls == 0u && issue_calls == 0u);

    reset("overflow declared incoming length denied before trailer address");
    request(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, packet, UINT32_MAX, connection, 1);
    denied(8, connection);
    CHECK(check_calls == 0u);

    reset("maximum exact packet fits and preserves payload");
    unsigned char *large = HeapAlloc(GetProcessHeap(), 0, JOIN_MAX_PACKET);
    CHECK(large != NULL);
    uint32_t maximum_original = JOIN_MAX_PACKET - JOIN_TRAILER_BYTES;
    issue(large, maximum_original, 8);
    CHECK(sent_length == JOIN_MAX_PACKET);
    guarded_receive(&test_server_marker, sent_bytes, sent_length, connection, 1);
    CHECK(receive_calls == 1u && received_length == maximum_original);
    CHECK(!memcmp(received_bytes, large, maximum_original));
    HeapFree(GetProcessHeap(), 0, large);

    reset("oversized outgoing request rejected at boundary");
    request(packet, sizeof(packet), 8);
    guarded_send(&test_server_marker, packet, JOIN_MAX_PACKET - JOIN_TRAILER_BYTES + 1u, 0);
    CHECK(send_calls == 0u && issue_calls == 0u);

    reset("unrelated control traffic passes without verification");
    request(packet, sizeof(packet), 25);
    test_eligible = 0;
    guarded_send(&test_server_marker, packet, sizeof(packet), connection);
    guarded_receive(&test_server_marker, packet, sizeof(packet), connection, 1);
    CHECK(send_calls == 1u && receive_calls == 1u && deny_calls == 0u);
    CHECK(sent_length == sizeof(packet) && received_length == sizeof(packet));
    CHECK(received_packet == packet && sent_connection == connection);
    CHECK(!memcmp(sent_bytes, packet, sizeof(packet)) && !memcmp(received_bytes, packet, sizeof(packet)));
    CHECK(issue_calls == 0u && check_calls == 0u);

    reset("noncontrol channel remains native command traffic");
    request(packet, sizeof(packet), 8);
    guarded_receive(&test_server_marker, packet, sizeof(packet), connection, 0);
    CHECK(receive_calls == 1u && deny_calls == 0u && check_calls == 0u);
    CHECK(received_channel == 0 && received_length == sizeof(packet) && received_packet == packet);

    reset("unclassifiable short and null packets preserve native bounds handling");
    guarded_receive(&test_server_marker, packet, 3, connection, 1);
    CHECK(receive_calls == 1u && received_length == 3u && deny_calls == 0u);
    guarded_receive(&test_server_marker, NULL, 0, connection, 1);
    CHECK(receive_calls == 2u && received_packet == NULL && received_length == 0u);
    guarded_send(&test_server_marker, NULL, 0, connection);
    CHECK(send_calls == 1u && sent_length == 0u && issue_calls == 0u);

    printf("Lobby guard: %u cases, %u assertions passed. Native send/receive wrappers used; no game process patched.\n", cases, assertions);
    return 0;
}
