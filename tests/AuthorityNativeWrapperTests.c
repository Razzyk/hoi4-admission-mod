/* Native wrapper and ABI fixtures for authority_guard.c.
 * This test owns a private executable-image reservation; it never attaches to
 * or modifies a game process. Caller thunks are test-authored machine code. */
#include "../native/authorization/authority_guard.c"

static unsigned assertions;
static const char *case_name;
static void *expected_command, *expected_motivation;
static int expected_native_answer, valid_calls, valid_arg_errors;
static int loggable_calls, loggable_arg_errors, destructor_calls, destructor_flags;
static void *destructor_result;
static uint64_t fixture_sender_id = 1001;
static int fixture_history_count;
static void **capture_command;
static void *capture_motivation;
static int load_task_calls;
static void *load_task_result;
static unsigned char expected_capture_answer;

#define CHECK(c) do { ++assertions; if (!(c)) { \
    fprintf(stderr, "FAIL %s line %d: %s\n", case_name, __LINE__, #c); ExitProcess(1); \
} } while (0)

static __attribute__((used)) unsigned char __fastcall valid_probe(void *command, void *motivation) {
    ++valid_calls;
    if (command != expected_command || motivation != expected_motivation) ++valid_arg_errors;
    return (unsigned char)expected_native_answer;
}

static __attribute__((used)) unsigned char __fastcall loggable_probe(void *command) {
    ++loggable_calls;
    if (command != expected_command) ++loggable_arg_errors;
    return 1;
}

/* Preserve only AL from the C probe while returning conspicuous garbage in
 * the rest of RAX. The wrappers must honor their native unsigned-char ABI. */
static unsigned char __fastcall mock_native_valid(void *command, void *motivation)
    __attribute__((naked));
static unsigned char __fastcall mock_native_valid(void *command, void *motivation) {
    __asm__ volatile(
        "sub $0x28, %rsp\n\t"
        "movabs $valid_probe, %rax\n\t"
        "call *%rax\n\t"
        "add $0x28, %rsp\n\t"
        "movb %al, %r11b\n\t"
        "movabs $0x1122334455667700, %rax\n\t"
        "movb %r11b, %al\n\t"
        "ret\n\t");
}

static unsigned char __fastcall mock_native_loggable(void *command)
    __attribute__((naked));
static unsigned char __fastcall mock_native_loggable(void *command) {
    __asm__ volatile(
        "sub $0x28, %rsp\n\t"
        "movabs $loggable_probe, %rax\n\t"
        "call *%rax\n\t"
        "add $0x28, %rsp\n\t"
        "movb %al, %r11b\n\t"
        "movabs $0x8877665544332200, %rax\n\t"
        "movb %r11b, %al\n\t"
        "ret\n\t");
}

typedef unsigned char (__fastcall *ValidThunk)(void *, void *);
typedef unsigned char (__fastcall *LogThunk)(void *);

static void *__fastcall mock_destructor(void *command, unsigned int flags) {
    CommandProvenanceSnapshot snapshot;
    ++destructor_calls;
    destructor_flags = (int)flags;
    /* Guard must have removed metadata before entering the native destructor. */
    if (CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot)) ++valid_arg_errors;
    return destructor_result;
}

static void *fake_humans[8];
static int fake_human_count;
static void *fake_countries[8];
static int fake_country_lookup_calls, fake_observer_predicate_calls;
static int fake_country_lookup_missing;
static void *__fastcall fake_country_lookup(int32_t *tag) {
    ++fake_country_lookup_calls;
    if (fake_country_lookup_missing || !tag || *tag < 0 || *tag >= 8) return NULL;
    return fake_countries[*tag];
}
static unsigned char __fastcall fake_observer_eligible(void *country) {
    int32_t value = 0;
    ++fake_observer_predicate_calls;
    if (!country) return 0;
    memcpy(&value, (unsigned char *)country + 0x41c, sizeof(value));
    return (unsigned char)(value < 1);
}
static void *__fastcall fake_human_lookup(void *world, int32_t machineId) {
    (void)world;
    for (int i = 0; i < fake_human_count; ++i) {
        int32_t id = -1;
        memcpy(&id, (unsigned char *)fake_humans[i] + 0x98, sizeof(id));
        if (id == machineId) return fake_humans[i];
    }
    return NULL;
}

static uint64_t __fastcall fake_sender_resolver(void *context, uintptr_t connection) {
    (void)context; (void)connection;
    return fixture_sender_id;
}

static void __fastcall capture_callback(void *server, const void *packet, uint32_t length,
    uintptr_t connection, int channel) {
    (void)server; (void)packet; (void)length; (void)connection; (void)channel;
    ValidThunk thunk = (ValidThunk)(imageBase + 0x236795c - 16);
    expected_command = capture_command; expected_motivation = capture_motivation;
    CHECK(thunk(capture_command, capture_motivation) == expected_capture_answer);
}

static void *__fastcall mock_load_task(void *task) {
    ++load_task_calls;
    return load_task_result ? load_task_result : task;
}

static unsigned char __fastcall fake_canonical_equal(const int32_t *left, int32_t right) {
    /* Fixture countries 1 and 2 are aliases. */
    return (unsigned char)(*left == right || ((*left == 1 || *left == 2) && (right == 1 || right == 2)));
}

static unsigned char __fastcall fake_native_available(void *world, int32_t *tag) {
    (void)world;
    return (unsigned char)(tag && *tag >= 0 && *tag < 8);
}

static void emit_absolute_jump(void *site, const void *target) {
    unsigned char *p = (unsigned char *)site;
    uintptr_t address = (uintptr_t)target;
    p[0] = 0x48; p[1] = 0xb8; memcpy(p + 2, &address, sizeof(address));
    p[10] = 0xff; p[11] = 0xe0;
}

/* Entry ABI: RCX/RDX pass through. The wrapper's call sees the requested
 * in-image return address exactly, while this thunk maintains Win64 alignment. */
static void *emit_caller_thunk(uint32_t returnRva, const void *wrapper) {
    unsigned char *p = imageBase + returnRva - 16;
    uintptr_t address = (uintptr_t)wrapper;
    const unsigned char prefix[] = {0x48,0x83,0xec,0x28,0x48,0xb8};
    memcpy(p, prefix, sizeof(prefix));
    memcpy(p + 6, &address, sizeof(address));
    p[14] = 0xff; p[15] = 0xd0;
    p[16] = 0x48; p[17] = 0x83; p[18] = 0xc4; p[19] = 0x28; p[20] = 0xc3;
    return p;
}


static void set_private_pointer(uint32_t rva, const void *value) {
    memcpy(imageBase + rva, &value, sizeof(value));
}

static void **make_command(int32_t actor) {
    unsigned char *command = (unsigned char *)VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!command) return NULL;
    void *vtable = imageBase + classes[0].vtableRva;
    memcpy(command, &vtable, sizeof(vtable));
    memcpy(command + 0x0c, &fixture_sender_id, sizeof(uint32_t));
    memcpy(command + classes[0].actorOffset, &actor, sizeof(actor));
    return (void **)command;
}

static void set_fixture_human(void *record, int32_t id, int32_t country) {
    memset(record, 0, 0xa0);
    memcpy((unsigned char *)record + 0x98, &id, sizeof(id));
    memcpy((unsigned char *)record + 0x70, &country, sizeof(country));
}

static void reset_fixture(uint64_t epoch) {
    memset(peers, 0, sizeof(peers));
    memset(&ingress, 0, sizeof(ingress));
    InterlockedExchange(&active, 1);
    InterlockedExchange64(&epochCounter, (LONG64)epoch);
    AuthorityPolicyInit(&policy, epoch);
    CommandProvenanceInit(&provenance, epoch);
    valid_calls = valid_arg_errors = loggable_calls = loggable_arg_errors = 0;
    destructor_calls = destructor_flags = 0;
    fixture_history_count = 0;
    load_task_calls = 0;
    expected_native_answer = 1;
    expected_capture_answer = 1;
    fixture_sender_id = 1001;
    fake_human_count = 0;
    fake_country_lookup_calls = fake_observer_predicate_calls = 0;
    fake_country_lookup_missing = 0;
}

static void setup_private_image(void) {
    const SIZE_T reserveSize = 0x37ec000;
    imageBase = (unsigned char *)VirtualAlloc(NULL, reserveSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!imageBase) { fprintf(stderr, "VirtualAlloc reserve failed\n"); ExitProcess(2); }
    imageSize = reserveSize;
    const uint32_t pages[] = {0x06fc000,0x0bb4000,0x0bb5000,0x1c9000,0x1e2000,
        0x2250000,0x2252000,0x2253000,0x2367000,0x332f000};
    for (size_t i = 0; i < sizeof(pages)/sizeof(pages[0]); ++i) {
        if (!VirtualAlloc(imageBase + pages[i], 0x1000, MEM_COMMIT, PAGE_READWRITE)) {
            fprintf(stderr, "VirtualAlloc commit failed at %x\n", pages[i]); ExitProcess(2);
        }
    }
    emit_absolute_jump(imageBase + 0x1c9cd0, fake_human_lookup);
    emit_absolute_jump(imageBase + 0xbb52f0, fake_canonical_equal);
    emit_absolute_jump(imageBase + 0xbb48f0, fake_country_lookup);
    emit_absolute_jump(imageBase + 0x6fcfa0, fake_observer_eligible);
    emit_absolute_jump(imageBase + 0x1e2460, fake_native_available);
    set_private_pointer(0x332f260, NULL);
    DWORD oldProtect = 0;
    const uint32_t codePages[] = {0x06fc000,0x0bb4000,0x0bb5000,0x1c9000,0x1e2000,
        0x2250000,0x2252000,0x2253000,0x2367000};
    /* Materialize each authenticated return site once, then seal every code
     * page RX before executing any fixture thunk. */
    emit_caller_thunk(0x236795c, guarded_is_valid);
    emit_caller_thunk(0x22530ef, guarded_is_valid);
    emit_caller_thunk(0x2250dbd, guarded_is_valid);
    emit_caller_thunk(0x22536df, guarded_is_valid);
    emit_caller_thunk(0x225381d, guarded_loggable);
    emit_caller_thunk(0x22534b7, guarded_loggable);
    emit_caller_thunk(0x2252f6e, guarded_loggable);
    for (size_t i = 0; i < sizeof(codePages)/sizeof(codePages[0]); ++i)
        if (!VirtualProtect(imageBase + codePages[i], 0x1000, PAGE_EXECUTE_READ, &oldProtect)) {
            fprintf(stderr, "VirtualProtect fixture code failed\n"); ExitProcess(2);
        }
    FlushInstructionCache(GetCurrentProcess(), imageBase, reserveSize);
    senderResolver = fake_sender_resolver;
    classes[0].originalValid = mock_native_valid;
    classes[0].originalDestructor = mock_destructor;
    classes[0].originalLoggable = mock_native_loggable;
}

static void capture_from_receive(void **command, void *motivation) {
    static unsigned char server[0x60];
    static uintptr_t context = 0x778899;
    memcpy(server + 0x48, &context, sizeof(context));
    capture_command = command; capture_motivation = motivation;
    AuthorityGuardReceive(capture_callback, server, NULL, 0, 0x9911, 0);
}

static unsigned char invoke_valid(uint32_t returnRva, void **command, void *motivation) {
    ValidThunk thunk = (ValidThunk)(imageBase + returnRva - 16);
    expected_command = command; expected_motivation = motivation;
    return thunk(command, motivation);
}

static unsigned char invoke_log(uint32_t returnRva, void **command) {
    LogThunk thunk = (LogThunk)(imageBase + returnRva - 16);
    expected_command = command;
    return thunk(command);
}

static void *invoke_destructor(void **command, unsigned int flags) {
    return guarded_destructor(command, flags);
}

int main(void) {
    setup_private_image();
    static unsigned char world[0xb40];
    static unsigned char map[0x100];
    static unsigned char human[0xa0];
    static unsigned char secondHuman[0xa0];
    static unsigned char countries[8][0x500];
    void *mapPointer = map;
    int32_t countryCount = 8;
    uintptr_t humansPointer = (uintptr_t)human;
    int32_t humanCount = 1;
    memcpy(world + 0x340, &mapPointer, sizeof(mapPointer));
    memcpy(world + 0x34c, &countryCount, sizeof(countryCount));
    memcpy(world + 0xf8, &humansPointer, sizeof(humansPointer));
    memcpy(world + 0x104, &humanCount, sizeof(humanCount));
    set_private_pointer(0x332f260, world);
    fake_humans[0] = human; fake_humans[1] = secondHuman;
    for (int i = 0; i < 8; ++i) fake_countries[i] = countries[i];

    void *motivation = (void *)(uintptr_t)0x12345678;
    void **command;
    CommandProvenanceSnapshot snapshot;

    case_name = "receive captures exact claimed sender, then ordered primary allows owned actor";
    reset_fixture(41); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(valid_calls == 1 && valid_arg_errors == 0);
    CHECK(CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));
    CHECK(snapshot.authenticatedMachineId == 1001 && snapshot.sessionEpoch == 41);
    CHECK(invoke_valid(0x22530ef, command, motivation) == 1);
    CHECK(invoke_valid(0x2250dbd, command, motivation) == 1);
    CHECK(valid_calls == 3 && valid_arg_errors == 0);
    CHECK(invoke_valid(0x22536df, command, motivation) == 1);

    case_name = "foreign actor denial remains stable through motivation retry and history";
    reset_fixture(42); set_fixture_human(human, 1001, 3); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(invoke_log(0x225381d, command) == 0); /* Pending commands cannot serialize early. */
    CHECK(invoke_valid(0x22530ef, command, motivation) == 0);
    CHECK(invoke_valid(0x22536df, command, motivation) == 0);
    CHECK(invoke_log(0x225381d, command) == 0);
    CHECK(fixture_history_count == 0);

    case_name = "canonical aliases are accepted and only post-execution history serializes";
    reset_fixture(43); set_fixture_human(human, 1001, 2); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(invoke_log(0x225381d, command) == 0);
    CHECK(invoke_valid(0x22530ef, command, motivation) == 1);
    if (invoke_log(0x22534b7, command)) ++fixture_history_count;
    CHECK(fixture_history_count == 1);
    CHECK(invoke_log(0x2252f6e, command) == 1); /* Hot-join eligibility keeps native behavior. */

    case_name = "invalid actor tag is refused before the receive predicate can index it";
    reset_fixture(431); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    expected_capture_answer = 0;
    command = make_command(99); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(valid_calls == 0);
    CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));

    case_name = "an observer cannot issue an actor command for the native null country";
    reset_fixture(4311); set_fixture_human(human, 1001, 0); fake_human_count = 1;
    expected_capture_answer = 0;
    command = make_command(0); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(valid_calls == 0);
    CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));

    case_name = "ingress rejects a command whose claimed sender differs from transport identity";
    reset_fixture(432); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    expected_capture_answer = 0;
    command = make_command(1); CHECK(command != NULL);
    { uint32_t forged = 2002; memcpy((unsigned char *)command + 0x0c, &forged, sizeof(forged)); }
    capture_from_receive(command, motivation);
    CHECK(valid_calls == 1 && valid_arg_errors == 0);
    CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));

    case_name = "full provenance store refuses ingress capture instead of permitting queued bypass";
    reset_fixture(433);
    expected_capture_answer = 0;
    for (uint32_t i = 0; i < COMMAND_PROVENANCE_MAX_LIVE; ++i) {
        CommandProvenanceSnapshot filled;
        void *identity = (void *)(uintptr_t)(0x10000000ull + (uint64_t)i * 0x1000ull);
        CHECK(CommandProvenanceCapture(&provenance, identity, (void *)(imageBase + classes[0].vtableRva),
            433, 1001, 1001, 1, 0x6000, 0x7000, 0x8000, 1, &filled) == COMMAND_PROVENANCE_CAPTURED);
    }
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));

    case_name = "world load task advances epoch, clears grants, retains old metadata and returns native result";
    reset_fixture(434); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    { AuthorityGrant grant; memset(&grant, 0, sizeof(grant));
      grant.grantId = 1; grant.sessionEpoch = 434; grant.peer.machineId = 1001;
      grant.peer.generation = 1; grant.sourceCountry = 1; grant.destinationCountry = 2;
      grant.kind = AUTHORITY_GRANT_SCRIPT; grant.allowOccupiedDestination = 1;
      CHECK(AuthorityPolicyGrantTrusted(&policy, &grant, GetTickCount64(), 434) == AUTHORITY_REASON_NONE); }
    CHECK(policy.highestGrantId == 1);
    originalLoadTask = mock_load_task;
    load_task_result = (void *)(uintptr_t)0x9876543212345678ull;
    { void *task = (void *)(uintptr_t)0x11223344;
      CHECK(guarded_load_task(task) == load_task_result); }
    CHECK(current_epoch() == 435 && policy.highestGrantId == 0);
    CHECK(load_task_calls == 1);
    CHECK(CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));
    CHECK(snapshot.sessionEpoch == 434);
    CHECK(invoke_valid(0x22530ef, command, motivation) == 0);
    { uint32_t retainedGeneration = snapshot.authenticatedPeerGeneration;
      void **firstAfterLoad = make_command(1); CHECK(firstAfterLoad != NULL);
      capture_from_receive(firstAfterLoad, motivation);
      CHECK(CommandProvenanceFindAny(&provenance, firstAfterLoad,
          (void *)(imageBase + classes[0].vtableRva), &snapshot));
      CHECK(snapshot.sessionEpoch == 435 && snapshot.authenticatedPeerGeneration == retainedGeneration);
      CHECK(invoke_valid(0x22530ef, firstAfterLoad, motivation) == 1); }

    case_name = "native AL false dominates cached allow despite garbage in upper RAX";
    reset_fixture(44); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(invoke_valid(0x22530ef, command, motivation) == 1);
    expected_native_answer = 0;
    CHECK(invoke_valid(0x22536df, command, motivation) == 0);
    CHECK(valid_calls == 3 && valid_arg_errors == 0);

    case_name = "retained old-epoch metadata is denied after session advance";
    reset_fixture(45); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(CommandProvenanceAdvanceSession(&provenance, 46));
    AuthorityPolicyReset(&policy, 46); InterlockedExchange64(&epochCounter, 46);
    CHECK(CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));
    CHECK(invoke_valid(0x22530ef, command, motivation) == 0);

    case_name = "destructor preserves full pointer ABI and removes metadata before callback";
    reset_fixture(47); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = make_command(1); CHECK(command != NULL);
    capture_from_receive(command, motivation);
    CHECK(CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));
    { CommandProvenanceSnapshot old = snapshot;
    destructor_result = (void *)(uintptr_t)0x123456789abcdef0ull;
    CHECK(invoke_destructor(command, 0xa5a55a5a) == destructor_result);
    CHECK(destructor_calls == 1 && destructor_flags == (int)0xa5a55a5a);
    CHECK(valid_arg_errors == 0);
    CHECK(!CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[0].vtableRva), &snapshot));
      CHECK(CommandProvenanceCapture(&provenance, command,
          (void *)(imageBase + classes[0].vtableRva), 47, 1001, 1001, 1,
          0x6000, 0x7000, 0x8000, 1, &snapshot) == COMMAND_PROVENANCE_CAPTURED);
      CHECK(CommandProvenanceRemove(&provenance, &old) == 0);
      CHECK(CommandProvenanceFindAny(&provenance, command,
          (void *)(imageBase + classes[0].vtableRva), &snapshot)); }

    case_name = "host-local no-provenance call passes native result and motivation unchanged";
    reset_fixture(48); command = make_command(1); CHECK(command != NULL);
    expected_command = command; expected_motivation = motivation;
    expected_native_answer = 1;
    CHECK(guarded_is_valid(command, motivation) == 1);
    CHECK(valid_calls == 1 && valid_arg_errors == 0);
    expected_native_answer = 0;
    CHECK(guarded_is_valid(command, motivation) == 0);
    CHECK(valid_calls == 2 && valid_arg_errors == 0);

    printf("PASS %u native authority wrapper assertions\n", assertions);
    return 0;
}
