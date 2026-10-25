/* Ownership checks for authenticated industrial-organization trait commands. */
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main

static unsigned mio_assertions;
#define M_CHECK(c) do { ++mio_assertions; if (!(c)) { \
    fprintf(stderr, "FAIL MIO wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static unsigned char mioWorld[0xb40];
static unsigned char mioMap[0x100];
static unsigned char mioHuman[0xa0];
static unsigned char mioOrganizations[2][0x200];
static unsigned char mioReferences[2][0x10];
static unsigned char mioTraitEntries[2][0x10];
static void *mioExpectedReferences[2];
static void *mioExpectedOrganizations[2];
static size_t mioReferenceCount;
static void **mioCommand;

static void *__fastcall fake_mio_resolver(void *reference) {
    for (size_t i = 0; i < mioReferenceCount; ++i)
        if (reference == mioExpectedReferences[i]) return mioExpectedOrganizations[i];
    return NULL;
}

static void set_u32(void *base, size_t offset, uint32_t value) {
    memcpy((unsigned char *)base + offset, &value, sizeof(value));
}

static void set_ptr(void *base, size_t offset, const void *value) {
    uintptr_t pointer = (uintptr_t)value;
    memcpy((unsigned char *)base + offset, &pointer, sizeof(pointer));
}

static void set_mio_organization(size_t index, int32_t country, int validType) {
    memset(mioOrganizations[index], 0, sizeof(mioOrganizations[index]));
    set_ptr(mioOrganizations[index], 0, imageBase + (validType ? 0x2967a28 : 0x2967cd8));
    memcpy(mioOrganizations[index] + 0x120, &country, sizeof(country));
}

static void setup_mio_resolver(void) {
    if (!VirtualAlloc(imageBase + 0x221f000, 0x1000, MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "MIO resolver page commit failed\n"); ExitProcess(2);
    }
    emit_absolute_jump(imageBase + 0x221f310, fake_mio_resolver);
    DWORD oldProtection = 0;
    if (!VirtualProtect(imageBase + 0x221f000, 0x1000, PAGE_EXECUTE_READ, &oldProtection)) {
        fprintf(stderr, "MIO resolver page seal failed\n"); ExitProcess(2);
    }
    FlushInstructionCache(GetCurrentProcess(), imageBase + 0x221f000, 0x1000);
}

static void prepare_mio_fixture(uint64_t epoch, size_t rowIndex, int32_t ownerCountry,
    int32_t senderCountry, uint32_t vectorCount) {
    reset_fixture(epoch);
    memset(mioWorld, 0, sizeof(mioWorld));
    memset(mioMap, 0, sizeof(mioMap));
    memset(mioHuman, 0, sizeof(mioHuman));
    memset(mioReferences, 0, sizeof(mioReferences));
    memset(mioTraitEntries, 0, sizeof(mioTraitEntries));
    mioReferenceCount = 0;
    set_fixture_human(mioHuman, 1001, senderCountry);
    fake_humans[0] = mioHuman;
    fake_human_count = 1;
    void *map = mioMap;
    int32_t countryCount = 8;
    memcpy(mioWorld + 0x340, &map, sizeof(map));
    memcpy(mioWorld + 0x34c, &countryCount, sizeof(countryCount));
    set_private_pointer(0x332f260, mioWorld);

    mioCommand = (void **)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mioCommand) { fprintf(stderr, "MIO command allocation failed\n"); ExitProcess(2); }
    set_ptr(mioCommand, 0, imageBase + classes[rowIndex].vtableRva);
    uint32_t claimed = (uint32_t)fixture_sender_id;
    memcpy((unsigned char *)mioCommand + 0x0c, &claimed, sizeof(claimed));
    classes[rowIndex].originalValid = mock_native_valid;
    classes[rowIndex].originalLoggable = mock_native_loggable;

    if (rowIndex == 35) {
        for (uint32_t i = 0; i < vectorCount && i < 2; ++i) {
            set_ptr(mioTraitEntries[i], 0, imageBase + 0x2967a28);
            set_u32(mioTraitEntries[i], 8, i + 1);
        }
        set_u32(mioReferences[0], 0, 1);
        set_mio_organization(0, ownerCountry, 1);
        mioExpectedReferences[0] = (unsigned char *)mioCommand + 0x48;
        mioExpectedOrganizations[0] = mioOrganizations[0];
        mioReferenceCount = 1;
        set_ptr(mioCommand, 0x30, mioTraitEntries);
        set_u32(mioCommand, 0x38, 2);
        set_u32(mioCommand, 0x3c, vectorCount);
        memcpy((unsigned char *)mioCommand + 0x48, mioReferences[0], sizeof(mioReferences[0]));
    } else {
        set_u32(mioReferences[0], 0, 1);
        set_mio_organization(0, ownerCountry, 1);
        mioExpectedReferences[0] = (unsigned char *)mioCommand + 0x40;
        memcpy((unsigned char *)mioCommand + 0x40, mioReferences[0], sizeof(mioReferences[0]));
        mioExpectedOrganizations[0] = mioOrganizations[0];
        mioReferenceCount = 1;
    }
}

int main(void) {
    setup_private_image();
    setup_mio_resolver();
    void *motivation = (void *)(uintptr_t)0x12345678;
    static const size_t mioRows[] = {31, 32, 33, 34, 35};

    for (size_t i = 0; i < sizeof(mioRows) / sizeof(mioRows[0]); ++i) {
        size_t rowIndex = mioRows[i];
        case_name = "organization owner controlled by authenticated sender is accepted";
        prepare_mio_fixture(3000 + i, rowIndex, 1, 1, 1);
        capture_from_receive(mioCommand, motivation);
        M_CHECK(valid_calls == 1);
        M_CHECK(invoke_valid(0x22530ef, mioCommand, motivation) == 1);
        M_CHECK(invoke_valid(0x2250dbd, mioCommand, motivation) == 1);
        M_CHECK(invoke_log(0x225381d, mioCommand) == 1);

        case_name = "organization owned by another country is denied before history serialization";
        prepare_mio_fixture(3100 + i, rowIndex, 3, 1, 1);
        capture_from_receive(mioCommand, motivation);
        M_CHECK(invoke_log(0x225381d, mioCommand) == 0);
        M_CHECK(invoke_valid(0x22530ef, mioCommand, motivation) == 0);
        M_CHECK(invoke_valid(0x2250dbd, mioCommand, motivation) == 0);
        M_CHECK(invoke_valid(0x22536df, mioCommand, motivation) == 0);
        M_CHECK(invoke_log(0x225381d, mioCommand) == 0);
        M_CHECK(fixture_history_count == 0);
    }

    case_name = "wrong native organization type is refused before IsValid";
    prepare_mio_fixture(3200, 31, 1, 1, 1);
    set_mio_organization(0, 1, 0);
    expected_capture_answer = 0;
    capture_from_receive(mioCommand, motivation);
    M_CHECK(valid_calls == 0);
    M_CHECK(!CommandProvenanceFindAny(&provenance, mioCommand,
        (void *)(imageBase + classes[31].vtableRva), &(CommandProvenanceSnapshot){0}));

    case_name = "SetQueue rejects a count beyond capacity before native iteration";
    prepare_mio_fixture(3201, 35, 1, 1, 2);
    set_u32(mioCommand, 0x38, 1);
    expected_capture_answer = 0;
    capture_from_receive(mioCommand, motivation);
    M_CHECK(valid_calls == 0);

    case_name = "SetQueue validates trait vector span and binds its typed organization";
    prepare_mio_fixture(3202, 35, 1, 1, 2);
    capture_from_receive(mioCommand, motivation);
    M_CHECK(valid_calls == 1);
    set_mio_organization(0, 3, 1);
    M_CHECK(invoke_valid(0x22530ef, mioCommand, motivation) == 0);
    M_CHECK(invoke_log(0x225381d, mioCommand) == 0);

    case_name = "native false remains authoritative for a valid organization owner";
    prepare_mio_fixture(3203, 31, 1, 1, 1);
    expected_native_answer = 0;
    expected_capture_answer = 0;
    capture_from_receive(mioCommand, motivation);
    M_CHECK(valid_calls == 1);
    M_CHECK(invoke_valid(0x22530ef, mioCommand, motivation) == 0);

    case_name = "old-epoch MIO command cannot be retried after a world transition";
    prepare_mio_fixture(3204, 31, 1, 1, 1);
    capture_from_receive(mioCommand, motivation);
    M_CHECK(CommandProvenanceAdvanceSession(&provenance, 3205));
    AuthorityPolicyReset(&policy, 3205);
    InterlockedExchange64(&epochCounter, 3205);
    M_CHECK(invoke_valid(0x22530ef, mioCommand, motivation) == 0);
    M_CHECK(invoke_log(0x225381d, mioCommand) == 0);

    printf("PASS %u MIO wrapper assertions\n", mio_assertions);
    return 0;
}
