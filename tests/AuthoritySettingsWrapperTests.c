/* Remote lobby settings must remain host-local while retaining native results. */
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main

static unsigned settings_assertions;
#define S_CHECK(c) do { ++settings_assertions; if (!(c)) { \
    fprintf(stderr, "FAIL settings wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static const size_t settingsRows[] = {25, 26, 27, 28, 29, 30};
static unsigned char settingsWorld[0xb40];

static void **settings_command(size_t rowIndex) {
    unsigned char *command = (unsigned char *)VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!command) return NULL;
    void *vtable = imageBase + classes[rowIndex].vtableRva;
    memcpy(command, &vtable, sizeof(vtable));
    uint32_t claimed = (uint32_t)fixture_sender_id;
    memcpy(command + 0x0c, &claimed, sizeof(claimed));
    classes[rowIndex].originalValid = mock_native_valid;
    classes[rowIndex].originalLoggable = mock_native_loggable;
    return (void **)command;
}

int main(void) {
    setup_private_image();
    void *motivation = (void *)(uintptr_t)0x12345678;

    for (size_t i = 0; i < sizeof(settingsRows) / sizeof(settingsRows[0]); ++i) {
        size_t rowIndex = settingsRows[i];
        case_name = "authenticated remote settings command is denied before retry/history";
        reset_fixture(2000 + i);
        memset(settingsWorld, 0, sizeof(settingsWorld));
        set_private_pointer(0x332f260, settingsWorld);
        void **command = settings_command(rowIndex);
        S_CHECK(command != NULL);
        capture_from_receive(command, motivation);
        S_CHECK(valid_calls == 1);
        S_CHECK(invoke_log(0x225381d, command) == 0);
        S_CHECK(invoke_valid(0x22530ef, command, motivation) == 0);
        S_CHECK(invoke_valid(0x2250dbd, command, motivation) == 0);
        S_CHECK(invoke_valid(0x22536df, command, motivation) == 0);
        S_CHECK(invoke_log(0x225381d, command) == 0);
        S_CHECK(fixture_history_count == 0);

        case_name = "settings command queued in an earlier epoch stays denied";
        reset_fixture(2100 + i);
        memset(settingsWorld, 0, sizeof(settingsWorld));
        set_private_pointer(0x332f260, settingsWorld);
        command = settings_command(rowIndex);
        S_CHECK(command != NULL);
        capture_from_receive(command, motivation);
        S_CHECK(CommandProvenanceAdvanceSession(&provenance, 2200 + i));
        AuthorityPolicyReset(&policy, 2200 + i);
        InterlockedExchange64(&epochCounter, (LONG64)(2200 + i));
        S_CHECK(invoke_valid(0x22530ef, command, motivation) == 0);
        S_CHECK(invoke_log(0x225381d, command) == 0);
        S_CHECK(fixture_history_count == 0);

        case_name = "host-local settings command preserves both native truth values";
        reset_fixture(2300 + i);
        memset(settingsWorld, 0, sizeof(settingsWorld));
        set_private_pointer(0x332f260, settingsWorld);
        command = settings_command(rowIndex);
        S_CHECK(command != NULL);
        expected_command = command;
        expected_motivation = motivation;
        expected_native_answer = 1;
        S_CHECK(guarded_is_valid(command, motivation) == 1);
        expected_native_answer = 0;
        S_CHECK(guarded_is_valid(command, motivation) == 0);
        S_CHECK(valid_calls == 2 && valid_arg_errors == 0);
    }

    printf("PASS %u settings wrapper assertions\n", settings_assertions);
    return 0;
}
