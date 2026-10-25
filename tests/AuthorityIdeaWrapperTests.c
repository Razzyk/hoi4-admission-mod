/* Authenticated native-boundary tests for Add/Remove/Replace idea commands.
 * The shared fixture reserves a private image and never touches a game. */
#define main authority_native_wrapper_tests_main
#include "AuthorityNativeWrapperTests.c"
#undef main

static unsigned idea_assertions;
#define I_CHECK(c) do { ++idea_assertions; if (!(c)) { \
    fprintf(stderr, "FAIL idea wrapper line %d: %s\n", __LINE__, #c); ExitProcess(1); \
} } while (0)

static void *idea_command(uint32_t rowIndex, int32_t actor, void *oldIdea,
    void *newIdea, uint8_t costFlag) {
    unsigned char *command = (unsigned char *)VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!command) return NULL;
    void *vtable = imageBase + classes[rowIndex].vtableRva;
    memcpy(command, &vtable, sizeof(vtable));
    memcpy(command + 0x0c, &fixture_sender_id, sizeof(uint32_t));
    memcpy(command + 0x28, &actor, sizeof(actor));
    if (rowIndex == 5) {
        memcpy(command + 0x30, &oldIdea, sizeof(oldIdea));
        memcpy(command + 0x38, &newIdea, sizeof(newIdea));
        memcpy(command + 0x40, &costFlag, sizeof(costFlag));
    } else {
        void *idea = rowIndex == 4 ? oldIdea : newIdea;
        memcpy(command + 0x30, &idea, sizeof(idea));
        memcpy(command + 0x38, &costFlag, sizeof(costFlag));
    }
    return command;
}

static void link_idea(void *idea, void *category, void *group,
    int32_t groupType, uint8_t hidden) {
    memcpy((unsigned char *)idea + 0xaa0, &category, sizeof(category));
    memcpy((unsigned char *)category + 0x60, &group, sizeof(group));
    memcpy((unsigned char *)group + 0x78, &groupType, sizeof(groupType));
    memcpy((unsigned char *)group + 0x7c, &hidden, sizeof(hidden));
}

int main(void) {
    setup_private_image();
    static unsigned char world[0xb40], map[0x100], human[0xa0];
    static unsigned char ideas[4][0xb00], categories[4][0x80], groups[4][0x100];
    void *mapPointer = map;
    int32_t countryCount = 8, humanCount = 1;
    uintptr_t humansPointer = (uintptr_t)human;
    memcpy(world + 0x340, &mapPointer, sizeof(mapPointer));
    memcpy(world + 0x34c, &countryCount, sizeof(countryCount));
    memcpy(world + 0xf8, &humansPointer, sizeof(humansPointer));
    memcpy(world + 0x104, &humanCount, sizeof(humanCount));
    set_private_pointer(0x332f260, world);
    fake_humans[0] = human;
    classes[3].originalValid = mock_native_valid;
    classes[4].originalValid = mock_native_valid;
    classes[5].originalValid = mock_native_valid;
    classes[3].originalLoggable = mock_native_loggable;
    classes[4].originalLoggable = mock_native_loggable;
    classes[5].originalLoggable = mock_native_loggable;
    void *motivation = (void *)(uintptr_t)0x12345678;
    uint64_t epoch = 801;

    case_name = "purchasable zero-cost idea passes and only becomes serializable after ordered authorization";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    link_idea(ideas[0], categories[0], groups[0], 0, 0);
    void *command = idea_command(3, 1, NULL, ideas[0], 1); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 1 && invoke_log(0x225381d, (void **)command) == 0);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 1);
    I_CHECK(invoke_valid(0x22536df, (void **)command, motivation) == 1);
    I_CHECK(invoke_log(0x225381d, (void **)command) == 1);

    case_name = "zero cost flag is refused at ordered boundary while native validation still runs";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(3, 1, NULL, ideas[0], 0); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 1);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 0);
    I_CHECK(valid_calls == 2 && invoke_log(0x225381d, (void **)command) == 0);

    case_name = "hidden and national-spirit add groups fail safe preflight before native dereference";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    link_idea(ideas[1], categories[1], groups[1], 0, 1);
    command = idea_command(3, 1, NULL, ideas[1], 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0 && !CommandProvenanceFindAny(&provenance, command,
        (void *)(imageBase + classes[3].vtableRva), &(CommandProvenanceSnapshot){0}));
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    link_idea(ideas[2], categories[2], groups[2], 1, 0);
    command = idea_command(3, 1, NULL, ideas[2], 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);

    case_name = "remove checks its old idea and native cost flag";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(4, 1, ideas[0], NULL, 1); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 1);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(4, 1, ideas[2], NULL, 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(4, 1, ideas[0], NULL, 0); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 0);

    case_name = "replace checks both old and new ideas plus its separate cost flag";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(5, 1, ideas[0], ideas[0], 1); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 1);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(5, 1, ideas[2], ideas[0], 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(5, 1, ideas[0], ideas[2], 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(5, 1, ideas[0], ideas[0], 0); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 0);

    case_name = "null unreadable and high pointers are rejected before native validation";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(3, 1, NULL, NULL, 1); I_CHECK(command != NULL);
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    { void *unreadable = (void *)(uintptr_t)0x7fffffffffffULL;
      command = idea_command(3, 1, NULL, unreadable, 1); I_CHECK(command != NULL); }
    expected_capture_answer = 0; capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 0);

    case_name = "forged actor country is denied and native false still dominates";
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(3, 3, NULL, ideas[0], 1); I_CHECK(command != NULL);
    capture_from_receive((void **)command, motivation);
    I_CHECK(invoke_valid(0x22530ef, (void **)command, motivation) == 0);
    reset_fixture(epoch++); set_fixture_human(human, 1001, 1); fake_human_count = 1;
    command = idea_command(3, 1, NULL, ideas[0], 1); I_CHECK(command != NULL);
    expected_native_answer = 0; expected_capture_answer = 0;
    capture_from_receive((void **)command, motivation);
    I_CHECK(valid_calls == 1 && invoke_valid(0x22530ef, (void **)command, motivation) == 0);

    printf("PASS %u native idea wrapper assertions\n", idea_assertions);
    return 0;
}
