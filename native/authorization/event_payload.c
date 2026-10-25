#include "event_payload.h"
#include <stdlib.h>

typedef unsigned char u8;

#ifdef AUTHORITY_EVENT_PAYLOAD_TEST
static AuthorityEventResolveRefTestFn testEventResolver;
static AuthorityEventResolveEntityTestFn testEntityResolver;
static AuthorityEventCanonicalEqualTestFn testCanonicalEqual;

void AuthorityEventPayloadTestSetResolvers(AuthorityEventResolveRefTestFn eventResolver,
    AuthorityEventResolveEntityTestFn entityResolver,
    AuthorityEventCanonicalEqualTestFn canonicalEqual) {
    testEventResolver = eventResolver;
    testEntityResolver = entityResolver;
    testCanonicalEqual = canonicalEqual;
}
#endif

static AuthorityResult event_result(AuthorityDecision decision, AuthorityReason reason) {
    AuthorityResult result;
    result.decision = decision;
    result.reason = reason;
    result.usedGrantKind = 0;
    return result;
}

static AuthorityResult malformed(void) {
    return event_result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_EVENT_PAYLOAD_INVALID);
}

static int read_memory(const void *source, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return source && destination && size &&
        ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) && copied == size;
}

static void *at_offset(const void *base, uintptr_t offset) {
    uintptr_t address = (uintptr_t)base;
    if (!base || address > UINTPTR_MAX - offset) return NULL;
    return (void *)(address + offset);
}

static int indexed_address(uintptr_t base, size_t index, size_t stride, uintptr_t *out) {
    if (!base || !out || (index && stride > SIZE_MAX / index)) return 0;
    size_t offset = index * stride;
    if (base > UINTPTR_MAX - offset) return 0;
    *out = base + offset;
    return 1;
}

static int read_at(const void *base, uintptr_t offset, void *out, SIZE_T size) {
    void *address = at_offset(base, offset);
    return address && read_memory(address, out, size);
}

static int read_pointer(const void *base, uintptr_t offset, uintptr_t *out) {
    return out && read_at(base, offset, out, sizeof(*out));
}

static int country_valid(void *world, int32_t country) {
    uintptr_t tagMap = 0;
    int32_t count = -1;
    return country >= 0 && read_at(world, 0x340, &tagMap, sizeof(tagMap)) && tagMap &&
        read_at(world, 0x34c, &count, sizeof(count)) && count > 0 && country < count;
}

static int event_countries_equal(unsigned char *imageBase, void *world, int32_t left, int32_t right) {
    typedef unsigned char (__fastcall *CanonicalEqualFn)(const int32_t *, int32_t);
    if (!country_valid(world, left) || !country_valid(world, right)) return 0;
    if (left == right) return 1;
#ifdef AUTHORITY_EVENT_PAYLOAD_TEST
    if (testCanonicalEqual) return testCanonicalEqual(&left, right) != 0;
#endif
    return ((CanonicalEqualFn)(imageBase + 0xbb52f0))(&left, right) != 0;
}

static int scope_country_equal(unsigned char *imageBase, void *world, void *left, void *right) {
    int32_t leftCountry = -1, rightCountry = -1;
    if (!read_at(left, 8, &leftCountry, sizeof(leftCountry)) ||
        !read_at(right, 8, &rightCountry, sizeof(rightCountry))) return 0;
    if (leftCountry == rightCountry) return country_valid(world, leftCountry);
    if (leftCountry == 0 || rightCountry == 0) return 0;
    return event_countries_equal(imageBase, world, leftCountry, rightCountry);
}

typedef struct EventScopePair { void *left, *right; } EventScopePair;

/* The first walk establishes a trusted size bound from the host's pending
 * scope. The comparison then carries pairs iteratively and refuses an
 * attacker-expanded graph or an ambiguous remapping of trusted nodes. */
typedef struct EventScopeFrame { void *scope; unsigned nextEdge; } EventScopeFrame;

static int trusted_scope_expansion_size(void *world, void *root, size_t *outCount) {
    static const uintptr_t edgeOffsets[3] = {0x18, 0x20, 0x28};
    EventScopeFrame *stack = NULL;
    size_t stackCapacity = 16, depth = 1, visited = 1;
    if (!root || !outCount) return 0;
    stack = (EventScopeFrame *)malloc(stackCapacity * sizeof(*stack));
    if (!stack) return 0;
    stack[0] = (EventScopeFrame){root, 0};
    while (depth) {
        EventScopeFrame *frame = &stack[depth - 1];
        if (frame->nextEdge == 3) { --depth; continue; }
        u8 nodeBytes[0xb0];
        int32_t nodeCountry = -1;
        if (!read_memory(frame->scope, nodeBytes, sizeof(nodeBytes)) ||
            !read_at(frame->scope, 8, &nodeCountry, sizeof(nodeCountry)) ||
            (nodeCountry != 0 && !country_valid(world, nodeCountry))) goto fail;
        uintptr_t child = 0;
        if (!read_pointer(frame->scope, edgeOffsets[frame->nextEdge++], &child)) goto fail;
        if (!child || child == (uintptr_t)frame->scope) continue;
        for (size_t i = 0; i < depth; ++i)
            if (stack[i].scope == (void *)child) goto fail; /* Native clone cannot safely copy a non-self cycle. */
        if (depth == stackCapacity) {
            if (stackCapacity > SIZE_MAX / 2 / sizeof(*stack)) goto fail;
            stackCapacity *= 2;
            EventScopeFrame *grown = (EventScopeFrame *)realloc(stack, stackCapacity * sizeof(*stack));
            if (!grown) goto fail;
            stack = grown;
        }
        if (visited == SIZE_MAX) goto fail;
        ++visited;
        stack[depth++] = (EventScopeFrame){(void *)child, 0};
    }
    *outCount = visited;
    free(stack); return visited > 0;
fail:
    free(stack); return 0;
}

static int scope_scalars_equal(void *left, void *right) {
    static const uintptr_t pointerOffsets[] = {0x48, 0x60};
    static const uintptr_t scalarOffsets[] = {0x50, 0x54, 0x68, 0x6c, 0x70, 0x74, 0xa8};
    uintptr_t lp = 0, rp = 0;
    int32_t li = 0, ri = 0;
    for (size_t i = 0; i < sizeof(pointerOffsets) / sizeof(pointerOffsets[0]); ++i) {
        if (!read_pointer(left, pointerOffsets[i], &lp) ||
            !read_pointer(right, pointerOffsets[i], &rp) || lp != rp) return 0;
    }
    for (size_t i = 0; i < sizeof(scalarOffsets) / sizeof(scalarOffsets[0]); ++i) {
        if (!read_at(left, scalarOffsets[i], &li, sizeof(li)) ||
            !read_at(right, scalarOffsets[i], &ri, sizeof(ri)) || li != ri) return 0;
    }
    return 1;
}

static int scope_graph_equal(unsigned char *imageBase, void *world,
    void *pendingScope, void *commandScope) {
    static const uintptr_t edgeOffsets[3] = {0x18, 0x20, 0x28};
    EventScopeFrame *leftStack = NULL, *rightStack = NULL;
    size_t trustedCount = 0, depth = 1, compared = 1;
    if (!trusted_scope_expansion_size(world, pendingScope, &trustedCount) || !commandScope) return 0;
    if (trustedCount > SIZE_MAX / sizeof(*leftStack)) return 0;
    leftStack = (EventScopeFrame *)malloc(trustedCount * sizeof(*leftStack));
    rightStack = (EventScopeFrame *)malloc(trustedCount * sizeof(*rightStack));
    if (!leftStack || !rightStack) { free(leftStack); free(rightStack); return 0; }
    leftStack[0] = (EventScopeFrame){pendingScope, 0};
    rightStack[0] = (EventScopeFrame){commandScope, 0};
    if (!scope_country_equal(imageBase, world, pendingScope, commandScope) ||
        !scope_scalars_equal(pendingScope, commandScope)) { free(leftStack); free(rightStack); return 0; }
    while (depth) {
        EventScopeFrame *leftFrame = &leftStack[depth - 1];
        EventScopeFrame *rightFrame = &rightStack[depth - 1];
        if (leftFrame->nextEdge == 3) { --depth; continue; }
        uintptr_t leftChild = 0, rightChild = 0;
        uintptr_t edgeOffset = edgeOffsets[leftFrame->nextEdge];
        ++leftFrame->nextEdge;
        ++rightFrame->nextEdge;
        if (!read_pointer(leftFrame->scope, edgeOffset, &leftChild) ||
            !read_pointer(rightFrame->scope, edgeOffset, &rightChild)) goto fail;
        if (!leftChild || !rightChild) {
            if (leftChild != rightChild) goto fail;
            continue;
        }
        int leftSelf = leftChild == (uintptr_t)leftFrame->scope;
        int rightSelf = rightChild == (uintptr_t)rightFrame->scope;
        if (leftSelf || rightSelf) {
            if (leftSelf != rightSelf) goto fail;
            continue;
        }
        for (size_t i = 0; i < depth; ++i) {
            if (leftStack[i].scope == (void *)leftChild ||
                rightStack[i].scope == (void *)rightChild) goto fail;
        }
        if (depth >= trustedCount || ++compared > trustedCount ||
            !scope_country_equal(imageBase, world, (void *)leftChild, (void *)rightChild) ||
            !scope_scalars_equal((void *)leftChild, (void *)rightChild)) goto fail;
        leftStack[depth] = (EventScopeFrame){(void *)leftChild, 0};
        rightStack[depth] = (EventScopeFrame){(void *)rightChild, 0};
        ++depth;
    }
    free(leftStack); free(rightStack); return 1;
fail:
    free(leftStack); free(rightStack); return 0;
}

static void *resolve_event(unsigned char *imageBase, void *reference) {
    typedef void *(__fastcall *ResolveRefFn)(void *);
#ifdef AUTHORITY_EVENT_PAYLOAD_TEST
    if (testEventResolver) return testEventResolver(reference);
#endif
    return ((ResolveRefFn)(imageBase + 0x221f310))(reference);
}

static void *resolve_entity(unsigned char *imageBase, void *scope) {
    typedef void *(__fastcall *ResolveEntityFn)(void *);
#ifdef AUTHORITY_EVENT_PAYLOAD_TEST
    if (testEntityResolver) return testEntityResolver(scope);
#endif
    return ((ResolveEntityFn)(imageBase + 0x535e00))(scope);
}

static int event_scope_recipient(unsigned char *imageBase, void *world,
    void *scope, int32_t *outCountry) {
    int32_t scopeCountry = 0, scopeState = 0, stateCount = 0, country = -1;
    uintptr_t stateMap = 0, state = 0;
    if (!scope || !outCountry || !read_at(scope, 8, &scopeCountry, sizeof(scopeCountry)) ||
        !read_at(scope, 0xa8, &scopeState, sizeof(scopeState))) return 0;
    if (scopeCountry > 0) country = scopeCountry;
    else if (scopeState > 0) {
        if (!read_at(world, 0x2c8, &stateMap, sizeof(stateMap)) || !stateMap ||
            !read_at(world, 0x2d4, &stateCount, sizeof(stateCount)) ||
            scopeState >= stateCount) return 0;
        uintptr_t stateSlot = 0;
        if (!indexed_address(stateMap, (size_t)scopeState, sizeof(uintptr_t), &stateSlot) ||
            !read_memory((void *)stateSlot,
            &state, sizeof(state)) || !state ||
            !read_at((void *)state, 0xc8, &country, sizeof(country))) return 0;
    } else {
        void *entity = resolve_entity(imageBase, scope);
        if (!entity || !read_at(entity, 0x120, &country, sizeof(country))) return 0;
    }
    if (!country_valid(world, country)) return 0;
    *outCountry = country;
    return 1;
}

static int sender_controls_recipient(unsigned char *imageBase, void *world,
    uint64_t senderMachineId, int32_t actor, int *outLeader) {
    uintptr_t roster = 0;
    int32_t count = -1;
    unsigned matches = 0;
    if (!outLeader || !senderMachineId || senderMachineId > INT32_MAX ||
        !read_at(world, 0xf8, &roster, sizeof(roster)) || !roster ||
        !read_at(world, 0x104, &count, sizeof(count)) || count < 0) return 0;
    for (int32_t i = 0; i < count; ++i) {
        uintptr_t recordAddress = 0;
        if (!indexed_address(roster, (size_t)i, 0xa0, &recordAddress)) return 0;
        int32_t machineId = 0, country = -1;
        u8 flags = 0;
        if (!read_at((void *)recordAddress, 0x98, &machineId, sizeof(machineId)) ||
            !read_at((void *)recordAddress, 0x70, &country, sizeof(country)) ||
            !read_at((void *)recordAddress, 0x94, &flags, sizeof(flags))) return 0;
        if (machineId != (int32_t)senderMachineId) continue;
        ++matches;
        if (!event_countries_equal(imageBase, world, country, actor)) return 0;
        *outLeader = (flags & 1) != 0;
    }
    return matches == 1;
}

static int event_allows_nonleader(unsigned char *imageBase, void *event,
    int32_t optionCount) {
    uintptr_t optionVector = 0;
    u8 eventWindow = 0;
    if (!read_at(event, 0x420, &eventWindow, sizeof(eventWindow)) || !eventWindow ||
        !read_at(event, 0x368, &optionVector, sizeof(optionVector)) || !optionVector ||
        optionCount < 0) return 0;
    for (int32_t i = 0; i < optionCount; ++i) {
        uintptr_t optionAddress = 0, option = 0;
        int32_t optionFlag = -1;
        if (!indexed_address(optionVector, (size_t)i, sizeof(uintptr_t), &optionAddress) ||
            !read_memory((void *)optionAddress, &option, sizeof(option)) || !option ||
            !read_at((void *)option, 0x134, &optionFlag, sizeof(optionFlag)) || optionFlag != 0)
            return 0;
    }
    (void)imageBase;
    return 1;
}

AuthorityResult AuthorityValidateEventPayload(unsigned char *imageBase,
    void *world, void *command, uint64_t senderMachineId, int safetyOnly) {
    uintptr_t pendingVector = 0;
    int32_t pendingCount = -1, pendingCapacity = -1;
    int32_t commandId = 0, actor = -1, optionIndex = -1;
    int senderLeader = 0;
    void *pendingEvent = NULL, *pendingScope = NULL, *resolvedEvent = NULL;
    void *commandScope = NULL;
    if (!imageBase || !world || !command || !senderMachineId ||
        !read_at(command, 0x28, &commandId, sizeof(commandId)) ||
        !read_at(command, 0x34, &actor, sizeof(actor)) || actor <= 0 ||
        !read_at(command, 0xe8, &optionIndex, sizeof(optionIndex)) ||
        !country_valid(world, actor)) return malformed();
    commandScope = at_offset(command, 0x38);
    if (!commandScope || !read_memory(commandScope, &(u8[0xb0]){0}, 0xb0)) return malformed();
    void *reference = at_offset(command, 0x2c);
    u8 referenceBytes[8];
    if (!reference || !read_memory(reference, referenceBytes, sizeof(referenceBytes))) return malformed();
    /* Resolve and validate the reference and option bounds before native code
       can use the index or dereference the event. Pending-event and ownership
       checks wait for the ordered boundary, where host state is authoritative. */
    resolvedEvent = resolve_event(imageBase, reference);
    if (!resolvedEvent) return malformed();
    uintptr_t eventVtable = 0;
    int32_t optionCount = -1;
    if (!read_pointer(resolvedEvent, 0, &eventVtable) ||
        eventVtable != (uintptr_t)(imageBase + 0x2999be8) ||
        !read_at(resolvedEvent, 0x374, &optionCount, sizeof(optionCount)) ||
        optionCount < 1 || optionIndex < 0 || optionIndex >= optionCount) return malformed();
    if (safetyOnly) {
        size_t commandScopeSize = 0;
        if (!trusted_scope_expansion_size(world, commandScope, &commandScopeSize)) return malformed();
        return event_result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
    }

    if (!sender_controls_recipient(imageBase, world, senderMachineId, actor, &senderLeader))
        return event_result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    if (!read_at(world, 0x560, &pendingVector, sizeof(pendingVector)) ||
        !read_at(world, 0x568, &pendingCapacity, sizeof(pendingCapacity)) ||
        !read_at(world, 0x56c, &pendingCount, sizeof(pendingCount)) ||
        pendingCount < 0 || pendingCapacity < pendingCount ||
        (pendingCount && !pendingVector)) return malformed();

    unsigned matches = 0;
    for (int32_t i = 0; i < pendingCount; ++i) {
        uintptr_t entryAddress = 0;
        if (!indexed_address(pendingVector, (size_t)i, 0x38, &entryAddress)) return malformed();
        int32_t pendingId = 0;
        void *event = NULL, *scope = NULL;
        if (!read_at((void *)entryAddress, 0, &pendingId, sizeof(pendingId)) ||
            !read_at((void *)entryAddress, 8, &event, sizeof(event)) ||
            !read_at((void *)entryAddress, 0x10, &scope, sizeof(scope))) return malformed();
        if (pendingId != commandId) continue;
        ++matches;
        pendingEvent = event;
        pendingScope = scope;
    }
    if (matches != 1 || !pendingEvent || !pendingScope) return malformed();

    if (resolvedEvent != pendingEvent) return malformed();
    if (!senderLeader && !event_allows_nonleader(imageBase, pendingEvent, optionCount))
        return event_result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);

    int32_t recipient = -1;
    if (!event_scope_recipient(imageBase, world, pendingScope, &recipient) ||
        !event_countries_equal(imageBase, world, recipient, actor))
        return event_result(AUTHORITY_DECISION_DENY, AUTHORITY_REASON_ACTOR_NOT_CONTROLLED);
    if (!scope_graph_equal(imageBase, world, pendingScope, commandScope)) return malformed();
    return event_result(AUTHORITY_DECISION_ALLOW, AUTHORITY_REASON_NONE);
}
