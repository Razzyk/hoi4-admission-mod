#include "../native/protocol.h"
int main(void) {
    unsigned char secret[32];
    memset(secret, 0xaa, sizeof(secret));
    char result[65];
    if (!hmac_message(secret, "HOI4-admission-protocol-1", result)) return 1;
    puts(result);
    return 0;
}
