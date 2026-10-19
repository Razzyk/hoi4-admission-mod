#define LOBBY_GUARD_TEST 1
#include "../native/lobby_guard.c"

static unsigned assertions, cases, sends, receives, proxy_receives, denials;
static volatile LONG verified = 1;
static int client_marker, host_marker;
static unsigned char sent[PEER_MAX_PACKET], delivered[PEER_MAX_PACKET];
static uint32_t sent_size, delivered_size;
static uintptr_t last_connection;
static char last_event[256];
static const char *case_name;
#define CHECK(c) do { ++assertions; if (!(c)) { fprintf(stderr,"FAIL %s line %d: %s\n",case_name,__LINE__,#c); exit(1); } } while(0)
static void send_stub(void *s, const void *p, uint32_t n, uintptr_t c) {
    (void)s; ++sends; sent_size = n; last_connection = c;
    CHECK(n <= sizeof(sent)); if (p && n) memcpy(sent,p,n);
}
static void receive_stub(void *s, const void *p, uint32_t n, uintptr_t c, int channel) {
    CHECK(s == &host_marker); CHECK(channel == 1 || channel == 0);
    ++receives; delivered_size = n; last_connection = c;
    CHECK(n <= sizeof(delivered)); if (p && n) memcpy(delivered,p,n);
}
static void proxy_stub(void *s, const void *p, uint32_t n, uintptr_t c, int channel) {
    (void)p; (void)n; (void)c; (void)channel; CHECK(s == &client_marker); ++proxy_receives;
}
static void deny_stub(void *s, int type, uintptr_t c) {
    CHECK(s == &host_marker); CHECK(type == 33 || type == 11 || type == 16); CHECK(c == 101 || c == 999);
    ++denials;
}
static void logger(const char *s) { CHECK(strlen(s) < sizeof(last_event)); strcpy(last_event,s); }
static void begin(const char *name) {
    static int initialized;
    if (initialized) { PeerHostDestroy(&peer_host); PeerClientDestroy(&peer_client); }
    unsigned char dll[32], manifest[32]; memset(dll,0x31,sizeof(dll)); memset(manifest,0x72,sizeof(manifest));
    PeerClientInit(&peer_client,dll,manifest); PeerHostInit(&peer_host,dll,manifest); initialized=1;
    case_name=name; ++cases; verified=1; stopped=0; client_eligible=&verified;
    sends=receives=proxy_receives=denials=0; rejected=accepted=decorated=0;
    original_receive=receive_stub; original_client_receive=proxy_stub; original_send=send_stub;
    native_deny=deny_stub; guard_log=logger; last_event[0]=0;
}
static void join_packet(unsigned char p[24], uint32_t type) {
    memset(p,0,24); memcpy(p,&type,4); memcpy(p+8,"player-wire-data",16);
}
static void offer_to_challenge(uint32_t type) {
    unsigned char p[24]; join_packet(p,type);
    guarded_send(&client_marker,p,sizeof(p),0);
    CHECK(sends==1 && sent_size==sizeof(p)+PEER_OFFER_BYTES && receives==0);
    unsigned char offer[24+PEER_OFFER_BYTES]; memcpy(offer,sent,sizeof(offer));
    guarded_receive(&host_marker,offer,sizeof(offer),101,1);
    CHECK(sends==2 && sent_size==PEER_MESSAGE_BYTES && receives==0 && denials==0);
    CHECK(last_connection==101 && get32(sent)==PEER_MESSAGE_CHALLENGE);
}
static void answer(int server_role) {
    unsigned char challenge[PEER_MESSAGE_BYTES]; memcpy(challenge,sent,sizeof(challenge));
    if (server_role) guarded_receive(&client_marker,challenge,sizeof(challenge),202,1);
    else guarded_client_receive(&client_marker,challenge,sizeof(challenge),202,1);
    CHECK(sends==3 && sent_size==PEER_MESSAGE_BYTES && get32(sent)==PEER_MESSAGE_RESPONSE);
    CHECK(last_connection==202 && proxy_receives==0);
}
int main(void) {
    for (unsigned i=0;i<3;++i) {
        const uint32_t types[3]={8,9,14}; unsigned char original[24]; join_packet(original,types[i]);
        begin("deferred admission after exact build peer round trip"); offer_to_challenge(types[i]); answer(i==2);
        unsigned char response[PEER_MESSAGE_BYTES]; memcpy(response,sent,sizeof(response));
        guarded_receive(&host_marker,response,sizeof(response),101,1);
        CHECK(receives==1 && accepted==1 && decorated==1 && denials==0);
        CHECK(delivered_size==24 && !memcmp(delivered,original,24));
        CHECK(strstr(last_event,"PEER_HANDSHAKE_VERIFIED")!=NULL);
        guarded_receive(&host_marker,response,sizeof(response),101,1);
        CHECK(receives==1 && denials==0 && accepted==1);
    }
    begin("plain clients are refused before original callback");
    unsigned char p[24]; join_packet(p,8); guarded_receive(&host_marker,p,sizeof(p),101,1);
    CHECK(denials==1 && receives==0 && strstr(last_event,"MATCHING_ADMISSION_MOD_REQUIRED"));
    begin("unverified client cannot send join"); verified=0; guarded_send(&client_marker,p,sizeof(p),0);
    CHECK(sends==0 && strstr(last_event,"LOCAL_CLIENT_NOT_VERIFIED"));
    begin("unverified host cannot challenge"); guarded_send(&client_marker,p,sizeof(p),0);
    unsigned char offer[24+PEER_OFFER_BYTES]; memcpy(offer,sent,sizeof(offer)); verified=0;
    guarded_receive(&host_marker,offer,sizeof(offer),101,1); CHECK(receives==0 && denials==1 && sends==1);
    begin("lease lost during handshake prevents response"); offer_to_challenge(8); verified=0;
    unsigned char msg[PEER_MESSAGE_BYTES]; memcpy(msg,sent,sizeof(msg));
    guarded_client_receive(&client_marker,msg,sizeof(msg),202,1); CHECK(sends==2 && receives==0 && proxy_receives==0);
    begin("host lease lost before response prevents admission"); offer_to_challenge(8); answer(0);
    memcpy(msg,sent,sizeof(msg)); verified=0; guarded_receive(&host_marker,msg,sizeof(msg),101,1);
    CHECK(receives==0 && accepted==0);
    begin("changed response refuses and consumes pending request"); offer_to_challenge(8); answer(0);
    memcpy(msg,sent,sizeof(msg)); msg[PEER_MESSAGE_BYTES-1]^=1;
    guarded_receive(&host_marker,msg,sizeof(msg),101,1); CHECK(receives==0 && denials==0);
    memcpy(msg,sent,sizeof(msg)); guarded_receive(&host_marker,msg,sizeof(msg),101,1);
    CHECK(receives==0 && denials==0);
    begin("cross connection response cannot admit"); offer_to_challenge(8); answer(0);
    memcpy(msg,sent,sizeof(msg)); guarded_receive(&host_marker,msg,sizeof(msg),999,1);
    CHECK(receives==0 && denials==0);
    begin("changed release cannot challenge"); guarded_send(&client_marker,p,sizeof(p),0);
    memcpy(offer,sent,sizeof(offer)); offer[sizeof(offer)-1]^=1;
    guarded_receive(&host_marker,offer,sizeof(offer),101,1); CHECK(receives==0 && denials==1 && sends==1);
    begin("ordinary traffic passes unchanged"); join_packet(p,17);
    guarded_send(&client_marker,p,sizeof(p),202); CHECK(sends==1 && sent_size==24 && !memcmp(p,sent,24));
    guarded_receive(&host_marker,p,sizeof(p),101,1); CHECK(receives==1 && delivered_size==24);
    guarded_client_receive(&client_marker,p,sizeof(p),202,1); CHECK(proxy_receives==1);
    begin("other channels do not enter peer control"); join_packet(p,8);
    guarded_receive(&host_marker,p,sizeof(p),101,0); CHECK(receives==1 && denials==0);
    uint32_t kind=PEER_MESSAGE_CHALLENGE; memcpy(p,&kind,4);
    guarded_client_receive(&client_marker,p,sizeof(p),202,0); CHECK(proxy_receives==1);
    begin("malformed extension frames never reach game parser");
    guarded_receive(&host_marker,p,4,101,1); guarded_client_receive(&client_marker,p,4,202,1);
    CHECK(receives==0 && proxy_receives==0 && sends==0);
    begin("stop leaves host refusing new joins"); LobbyGuardStop(); join_packet(p,8);
    guarded_receive(&host_marker,p,sizeof(p),101,1); CHECK(receives==0 && denials==1);
    guarded_send(&client_marker,p,sizeof(p),0); CHECK(sends==0);
    PeerHostDestroy(&peer_host); PeerClientDestroy(&peer_client);
    printf("PASS %u peer lobby wrapper cases, %u assertions\n",cases,assertions);
    return 0;
}
