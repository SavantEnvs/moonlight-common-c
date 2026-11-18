#define _GNU_SOURCE
/* STUN binding-response parsing (SimpleStun.c LiFindExternalAddressIP4 / validateStunResponse) against a
 * hostile STUN server.
 *
 * SimpleStun.c is #included and run as is: it resolves 127.0.0.1, binds its UDP socket, sends its binding
 * request and reads the reply with recvUdpSocket(). A loopback UDP socket owned by the harness plays the
 * server. Two stand-ins keep the exchange deterministic without touching the library's logic:
 *   - sendto() is wrapped so that, once the request has gone out, the server reads it (it is already queued
 *     on loopback) and answers with the fuzzed bytes. The client's port is only known from that request.
 *   - getaddrinfo() is wrapped to drop AI_ADDRCONFIG: the library sets it, and on a host with no non-loopback
 *     interface (the Mayhem sandbox) glibc then fails to resolve even the literal 127.0.0.1, so no input got
 *     past name resolution (14 edges). The flag only filters the answer by the machine's interfaces.
 *   - PltGenerateRandomData() returns a fixed transaction ID, so seeds can carry the one a valid reply
 *     must echo. Any other ID is still rejected by the library's own check.
 * The reply is sent several times: the library re-reads every UDP_RECV_POLL_TIMEOUT_MS until it has a
 * valid reply or its retry window ends, and waits for data that is not there; having the copies queued
 * lets an invalid reply run through that loop at once instead of sitting in it.
 *
 * Input: [config byte][reply datagram bytes]. config bit 0: the reply comes from a second socket (a
 * different source port than the server the library asked), which the library has to reject. */
#include "env.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define REPLY_COPIES 32

static int g_serverFd = -1;
static int g_otherFd = -1;
static struct sockaddr_in g_serverAddr;
static const uint8_t* g_reply;
static size_t g_replyLen;
static int g_replyFd;
static volatile uint32_t g_sink;

static void mhFixedRandom(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] = (unsigned char)(0xA0 + i);
    }
}

static int bindLoopback(struct sockaddr_in* addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t len = sizeof(*addr);
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr*)addr, sizeof(*addr)) != 0 || getsockname(fd, (struct sockaddr*)addr, &len) != 0) {
        abort();
    }
    return fd;
}

static void drain(int fd) {
    char sink[2048];
    while (recv(fd, sink, sizeof(sink), MSG_DONTWAIT) >= 0) {
    }
}

static ssize_t mhSendTo(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dst, socklen_t dstLen) {
    ssize_t n = sendto(fd, buf, len, flags, dst, dstLen);
    if (n < 0) {
        return n;
    }

    char request[64];
    struct sockaddr_in client;
    socklen_t clientLen = sizeof(client);
    if (recvfrom(g_serverFd, request, sizeof(request), 0, (struct sockaddr*)&client, &clientLen) < 0) {
        abort();
    }
    for (int i = 0; i < REPLY_COPIES; i++) {
        sendto(g_replyFd, g_reply, g_replyLen, 0, (struct sockaddr*)&client, clientLen);
    }
    return n;
}

static int mhGetAddrInfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    struct addrinfo h = *hints;
    h.ai_flags &= ~AI_ADDRCONFIG;
    return getaddrinfo(node, service, &h, res);
}

#define sendto mhSendTo
#define getaddrinfo mhGetAddrInfo
#define PltGenerateRandomData mhFixedRandom
#include "../src/SimpleStun.c"
#undef sendto
#undef getaddrinfo
#undef PltGenerateRandomData

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    mh_env_init();
    g_serverFd = bindLoopback(&g_serverAddr);
    struct sockaddr_in other;
    g_otherFd = bindLoopback(&other);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return -1;
    }
    g_replyFd = (data[0] & 1) ? g_otherFd : g_serverFd;
    g_reply = data + 1;
    g_replyLen = size - 1;
    drain(g_serverFd);

    unsigned int wanAddr = 0;
    int err = LiFindExternalAddressIP4("127.0.0.1", ntohs(g_serverAddr.sin_port), &wanAddr);
    g_sink += (uint32_t)err + wanAddr;
    return 0;
}
