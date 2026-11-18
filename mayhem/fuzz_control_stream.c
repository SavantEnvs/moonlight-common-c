#define _GNU_SOURCE
/* The control-stream receive path (ControlStream.c controlReceiveThreadFunc) against a hostile host.
 *
 * ControlStream.c is #included so its file-static state can be set up the way startControlStream()
 * does, then the real receive thread and the real async-callback thread run over a real ENet
 * connection to a loopback ENet server owned by the harness. The server sends the fuzzed control
 * packets as reliable ENet packets; nothing about ENet or the thread bodies is replaced.
 *
 * Encrypted control streams (7.1.431+) only accept AES-GCM sealed packets, so a record can ask the
 * harness to seal its bytes with the session key it also gives the library (StreamConfig.remoteInputAesKey),
 * which is what a legitimate host that sends hostile plaintext would do. That reaches
 * decryptControlMessageToV1() / decryptJumboControlMessageToV1() and everything behind them.
 *
 * Input: [config byte] then records of [flags byte][u16 little-endian length][packet bytes].
 *   config bits 0-1 server version (7.1.350, Sunshine 7.1.430, 7.1.431, Sunshine 7.1.431),
 *          bit 2 SS_ENC_CONTROL_V2 (12-byte IV, replay window) instead of Nvidia's 16-byte IV.
 *   flags bits 0-5 ENet channel (mod CTRL_CHANNEL_COUNT), bits 6-7 how the bytes are sent:
 *          0 as they are, 1 sealed as a V2 encrypted packet, 2 sealed as a jumbo encrypted packet,
 *          3 sealed as a V2 packet and sent twice (a replay). On a stream that is not encrypted
 *          every record is sent as it is. */
#include "../src/ControlStream.c"
#include "env.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

static const int kVersions[4][4] = { { 7, 1, 350, 0 }, { 7, 1, 430, -1 }, { 7, 1, 431, 0 }, { 7, 1, 431, -1 } };
static const unsigned char kKey[16] = { 0x6d, 0x6f, 0x6f, 0x6e, 0x6c, 0x69, 0x67, 0x68, 0x74, 0x2d, 0x66, 0x75, 0x7a, 0x7a, 0x21, 0x00 };

static atomic_bool g_recvDone;
static unsigned int g_seq[CTRL_CHANNEL_COUNT];
static PPLT_CRYPTO_CONTEXT g_sealCtx;
static volatile uint32_t g_sink;

static void receiveThreadMain(void* context) {
    controlReceiveThreadFunc(context);
    atomic_store(&g_recvDone, true);
}

static void put16(unsigned char* p, unsigned int v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
}

static void put32(unsigned char* p, unsigned int v) {
    put16(p, v);
    put16(p + 2, v >> 16);
}

/* A host that holds the session key seals plaintext the way encryptControlMessage() does for the
 * client-to-host direction, with the host-to-client IV. Returns a malloc()ed ENet packet body. */
static unsigned char* sealPacket(bool jumbo, uint8_t channel, const uint8_t* plain, size_t plainLen, size_t* outLen) {
    const size_t hdrLen = jumbo ? sizeof(NVCTL_ENCRYPTED_PACKET_HEADER_JUMBO) : sizeof(NVCTL_ENCRYPTED_PACKET_HEADER);
    const size_t maxPlain = jumbo ? (1u << 20) : (0xFFFFu - sizeof(unsigned int) - AES_GCM_TAG_LENGTH);
    if (plainLen > maxPlain) {
        plainLen = maxPlain;
    }

    unsigned int seq = g_seq[channel];
    unsigned char iv[16] = { 0 };
    int ivSize, cipherFlags;
    populateIncomingIv(seq, iv, &ivSize, &cipherFlags);

    unsigned char* out = (unsigned char*)calloc(1, hdrLen + AES_GCM_TAG_LENGTH + plainLen + 1);
    int cipherLen = (int)plainLen;
    if (out == NULL || !PltEncryptMessage(g_sealCtx, ALGORITHM_AES_GCM, 0, (unsigned char*)kKey, sizeof(kKey), iv, ivSize,
                                          out + hdrLen, AES_GCM_TAG_LENGTH, (unsigned char*)plain, (int)plainLen,
                                          out + hdrLen + AES_GCM_TAG_LENGTH, &cipherLen)) {
        abort();
    }

    const unsigned int length = (unsigned int)(sizeof(unsigned int) + AES_GCM_TAG_LENGTH + plainLen);
    if (jumbo) {
        put16(out, 0x0002);
        put32(out + 2, length);
        put32(out + 6, seq);
    }
    else {
        put16(out, 0x0001);
        put16(out + 2, length);
        put32(out + 4, seq);
    }
    *outLen = hdrLen + AES_GCM_TAG_LENGTH + plainLen;
    return out;
}

static void sendReliable(ENetPeer* serverPeer, uint8_t channel, const void* data, size_t len) {
    /* After a termination message the client drops the connection; there is nobody left to send to. */
    if (serverPeer->state != ENET_PEER_STATE_CONNECTED) {
        return;
    }
    ENetPacket* pkt = enet_packet_create(data, len, ENET_PACKET_FLAG_RELIABLE);
    if (pkt == NULL || enet_peer_send(serverPeer, channel, pkt) != 0) {
        abort();
    }
}

static void discardEvent(ENetEvent* ev) {
    if (ev->type == ENET_EVENT_TYPE_RECEIVE) {
        enet_packet_destroy(ev->packet);
    }
}

static bool clientIdle(void) {
    PltLockMutex(&enetMutex);
    bool idle = enet_list_empty(&client->dispatchQueue) && enet_list_empty(&peer->dispatchedCommands);
    PltUnlockMutex(&enetMutex);
    return idle;
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    mh_env_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return -1;
    }
    const uint8_t cfg = data[0];
    data++;
    size--;

    memcpy(AppVersionQuad, kVersions[cfg & 3], sizeof(AppVersionQuad));
    memset(&StreamConfig, 0, sizeof(StreamConfig));
    memcpy(StreamConfig.remoteInputAesKey, kKey, sizeof(kKey));
    EncryptionFeaturesEnabled = (cfg & 4) ? SS_ENC_CONTROL_V2 : 0;
    ConnectionInterrupted = false;
    atomic_store(&g_recvDone, false);
    memset(g_seq, 0, sizeof(g_seq));

    initializeControlStream();
    g_sealCtx = PltCreateCryptoContext(0);

    /* Loopback ENet server, and the client connected the way startControlStream() connects it. */
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ENetAddress serverAddress;
    enet_address_set_address(&serverAddress, (struct sockaddr*)&sin, sizeof(sin));
    enet_address_set_port(&serverAddress, 0);
    ENetHost* server = enet_host_create(AF_INET, &serverAddress, 1, CTRL_CHANNEL_COUNT, 0, 0);
    if (server == NULL || enet_socket_get_address(server->socket, &serverAddress) != 0) {
        abort();
    }

    client = enet_host_create(AF_INET, NULL, 1, CTRL_CHANNEL_COUNT, 0, 0);
    if (client == NULL) {
        abort();
    }
    client->intercept = ignoreDisconnectIntercept;
    peer = enet_host_connect(client, &serverAddress, CTRL_CHANNEL_COUNT, 0);
    if (peer == NULL) {
        abort();
    }

    ENetPeer* serverPeer = NULL;
    bool clientConnected = false;
    while (!clientConnected || serverPeer == NULL) {
        ENetEvent ev;
        int s = enet_host_service(server, &ev, 1);
        if (s > 0 && ev.type == ENET_EVENT_TYPE_CONNECT) {
            serverPeer = ev.peer;
        }
        else if (s < 0 || (s > 0 && ev.type != ENET_EVENT_TYPE_NONE)) {
            abort();
        }
        s = enet_host_service(client, &ev, 1);
        if (s > 0 && ev.type == ENET_EVENT_TYPE_CONNECT) {
            clientConnected = true;
        }
        else if (s < 0 || (s > 0 && ev.type != ENET_EVENT_TYPE_NONE)) {
            abort();
        }
    }
    enet_host_flush(client);

    if (PltCreateThread("CtrlAsyncCb", asyncCallbackThreadFunc, NULL, &asyncCallbackThread) != 0 ||
            PltCreateThread("ControlRecv", receiveThreadMain, NULL, &controlReceiveThread) != 0) {
        abort();
    }

    const bool encrypted = encryptedControlStream;
    while (size >= 3 && !atomic_load(&g_recvDone)) {
        const uint8_t flags = data[0];
        size_t len = (size_t)data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (len > size) {
            len = size;
        }

        const uint8_t channel = (uint8_t)((flags & 0x3f) % CTRL_CHANNEL_COUNT);
        const int mode = encrypted ? flags >> 6 : 0;
        if (mode == 0) {
            sendReliable(serverPeer, channel, data, len);
        }
        else {
            size_t sealedLen;
            unsigned char* sealed = sealPacket(mode == 2, channel, data, len, &sealedLen);
            sendReliable(serverPeer, channel, sealed, sealedLen);
            if (mode == 3) {
                sendReliable(serverPeer, channel, sealed, sealedLen);
            }
            free(sealed);
            g_seq[channel]++;
        }
        data += len;
        size -= len;

        /* Let the client drain what is in flight now; the window for reliable data is small. */
        ENetEvent ev;
        if (enet_host_service(server, &ev, 0) < 0) {
            abort();
        }
        discardEvent(&ev);
    }

    /* Everything sent has been acknowledged and handed to the receive thread, or the thread has ended. */
    for (;;) {
        ENetEvent ev;
        if (enet_host_service(server, &ev, 1) < 0) {
            abort();
        }
        discardEvent(&ev);
        if (atomic_load(&g_recvDone)) {
            break;
        }
        if (enet_list_empty(&serverPeer->sentReliableCommands) && enet_list_empty(&serverPeer->outgoingSendReliableCommands) &&
                enet_list_empty(&serverPeer->outgoingCommands) && clientIdle()) {
            break;
        }
    }

    /* Shut down in stopControlStream() order. The runt packet wakes the receive thread's socket wait. */
    stopping = true;
    LbqSignalQueueShutdown(&referenceFrameControlQueue);
    LbqSignalQueueShutdown(&frameFecStatusQueue);
    LbqSignalQueueDrain(&asyncCallbackQueue);
    PltInterruptThread(&controlReceiveThread);
    PltInterruptThread(&asyncCallbackThread);
    if (!atomic_load(&g_recvDone)) {
        const unsigned char kick = 0;
        ENetEvent ev;
        sendReliable(serverPeer, 0, &kick, sizeof(kick));
        enet_host_service(server, &ev, 0);
        discardEvent(&ev);
    }
    PltJoinThread(&controlReceiveThread);
    PltJoinThread(&asyncCallbackThread);

    g_sink += (uint32_t)hdrMetadata.maxDisplayLuminance + (uint32_t)atomic_load(&hdrEnabled);
    peer = NULL;
    enet_host_destroy(client);
    client = NULL;
    enet_host_destroy(server);
    PltDestroyCryptoContext(g_sealCtx);
    destroyControlStream();
    stopping = false;
    return 0;
}
