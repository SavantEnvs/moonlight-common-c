#define _GNU_SOURCE
/* The RTSP client state machine (RtspConnection.c performRtspHandshake) against a hostile host.
 *
 * A loopback TCP server plays the host: it accepts one connection per request, ignores the request,
 * answers with the next canned reply and closes. This runs the real request builders, response parsing,
 * SDP/Transport/Session handling and the audio-ping start-up that RTSP SETUP triggers.
 *
 * Input: [config][serverCodecModeSupport bit set][audio configuration] [rtspSessionUrl, NUL-terminated] then up to 7 replies
 * (OPTIONS, DESCRIBE, SETUP audio, SETUP video, SETUP control, ANNOUNCE, PLAY) separated by NUL bytes.
 *   config bits 0-1 server version, 2 high bitrate (use the supplied session URL), 3 remote streaming,
 *   4 no session URL, 5-7 supported video format mask.
 *   audio byte bits 0-1 audio configuration, bit 2 the host seals each reply as a host-originated AES-GCM
 *   RTSP message with the session key (StreamConfig.remoteInputAesKey, all zero here), the way a host does
 *   for an rtspenc:// session; that reaches the library's decrypt of encrypted RTSP responses. */
#include "env.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_REPLIES 7

typedef struct {
    int listenFd;
    bool seal;
    const uint8_t* replies[MAX_REPLIES];
    size_t replyLen[MAX_REPLIES];
} FAKE_HOST;

/* Mirrors the wire format of RtspConnection.c: BE32 (0x80000000 | length), BE32 sequence, 16-byte tag, ciphertext. */
static uint8_t* sealReply(PPLT_CRYPTO_CONTEXT ctx, uint32_t seq, const uint8_t* plain, size_t plainLen, size_t* outLen) {
    uint8_t* out = (uint8_t*)calloc(1, 24 + plainLen + 1);
    uint8_t iv[12] = { 0 };
    int cipherLen = (int)plainLen;
    if (out == NULL) {
        abort();
    }
    iv[0] = (uint8_t)seq;
    iv[1] = (uint8_t)(seq >> 8);
    iv[2] = (uint8_t)(seq >> 16);
    iv[3] = (uint8_t)(seq >> 24);
    iv[10] = 'H';
    iv[11] = 'R';
    if (!PltEncryptMessage(ctx, ALGORITHM_AES_GCM, 0, (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                           iv, sizeof(iv), out + 8, 16, (unsigned char*)plain, (int)plainLen, out + 24, &cipherLen)) {
        abort();
    }
    uint32_t typeAndLen = 0x80000000u | (uint32_t)plainLen;
    for (int b = 0; b < 4; b++) {
        out[b] = (uint8_t)(typeAndLen >> (24 - 8 * b));
        out[4 + b] = (uint8_t)(seq >> (24 - 8 * b));
    }
    *outLen = 24 + plainLen;
    return out;
}

static void* fakeHostThread(void* arg) {
    FAKE_HOST* host = (FAKE_HOST*)arg;
    PPLT_CRYPTO_CONTEXT sealCtx = PltCreateCryptoContext(0);

    for (int i = 0;; i++) {
        int fd = accept(host->listenFd, NULL, NULL);
        if (fd < 0) {
            break;
        }

        /* Answer as soon as the request starts to arrive. Encrypted requests (rtspenc://) carry no blank
         * line to wait for; the drain loop below absorbs the rest of the request. */
        char req[4096];
        if (recv(fd, req, sizeof(req), 0) <= 0) {
            close(fd);
            continue;
        }

        /* Requests past the last canned reply get an empty answer */
        const uint8_t* reply = i < MAX_REPLIES ? host->replies[i] : NULL;
        size_t replyLen = i < MAX_REPLIES ? host->replyLen[i] : 0;
        uint8_t* sealed = NULL;
        if (host->seal && reply != NULL) {
            sealed = sealReply(sealCtx, (uint32_t)(i + 1), reply, replyLen, &replyLen);
            reply = sealed;
        }
        size_t off = 0;
        while (off < replyLen) {
            ssize_t n = send(fd, reply + off, replyLen - off, MSG_NOSIGNAL);
            if (n <= 0) {
                break;
            }
            off += (size_t)n;
        }
        free(sealed);

        /* The client reads until we close; let it finish sending (ANNOUNCE has a body) before the FIN. */
        shutdown(fd, SHUT_WR);
        char sink[1024];
        while (recv(fd, sink, sizeof(sink), 0) > 0) {
        }
        close(fd);
    }
    PltDestroyCryptoContext(sealCtx);
    return NULL;
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    mh_env_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const int kVersions[4][4] = { { 7, 1, 431, 0 }, { 7, 1, 431, -1 }, { 7, 1, 415, 0 }, { 7, 1, 404, 0 } };
    static const int kFormats[8] = { VIDEO_FORMAT_H264, VIDEO_FORMAT_H264 | VIDEO_FORMAT_H265, VIDEO_FORMAT_MASK_H264 | VIDEO_FORMAT_MASK_H265,
                                     VIDEO_FORMAT_MASK_AV1 | VIDEO_FORMAT_MASK_H265 | VIDEO_FORMAT_MASK_H264, VIDEO_FORMAT_MASK_YUV444 | VIDEO_FORMAT_H264,
                                     VIDEO_FORMAT_H265_MAIN10 | VIDEO_FORMAT_H265, VIDEO_FORMAT_AV1_MAIN8, 0xFFFF };

    static const int kScm[8] = { SCM_H264, SCM_HEVC, SCM_HEVC_MAIN10, SCM_AV1_MAIN8, SCM_AV1_MAIN10,
                                 SCM_H264_HIGH8_444, SCM_HEVC_REXT8_444, SCM_HEVC_REXT10_444 | SCM_AV1_HIGH10_444 };
    static const int kAudio[4] = { AUDIO_CONFIGURATION_STEREO, AUDIO_CONFIGURATION_51_SURROUND,
                                   AUDIO_CONFIGURATION_71_SURROUND, AUDIO_CONFIGURATION_STEREO };

    if (size < 3) {
        return 0;
    }
    uint8_t cfg = data[0];
    int codecModes = 0;
    for (int i = 0; i < 8; i++) {
        if (data[1] & (1 << i)) {
            codecModes |= kScm[i];
        }
    }
    int audioConfig = kAudio[data[2] & 3];
    int sealReplies = data[2] & 4;
    data += 3;
    size -= 3;

    /* rtspSessionUrl is a NUL-terminated string handed to the library as such */
    char* url = (char*)malloc(size + 1);
    size_t urlLen = 0;
    while (urlLen < size && data[urlLen] != '\0') {
        urlLen++;
    }
    memcpy(url, data, urlLen);
    url[urlLen] = '\0';
    data += urlLen < size ? urlLen + 1 : urlLen;
    size -= urlLen < size ? urlLen + 1 : urlLen;

    FAKE_HOST host;
    memset(&host, 0, sizeof(host));
    host.seal = (sealReplies != 0);
    for (int i = 0; i < MAX_REPLIES; i++) {
        size_t n = 0;
        while (n < size && data[n] != '\0') {
            n++;
        }
        host.replies[i] = data;
        host.replyLen[i] = n;
        data += n < size ? n + 1 : n;
        size -= n < size ? n + 1 : n;
    }

    host.listenFd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t addrLen = sizeof(addr);
    if (host.listenFd < 0 || bind(host.listenFd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
            listen(host.listenFd, 4) != 0 || getsockname(host.listenFd, (struct sockaddr*)&addr, &addrLen) != 0) {
        abort();
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, fakeHostThread, &host) != 0) {
        abort();
    }

    memset(&RemoteAddr, 0, sizeof(RemoteAddr));
    memcpy(&RemoteAddr, &addr, sizeof(addr));
    memset(&LocalAddr, 0, sizeof(LocalAddr));
    AddrLen = sizeof(addr);
    RtspPortNumber = ntohs(addr.sin_port);
    AudioPortNumber = VideoPortNumber = ControlPortNumber = 0;
    NegotiatedVideoFormat = 0;
    ReferenceFrameInvalidationSupported = false;
    memcpy(AppVersionQuad, kVersions[cfg & 3], sizeof(AppVersionQuad));

    memset(&StreamConfig, 0, sizeof(StreamConfig));
    StreamConfig.width = 1920;
    StreamConfig.height = 1080;
    StreamConfig.fps = 60;
    StreamConfig.bitrate = (cfg & 4) ? 50000 : 10000;
    StreamConfig.packetSize = 1392;
    StreamConfig.streamingRemotely = (cfg & 8) ? STREAM_CFG_REMOTE : STREAM_CFG_LOCAL;
    StreamConfig.audioConfiguration = audioConfig;
    StreamConfig.supportedVideoFormats = kFormats[cfg >> 5];

    initializeAudioStream();

    SERVER_INFORMATION serverInfo;
    LiInitializeServerInformation(&serverInfo);
    serverInfo.address = "127.0.0.1";
    serverInfo.serverInfoAppVersion = "7.1.431.0";
    serverInfo.rtspSessionUrl = (cfg & 16) ? NULL : url;
    serverInfo.serverCodecModeSupport = codecModes;

    performRtspHandshake(&serverInfo);

    /* Wake the fake host if the client gave up before using every reply */
    shutdown(host.listenFd, SHUT_RDWR);
    pthread_join(thread, NULL);
    close(host.listenFd);

    destroyAudioStream();
    free(url);
    return 0;
}
