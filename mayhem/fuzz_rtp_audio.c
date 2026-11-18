/* Audio receive path: RtpAudioQueue.c (reorder + Reed-Solomon FEC via nanors), driven the way
 * AudioReceiveThreadProc() drives it.
 *
 * Input: [config byte] then records of [u16 little-endian length][RTP datagram bytes].
 *   config bit 0 selects a server new enough (>= 7.1.415) for the FEC-capable queue mode. */
#include "env.h"
#include "RtpAudioQueue.h"
#include <stdint.h>
#include <stdlib.h>

/* MAX_PACKET_SIZE in AudioStream.c: the receive buffer of each audio datagram. */
#define AUDIO_RECV_SIZE 1400
#define PACKET_HEADER_ROOM 16

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    mh_env_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RTP_AUDIO_QUEUE queue;
    static const int kVersions[2][4] = { { 7, 1, 431, 0 }, { 7, 1, 350, 0 } };

    if (size < 1) {
        return 0;
    }
    memcpy(AppVersionQuad, kVersions[data[0] & 1], sizeof(AppVersionQuad));
    data++;
    size--;

    RtpaInitializeQueue(&queue);

    while (size >= 2) {
        size_t len = (size_t)data[0] | ((size_t)data[1] << 8);
        data += 2;
        size -= 2;
        if (len > size) {
            len = size;
        }

        /* recv() delivers at most AUDIO_RECV_SIZE bytes; AudioReceiveThreadProc() drops anything shorter
         * than an RTP header ("Runt packet"). */
        size_t recvLen = len > AUDIO_RECV_SIZE ? AUDIO_RECV_SIZE : len;
        if (recvLen >= sizeof(RTP_PACKET)) {
            char* buffer = (char*)calloc(1, AUDIO_RECV_SIZE);
            memcpy(buffer, data, recvLen);

            PRTP_PACKET rtp = (PRTP_PACKET)buffer;
            rtp->sequenceNumber = BE16(rtp->sequenceNumber);
            rtp->timestamp = BE32(rtp->timestamp);
            rtp->ssrc = BE32(rtp->ssrc);

            int status = RtpaAddPacket(&queue, rtp, (uint16_t)recvLen);
            if (RTPQ_PACKET_READY(status)) {
                uint16_t outLen;
                PRTP_PACKET out;
                while ((out = RtpaGetQueuedPacket(&queue, PACKET_HEADER_ROOM, &outLen)) != NULL) {
                    volatile unsigned char sink = 0;
                    for (int i = 0; i < outLen; i++) {
                        sink += ((unsigned char*)out)[PACKET_HEADER_ROOM + i];
                    }
                    free(out);
                }
            }
            free(buffer);
        }

        data += len;
        size -= len;
    }

    RtpaCleanupQueue(&queue);
    return 0;
}
