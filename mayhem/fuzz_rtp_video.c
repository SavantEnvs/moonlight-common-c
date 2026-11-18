/* Video receive path: RtpVideoQueue.c (FEC reassembly) feeding VideoDepacketizer.c, driven the way
 * VideoReceiveThreadProc() drives it, with a decoder that walks every decode unit it is handed.
 *
 * ControlStream.c is #included so its file-static state (the RFI/IDR queues the depacketizer reports
 * into) can be initialised and torn down per input. Its symbols then come from this object; the
 * archive copy is not pulled in.
 *
 * Input: [config byte] then records of [u16 little-endian length][RTP datagram bytes].
 *   config bits 0-1 server version, 2-3 packet size, 4-5 negotiated codec, 6 RFI supported, 7 direct submit. */
#include "../src/ControlStream.c"
#include "env.h"
#include "RtpVideoQueue.h"
#include <stdint.h>

static const int kVersions[4][4] = { { 7, 1, 431, 0 }, { 7, 1, 431, -1 }, { 7, 1, 350, 0 }, { 5, 0, 0, 0 } };
static const int kPacketSizes[4] = { 1024, 1392, 512, 1456 };
static const int kFormats[4] = { VIDEO_FORMAT_H264, VIDEO_FORMAT_H265, VIDEO_FORMAT_AV1_MAIN8, VIDEO_FORMAT_H265_MAIN10 };

static volatile uint32_t g_sink;

static int submitDecodeUnit(PDECODE_UNIT du) {
    for (PLENTRY e = du->bufferList; e != NULL; e = e->next) {
        for (int i = 0; i < e->length; i++) {
            g_sink += (unsigned char)e->data[i];
        }
    }
    return DR_OK;
}

static void drainDecodeUnits(void) {
    VIDEO_FRAME_HANDLE handle;
    PDECODE_UNIT du;
    while (LiPollNextVideoFrame(&handle, &du)) {
        LiCompleteVideoFrame(handle, submitDecodeUnit(du));
    }
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    mh_env_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RTP_VIDEO_QUEUE queue;

    if (size < 1) {
        return 0;
    }
    uint8_t cfg = data[0];
    data++;
    size--;

    memcpy(AppVersionQuad, kVersions[cfg & 3], sizeof(AppVersionQuad));
    memset(&StreamConfig, 0, sizeof(StreamConfig));
    StreamConfig.packetSize = kPacketSizes[(cfg >> 2) & 3];
    NegotiatedVideoFormat = kFormats[(cfg >> 4) & 3];
    ReferenceFrameInvalidationSupported = (cfg >> 6) & 1;
    VideoCallbacks.capabilities = ((cfg >> 6) & 1 ? CAPABILITY_REFERENCE_FRAME_INVALIDATION_AVC | CAPABILITY_REFERENCE_FRAME_INVALIDATION_HEVC |
                                                    CAPABILITY_REFERENCE_FRAME_INVALIDATION_AV1 : 0) |
                                  ((cfg >> 7) & 1 ? CAPABILITY_DIRECT_SUBMIT : 0);
    VideoCallbacks.submitDecodeUnit = submitDecodeUnit;

    initializeControlStream();
    initializeVideoDepacketizer(StreamConfig.packetSize);
    RtpvInitializeQueue(&queue);

    const int decryptedSize = StreamConfig.packetSize + MAX_RTP_HEADER_SIZE;
    const int bufferSize = decryptedSize + (int)sizeof(RTPV_QUEUE_ENTRY);

    while (size >= 2) {
        size_t len = (size_t)data[0] | ((size_t)data[1] << 8);
        data += 2;
        size -= 2;
        if (len > size) {
            len = size;
        }

        /* The socket delivers at most decryptedSize bytes; VideoReceiveThreadProc() drops anything shorter
         * than an RTP header ("Runt packet"). */
        size_t recvLen = len > (size_t)decryptedSize ? (size_t)decryptedSize : len;
        if (recvLen >= sizeof(RTP_PACKET)) {
            char* buffer = (char*)calloc(1, bufferSize);
            memcpy(buffer, data, recvLen);

            PRTP_PACKET packet = (PRTP_PACKET)buffer;
            packet->sequenceNumber = BE16(packet->sequenceNumber);
            packet->timestamp = BE32(packet->timestamp);
            packet->ssrc = BE32(packet->ssrc);

            if (RtpvAddPacket(&queue, packet, (int)recvLen, (PRTPV_QUEUE_ENTRY)&buffer[decryptedSize]) != RTPF_RET_QUEUED) {
                free(buffer);
            }
            drainDecodeUnits();
        }

        data += len;
        size -= len;
    }

    RtpvCleanupQueue(&queue);
    stopVideoDepacketizer();
    destroyVideoDepacketizer();
    /* stopControlStream() / the async callback thread shut these queues down before destroyControlStream() */
    LbqSignalQueueShutdown(&referenceFrameControlQueue);
    LbqSignalQueueShutdown(&frameFecStatusQueue);
    LbqSignalQueueShutdown(&asyncCallbackQueue);
    stopping = true;
    destroyControlStream();
    stopping = false;
    return 0;
}
