/* Known-answer checks for the parts of the library the fuzz targets cover: RTSP parse/serialize and the
 * audio reorder/FEC queue. Built with the project's normal flags by build.sh; mayhem/test.sh runs it and
 * reads the `SELFTEST passed=N failed=M` line. */
#include "Limelight-internal.h"
#include "Rtsp.h"
#include "RtpAudioQueue.h"
#include <rs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_passed, g_failed;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (cond) {                                                                \
            g_passed++;                                                            \
        } else {                                                                   \
            g_failed++;                                                            \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                 \
        }                                                                          \
    } while (0)

static void testRtspParseResponse(void) {
    char text[] = "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: DEADBEEFCAFE;timeout = 90\r\nContent-length: 5\r\n\r\nhello";
    RTSP_MESSAGE msg;
    memset(&msg, 0, sizeof(msg));
    CHECK(parseRtspMessage(&msg, text, (int)strlen(text)) == RTSP_ERROR_SUCCESS);
    CHECK(msg.type == TYPE_RESPONSE);
    CHECK(msg.message.response.statusCode == 200);
    CHECK(msg.sequenceNumber == 3);
    CHECK(msg.protocol != NULL && strcmp(msg.protocol, "RTSP/1.0") == 0);
    char* session = getOptionContent(msg.options, "Session");
    CHECK(session != NULL && strcmp(session, "DEADBEEFCAFE;timeout = 90") == 0);
    CHECK(getOptionContent(msg.options, "No-Such-Option") == NULL);
    CHECK(msg.payloadLength == 5);
    CHECK(msg.payload != NULL && memcmp(msg.payload, "hello", 5) == 0);
    freeMessage(&msg);
}

static void testRtspParseRequest(void) {
    char text[] = "OPTIONS rtsp://10.0.0.1:48010 RTSP/1.0\r\nCSeq: 1\r\nX-GS-ClientVersion: 14\r\n\r\n";
    RTSP_MESSAGE msg;
    memset(&msg, 0, sizeof(msg));
    CHECK(parseRtspMessage(&msg, text, (int)strlen(text)) == RTSP_ERROR_SUCCESS);
    CHECK(msg.type == TYPE_REQUEST);
    CHECK(msg.message.request.command != NULL && strcmp(msg.message.request.command, "OPTIONS") == 0);
    CHECK(msg.message.request.target != NULL && strcmp(msg.message.request.target, "rtsp://10.0.0.1:48010") == 0);
    CHECK(msg.sequenceNumber == 1);
    char* version = getOptionContent(msg.options, "X-GS-ClientVersion");
    CHECK(version != NULL && strcmp(version, "14") == 0);
    CHECK(msg.payload == NULL);
    freeMessage(&msg);
}

static void testRtspParseMalformed(void) {
    RTSP_MESSAGE msg;
    memset(&msg, 0, sizeof(msg));
    CHECK(parseRtspMessage(&msg, "", 0) == RTSP_ERROR_MALFORMED);
    char noEol[] = "RTSP/1.0 200 OK";
    CHECK(parseRtspMessage(&msg, noEol, (int)strlen(noEol)) == RTSP_ERROR_MALFORMED);
}

static void testRtspSerialize(void) {
    RTSP_MESSAGE msg;
    OPTION_ITEM cseq = { 0 }, accept = { 0 };
    POPTION_ITEM options = NULL;
    int len = 0;

    cseq.option = "CSeq";
    cseq.content = "7";
    accept.option = "Accept";
    accept.content = "application/sdp";
    insertOption(&options, &cseq);
    insertOption(&options, &accept);

    createRtspRequest(&msg, NULL, 0, "DESCRIBE", "rtsp://h:1", "RTSP/1.0", 7, options, NULL, 0);
    char* out = serializeRtspMessage(&msg, &len);
    CHECK(out != NULL);
    if (out != NULL) {
        static const char expected[] = "DESCRIBE rtsp://h:1 RTSP/1.0\r\nCSeq: 7\r\nAccept: application/sdp\r\n\r\n";
        CHECK(len == (int)strlen(expected));
        CHECK(len == (int)strlen(expected) && memcmp(out, expected, len) == 0);

        RTSP_MESSAGE back;
        memset(&back, 0, sizeof(back));
        CHECK(parseRtspMessage(&back, out, len) == RTSP_ERROR_SUCCESS);
        CHECK(back.sequenceNumber == 7);
        CHECK(back.message.request.command != NULL && strcmp(back.message.request.command, "DESCRIBE") == 0);
        freeMessage(&back);
        free(out);
    }
}

#define PAYLOAD 64

static PRTP_PACKET makeDataPacket(uint16_t seq, const uint8_t* payload) {
    PRTP_PACKET p = calloc(1, sizeof(RTP_PACKET) + PAYLOAD);
    p->header = 0x80;
    p->packetType = 97;
    p->sequenceNumber = seq;
    p->timestamp = seq * 5;
    p->ssrc = 0x1234;
    memcpy(p + 1, payload, PAYLOAD);
    return p;
}

static void testAudioQueue(void) {
    RTP_AUDIO_QUEUE queue;
    uint8_t payload[12][PAYLOAD];
    AppVersionQuad[0] = 7; AppVersionQuad[1] = 1; AppVersionQuad[2] = 431; AppVersionQuad[3] = 0;
    AudioPacketDuration = 5;
    for (int i = 0; i < 12; i++) {
        for (int j = 0; j < PAYLOAD; j++) {
            payload[i][j] = (uint8_t)(i * 16 + j);
        }
    }

    RtpaInitializeQueue(&queue);

    /* Block 0 only synchronises the queue */
    PRTP_PACKET p = makeDataPacket(0, payload[0]);
    CHECK(RtpaAddPacket(&queue, p, sizeof(RTP_PACKET) + PAYLOAD) == 0);
    free(p);

    /* Block 1 (seq 4..7) is in order: handed straight back */
    for (int i = 4; i < 8; i++) {
        p = makeDataPacket(i, payload[i]);
        CHECK(RTPQ_HANDLE_NOW(RtpaAddPacket(&queue, p, sizeof(RTP_PACKET) + PAYLOAD)));
        free(p);
    }

    /* Block 2 (seq 8..11): 8 and 9 arrive, 10 is lost, 11 arrives, then one FEC shard recovers 10 */
    for (int i = 8; i < 10; i++) {
        p = makeDataPacket(i, payload[i]);
        CHECK(RTPQ_HANDLE_NOW(RtpaAddPacket(&queue, p, sizeof(RTP_PACKET) + PAYLOAD)));
        free(p);
    }
    p = makeDataPacket(11, payload[11]);
    CHECK(RtpaAddPacket(&queue, p, sizeof(RTP_PACKET) + PAYLOAD) == 0);
    free(p);

    reed_solomon* rs = reed_solomon_new(RTPA_DATA_SHARDS, RTPA_FEC_SHARDS);
    /* The queue swaps in the OpenFEC parity matrix that matches the host's audio FEC */
    static const unsigned char openfecParity[] = { 0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c };
    memcpy(rs->p, openfecParity, sizeof(openfecParity));
    uint8_t parity[RTPA_FEC_SHARDS][PAYLOAD];
    uint8_t* shards[RTPA_TOTAL_SHARDS] = { payload[8], payload[9], payload[10], payload[11], parity[0], parity[1] };
    CHECK(reed_solomon_encode(rs, shards, RTPA_TOTAL_SHARDS, PAYLOAD) == 0);
    reed_solomon_release(rs);

    size_t fecLen = sizeof(RTP_PACKET) + sizeof(AUDIO_FEC_HEADER) + PAYLOAD;
    PRTP_PACKET fec = calloc(1, fecLen);
    fec->header = 0x80;
    fec->packetType = 127;
    fec->sequenceNumber = 0;
    PAUDIO_FEC_HEADER fh = (PAUDIO_FEC_HEADER)(fec + 1);
    fh->fecShardIndex = 0;
    fh->payloadType = 97;
    fh->baseSequenceNumber = BE16(8);
    fh->baseTimestamp = BE32(8 * 5);
    fh->ssrc = BE32(0x1234);
    memcpy(fh + 1, parity[0], PAYLOAD);
    int status = RtpaAddPacket(&queue, fec, (uint16_t)fecLen);
    free(fec);
    CHECK(RTPQ_PACKET_READY(status));

    uint16_t outLen = 0;
    PRTP_PACKET out = RtpaGetQueuedPacket(&queue, 0, &outLen);
    CHECK(out != NULL);
    if (out != NULL) {
        CHECK(outLen == sizeof(RTP_PACKET) + PAYLOAD);
        CHECK(out->sequenceNumber == 10);
        CHECK(out->packetType == 97);
        CHECK(memcmp(out + 1, payload[10], PAYLOAD) == 0);
        free(out);
    }
    out = RtpaGetQueuedPacket(&queue, 0, &outLen);
    CHECK(out != NULL && out->sequenceNumber == 11 && memcmp(out + 1, payload[11], PAYLOAD) == 0);
    free(out);
    CHECK(RtpaGetQueuedPacket(&queue, 0, &outLen) == NULL);

    RtpaCleanupQueue(&queue);
}

int main(void) {
    testRtspParseResponse();
    testRtspParseRequest();
    testRtspParseMalformed();
    testRtspSerialize();
    testAudioQueue();
    printf("SELFTEST passed=%d failed=%d\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
