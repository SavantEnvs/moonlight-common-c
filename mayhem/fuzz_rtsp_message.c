/* RTSP response/request parser (RtspParser.c): the bytes a host sends back on the RTSP connection. */
#include "Limelight-internal.h"
#include "Rtsp.h"
#include <stdint.h>

/* transactRtspMessageTcp() never hands parseRtspMessage() more than MAX_RTSP_RESPONSE_SIZE (1 MB). */
#define MAX_PARSE_SIZE (1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RTSP_MESSAGE msg;
    static const char* const names[] = { "CSeq", "Session", "Transport", "Content-length", "X-SS-Ping-Payload" };
    volatile size_t sink = 0;

    if (size > MAX_PARSE_SIZE) {
        size = MAX_PARSE_SIZE;
    }

    memset(&msg, 0, sizeof(msg));
    if (parseRtspMessage(&msg, (char*)data, (int)size) != RTSP_ERROR_SUCCESS) {
        return 0;
    }

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char* content = getOptionContent(msg.options, (char*)names[i]);
        if (content != NULL) {
            sink += strlen(content);
        }
    }
    if (msg.payload != NULL) {
        for (int i = 0; i < msg.payloadLength; i++) {
            sink += (unsigned char)msg.payload[i];
        }
    }

    freeMessage(&msg);
    return 0;
}
