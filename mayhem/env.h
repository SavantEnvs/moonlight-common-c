/* Shared set-up for the in-process harnesses: the process-wide state that LiStartConnection() would
 * establish (placeholder callbacks, platform init). Per-input state is reset by each harness. */
#pragma once
#include "Limelight-internal.h"
#include "Platform.h"
#include <string.h>

static void mh_env_init(void) {
    PDECODER_RENDERER_CALLBACKS dr = NULL;
    PAUDIO_RENDERER_CALLBACKS ar = NULL;
    PCONNECTION_LISTENER_CALLBACKS cl = NULL;

    fixupMissingCallbacks(&dr, &ar, &cl);
    memcpy(&VideoCallbacks, dr, sizeof(VideoCallbacks));
    memcpy(&AudioCallbacks, ar, sizeof(AudioCallbacks));
    memcpy(&ListenerCallbacks, cl, sizeof(ListenerCallbacks));
    ListenerCallbacks.logMessage = NULL;
    initializePlatform();
}
