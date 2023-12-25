 /*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "audio_data_channel.h"

#include <securec.h>

#include "daudio_hitrace.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDataChannel"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioDataChannel::CreateSession(const std::shared_ptr<IAudioChannelListener> &listener,
    const std::string &sessionName)
{
    DHLOGI("Create session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    DAUDIO_SYNC_TRACE(DAUDIO_CREATE_DATA_SESSION);

    channelListener_ = listener;
    sessionName_ = sessionName;
    DHLOGI("Create softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::ReleaseSession()
{
    DHLOGI("Release session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    DAUDIO_SYNC_TRACE(DAUDIO_RELEASE_DATA_SESSION);
    channelListener_.reset();

    DHLOGI("Release softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::OpenSession()
{
    DHLOGI("Open session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    DaudioStartAsyncTrace(DAUDIO_OPEN_DATA_SESSION, DAUDIO_OPEN_DATA_SESSION_TASKID);

    DHLOGI("Open audio session success, sessionId: %d.", sessionId_);
    return DH_SUCCESS;
}

int32_t AudioDataChannel::CloseSession()
{
    DHLOGI("Close session, sessionId: %d.", sessionId_);
    if (sessionId_ == 0) {
        DHLOGD("Session is already close.");
        return DH_SUCCESS;
    }

    DAUDIO_SYNC_TRACE(DAUDIO_CLOSE_DATA_SESSION);

    DHLOGI("Close audio session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::SendEvent(const AudioEvent &audioEvent)
{
    (void) audioEvent;
    return DH_SUCCESS;
}

int32_t AudioDataChannel::SendData(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGD("Send data, sessionId: %d.", sessionId_);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
