/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "audio_transport_pause_status.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioTransportPauseStatus"

namespace OHOS {
namespace DistributedHardware {
AudioTransportPauseStatus::AudioTransportPauseStatus(std::shared_ptr<AudioTransportContext>& stateContext)
    : stateContext_(stateContext)
{
    DHLOGD("AudioTransportPauseStatus contruct.");
}

int32_t AudioTransportPauseStatus::Start(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)audioChannel;
    (void)processor;
    DHLOGE("Audiotransportstatus is pause, can not start.");
    return ERR_DH_AUDIO_TRANS_ILLEGAL_OPERATION;
}

int32_t AudioTransportPauseStatus::Stop(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)processor;
    DHLOGI("Audiotransport status is pause.");
    if (audioChannel == nullptr) {
        DHLOGE("audioChannel is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = audioChannel->CloseSession();
    if (ret != DH_SUCCESS) {
        DHLOGE("Close session failed, ret: %d.", ret);
        return ret;
    }
    std::shared_ptr<AudioTransportContext> stateContext = stateContext_.lock();
    if (stateContext == nullptr) {
        DHLOGE("AudioTransport start can not get context");
        return ERR_DH_AUDIO_NULLPTR;
    }
    stateContext->SetTransportStatus(TRANSPORT_STATE_STOP);
    return DH_SUCCESS;
}

int32_t AudioTransportPauseStatus::Pause(std::shared_ptr<IAudioProcessor> processor)
{
    (void)processor;
    DHLOGI("Audiotransport status is pasue.");
    return DH_SUCCESS;
}

int32_t AudioTransportPauseStatus::Restart(const AudioParam &localParam, const AudioParam &remoteParam,
    std::shared_ptr<IAudioProcessor> processor)
{
    DHLOGI("Restart.");
    if (processor == nullptr) {
        DHLOGE("processor is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto ret = processor->StartAudioProcessor();
    if (ret != DH_SUCCESS) {
        DHLOGE("Restart processor_ failed, ret: %d.", ret);
        return ret;
    }
    std::shared_ptr<AudioTransportContext> stateContext = stateContext_.lock();
    if (stateContext == nullptr) {
        DHLOGE("AudioTransport start can not get context");
        return ERR_DH_AUDIO_NULLPTR;
    }
    stateContext->SetTransportStatus(TRANSPORT_STATE_START);
    DHLOGI("Restart success.");
    return DH_SUCCESS;
}

TransportStateType AudioTransportPauseStatus::GetStateType()
{
    DHLOGI("Audiotransport get state stype.");
    return TRANSPORT_STATE_PAUSE;
}
} // namespace DistributedHardware
} // namespace OHOS
