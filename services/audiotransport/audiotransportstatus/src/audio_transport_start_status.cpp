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

#include "audio_transport_start_status.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioTransportStartStatus"

namespace OHOS {
namespace DistributedHardware {
AudioTransportStartStatus::AudioTransportStartStatus(std::shared_ptr<AudioTransportContext>& stateContext)
    : stateContext_(stateContext)
{
    DHLOGD("AudioTransportStartStatus contruct.");
}
int32_t AudioTransportStartStatus::Start(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)audioChannel;
    (void)processor;
    DHLOGI("Audiotransport status is start.");
    return DH_SUCCESS;
}

int32_t AudioTransportStartStatus::Stop(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    DHLOGI("Audiotransport status is start.");
    if (processor == nullptr) {
        DHLOGE("processor is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = processor->StopAudioProcessor();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop audio processor failed, ret: %d.", ret);
        return ret;
    }
    if (audioChannel == nullptr) {
        DHLOGE("audioChannel is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    ret = audioChannel->CloseSession();
    if (ret != DH_SUCCESS) {
        DHLOGE("Close session failed, ret: %d.", ret);
        return ret;
    }
    std::shared_ptr<AudioTransportContext> stateContext = stateContext_.lock();
    if (stateContext == nullptr) {
        DHLOGE("AudioTransport start can not get context");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    stateContext->SetTransportStatus(TRANSPORT_STATE_STOP);
    return DH_SUCCESS;
}

int32_t AudioTransportStartStatus::Pause(std::shared_ptr<IAudioProcessor> processor)
{
    DHLOGI("Audiotransport status is start.");
    if (processor == nullptr) {
        DHLOGE("Processor_ is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    int32_t ret = processor->StopAudioProcessor();
    if (ret != DH_SUCCESS) {
        DHLOGE("Pause processor failed, ret: %d.", ret);
        return ret;
    }
    ret = processor->ReleaseAudioProcessor();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release audio processor failed, ret: %d.", ret);
        return ret;
    }
    std::shared_ptr<AudioTransportContext> stateContext = stateContext_.lock();
    if (stateContext == nullptr) {
        DHLOGE("AudioTransport start can not get context");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    stateContext->SetTransportStatus(TRANSPORT_STATE_PAUSE);
    DHLOGI("Pause success.");
    return DH_SUCCESS;
}

int32_t AudioTransportStartStatus::Restart(const AudioParam &localParam, const AudioParam &remoteParam,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)localParam;
    (void)remoteParam;
    (void)processor;
    DHLOGE("Audiotransport status is start.");
    return DH_SUCCESS;
}

TransportStateType AudioTransportStartStatus::GetStateType()
{
    DHLOGD("Get audiotransport status.");
    return TRANSPORT_STATE_START;
}
} // namespace DistributedHardware
} // namespace OHOS
