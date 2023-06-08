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

#include "audio_transport_context.h"
#include "audio_transport_status_factory.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioTransportContext"

namespace OHOS {
namespace DistributedHardware {
void AudioTransportContext::SetTransportStatus(TransportStateType stateType)
{
    DHLOGD("Set transport status in state %d", stateType);
    auto stateContext = std::shared_ptr<AudioTransportContext>(shared_from_this());
    currentState_ = AudioTransportStatusFactory::GetInstance().CreateState(stateType, stateContext);
}

int32_t AudioTransportContext::GetTransportStatusType()
{
    if (currentState_ == nullptr) {
        DHLOGI("CurrentState is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DHLOGI("Get transport status in state %d", currentState_->GetStateType());
    return currentState_->GetStateType();
}

int32_t AudioTransportContext::Start()
{
    if (currentState_ == nullptr) {
        DHLOGD("CurrentState is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DHLOGI("Audio transport context start.");
    return currentState_->Start(audioChannel_, processor_);
}

int32_t AudioTransportContext::Stop()
{
    if (currentState_ == nullptr) {
        DHLOGD("CurrentState is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DHLOGI("Audio transport context stop.");
    return currentState_->Stop(audioChannel_, processor_);
}

int32_t AudioTransportContext::Pause()
{
    if (currentState_ == nullptr) {
        DHLOGD("CurrentState is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DHLOGI("Audio transport context pause.");
    return currentState_->Pause(processor_);
}

int32_t AudioTransportContext::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    if (currentState_ == nullptr) {
        DHLOGD("CurrentState is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DHLOGI("Audio transport context restart.");
    return currentState_->Restart(localParam, remoteParam, processor_);
}

void AudioTransportContext::SetAudioChannel(std::shared_ptr<IAudioChannel> &audioChannel)
{
    audioChannel_ = audioChannel;
}

void AudioTransportContext::SetAudioProcessor(std::shared_ptr<IAudioProcessor> &processor)
{
    processor_ = processor;
}
} // namespace DistributedHardware
} // namespace OHOS
