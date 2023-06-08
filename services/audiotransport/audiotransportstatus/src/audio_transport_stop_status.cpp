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

#include "audio_transport_stop_status.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioTransportStopStatus"

namespace OHOS {
namespace DistributedHardware {
AudioTransportStopStatus::AudioTransportStopStatus(std::shared_ptr<AudioTransportContext>& stateContext)
    : stateContext_(stateContext)
{
    DHLOGD("AudioTransportStopStatus contruct.");
}
int32_t AudioTransportStopStatus::Start(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)audioChannel;
    if (processor == nullptr) {
        DHLOGE("Processor is null, setup first.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = processor->StartAudioProcessor();
    if (ret != DH_SUCCESS) {
        DHLOGE("Open audio processor failed ret: %d.", ret);
        processor = nullptr;
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::shared_ptr<AudioTransportContext> stateContext = stateContext_.lock();
    if (stateContext == nullptr) {
        DHLOGE("AudioTransport start can not get context");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    stateContext->SetTransportStatus(TRANSPORT_STATE_START);
    DHLOGI("Start success.");
    return DH_SUCCESS;
}

int32_t AudioTransportStopStatus::Stop(std::shared_ptr<IAudioChannel> audioChannel,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)audioChannel;
    (void)processor;
    DHLOGE("Audiotransportstatus status is stop.");
    return DH_SUCCESS;
}

int32_t AudioTransportStopStatus::Pause(std::shared_ptr<IAudioProcessor> processor)
{
    (void)processor;
    DHLOGE("Audiotransport status is stop, can not pause.");
    return ERR_DH_AUDIO_TRANS_ILLEGAL_OPERATION;
}

int32_t AudioTransportStopStatus::Restart(const AudioParam &localParam, const AudioParam &remoteParam,
    std::shared_ptr<IAudioProcessor> processor)
{
    (void)localParam;
    (void)remoteParam;
    (void)processor;
    DHLOGE("Audiotransport status status is stop, can not restart.");
    return ERR_DH_AUDIO_TRANS_ILLEGAL_OPERATION;
}

TransportStateType AudioTransportStopStatus::GetStateType()
{
    return TRANSPORT_STATE_STOP;
}
} // namespace DistributedHardware
} // namespace OHOS
