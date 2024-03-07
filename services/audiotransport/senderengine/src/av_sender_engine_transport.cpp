/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "av_sender_engine_transport.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AVTransSenderTransport"

namespace OHOS {
namespace DistributedHardware {
int32_t AVTransSenderTransport::InitEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("Init av sender engine.");
    if (senderAdapter_ == nullptr) {
        senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    }
    int32_t ret = senderAdapter_->Initialize(providerPtr, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init av adapter failed.");
        return ret;
    }
    ret = senderAdapter_->RegisterAdapterCallback(shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Register callback failed.");
    }
    return ret;
}

int32_t AVTransSenderTransport::SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
    const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType)
{
    (void)remoteParam;
    (void)callback;
    (void)capType;
    return SetParameter(localParam);
}

int32_t AVTransSenderTransport::Start()
{
    DHLOGI("Start av sender engine.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->Start();
}

int32_t AVTransSenderTransport::CreateCtrl()
{
    DHLOGI("Create control channel.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->CreateControlChannel(devId_);
}

int32_t AVTransSenderTransport::Stop()
{
    DHLOGI("Stop av sender engine.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->Stop();
}

int32_t AVTransSenderTransport::Pause()
{
    DHLOGI("Pause av sender engine.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->SetParameter(AVTransTag::ENGINE_PAUSE, "");
}

int32_t AVTransSenderTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Restart av sender engine.");
    (void)localParam;
    (void)remoteParam;
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->SetParameter(AVTransTag::ENGINE_RESUME, "");
}

int32_t AVTransSenderTransport::Release()
{
    DHLOGI("Relase av sender engine.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->Release();
}

int32_t AVTransSenderTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    return senderAdapter_->PushData(audioData);
}

int32_t AVTransSenderTransport::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message, msg type: %{public}u, msg content: %{public}s.", type, content.c_str());
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    return senderAdapter_->SendMessageToRemote(message);
}

void AVTransSenderTransport::OnEngineEvent(const AVTransEvent &event)
{
    CHECK_NULL_VOID(transCallback_);
    transCallback_->OnEngineTransEvent(event);
}

void AVTransSenderTransport::OnEngineMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    CHECK_NULL_VOID(transCallback_);
    transCallback_->OnEngineTransMessage(message);
}

int32_t AVTransSenderTransport::SetParameter(const AudioParam &audioParam)
{
    DHLOGI("Set audio parameter.");
    CHECK_NULL_RETURN(senderAdapter_, ERR_DH_AUDIO_NULLPTR);
    senderAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_RATE, std::to_string(audioParam.comParam.sampleRate));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_FORMAT, std::to_string(audioParam.comParam.bitFormat));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_CHANNEL_MASK, std::to_string(audioParam.comParam.channelMask));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_CHANNEL_LAYOUT, std::to_string(audioParam.comParam.channelMask));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_BIT_RATE, std::to_string(AUDIO_SET_HISTREAMER_BIT_RATE));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_FRAME_SIZE, std::to_string(audioParam.comParam.frameSize));
    senderAdapter_->SetParameter(AVTransTag::AUDIO_CODEC_TYPE, std::to_string(audioParam.comParam.codecType));
    senderAdapter_->SetParameter(AVTransTag::ENGINE_READY, OWNER_NAME_D_SPEAKER);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS