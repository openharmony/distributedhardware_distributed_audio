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
    DHLOGI("InitSenderEngine enter");
    if (senderAdapter_ == nullptr) {
        DHLOGD("SenderAdapter_ is null, create new.");
        senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    }
    int32_t ret = senderAdapter_->Initialize(providerPtr, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("initialize av sender adapter failed.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    DHLOGI("Init SenderEngine success");
    ret = senderAdapter_->RegisterAdapterCallback(shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("InitSenderEngine register callback error.");
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
    DHLOGI("StartSenderEngine enter.");
    if (senderAdapter_ == nullptr) {
        DHLOGE("av transport sender adapter is null");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    int32_t ret = senderAdapter_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("start av sender engine failed");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderTransport::CreateCtrl()
{
    DHLOGI("Create ctrl enter.");
    if (senderAdapter_ == nullptr) {
        DHLOGE("av transport sender adapter is null");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    int32_t ret = senderAdapter_->CreateControlChannel(devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("create av sender control channel failed.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderTransport::Stop()
{
    DHLOGI("StopSenderEngine enter.");
    if (senderAdapter_ == nullptr) {
        DHLOGE("av transport sender adapter is null");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    int32_t ret = senderAdapter_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("av transport sender adapter is null");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

// todo pause
int32_t AVTransSenderTransport::Pause()
{
    DHLOGI("PauseSenderEngine enter.");
    return DH_SUCCESS;
}

// todo restart
int32_t AVTransSenderTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("RestartSenderEngine enter.");
    return DH_SUCCESS;
}

int32_t AVTransSenderTransport::Release()
{
    DHLOGI("RelaseSenderEngine enter.");
    if (senderAdapter_ == nullptr) {
        DHLOGE("ReleaseSenderEngine sender adapter is null.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    int32_t ret = senderAdapter_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release av sender engine failed.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    if (senderAdapter_ == nullptr) {
        DHLOGE("FeedAudioData sender adapter is null.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    int32_t ret = senderAdapter_->PushData(audioData);
    if (ret != DH_SUCCESS) {
        DHLOGE("push data failed.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderTransport::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote. type: %u, content: %s.", type, content.c_str());
    if (senderAdapter_ == nullptr) {
        DHLOGE("FeedAudioData sender adapter is null.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    int32_t ret = senderAdapter_->SendMessageToRemote(message);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send message to remote engine failed");
        return ret;
    }
    return DH_SUCCESS;
}

void AVTransSenderTransport::OnEngineEvent(const AVTransEvent &event)
{
    if (transCallback_ == nullptr) {
        DHLOGE("Trans callback is nullptr.");
        return;
    }
    transCallback_->OnEngineTransEvent(event);
}

void AVTransSenderTransport::OnEngineMessage(const std::shared_ptr<AVTransMessage> &message)
{
    if (message == nullptr) {
        DHLOGE("The parameter is nullptr");
        return;
    }
    if (transCallback_ == nullptr) {
        DHLOGE("Event callback is nullptr.");
        return;
    }
    transCallback_->OnEngineTransMessage(message);
}

int32_t AVTransSenderTransport::SetParameter(const AudioParam &audioParam)
{
    DHLOGI("SetParameter.");
    if (senderAdapter_ == nullptr) {
        DHLOGE("SetParameter error. adapter is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
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