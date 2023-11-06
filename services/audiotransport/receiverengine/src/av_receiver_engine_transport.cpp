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

#include "av_receiver_engine_transport.h"

#include <securec.h>
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AVTransReceiverTransport"

namespace OHOS {
namespace DistributedHardware {
int32_t AVTransReceiverTransport::InitEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    if (receiverAdapter_ == nullptr) {
        receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    }
    int32_t ret = receiverAdapter_->Initialize(providerPtr, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("initialize av receiver adapter failed.");
        return ret;
    }
    ret = receiverAdapter_->RegisterAdapterCallback(shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("InitReceiverEngine register callback error.");
    }
    return ret;
}

int32_t AVTransReceiverTransport::SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
    const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType)
{
    (void)remoteParam;
    (void)callback;
    (void)capType;
    return SetParameter(localParam);
}

int32_t AVTransReceiverTransport::CreateCtrl()
{
    DHLOGI("Create ctrl enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("av transport receiver adapter is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverAdapter_->CreateControlChannel(devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("create av receiver control channel failed.");
    }
    return ret;
}

int32_t AVTransReceiverTransport::Start()
{
    DHLOGI("StartReceiverEngine enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("av transport receiver adapter is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverAdapter_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("start av receiver engine failed");
    }
    return ret;
}

int32_t AVTransReceiverTransport::Stop()
{
    DHLOGI("StopReceiverEngine enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("StopReceiverEngine adapter is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverAdapter_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("StopReceiveEngine error.");
    }
    return ret;
}

int32_t AVTransReceiverTransport::Release()
{
    DHLOGI("ReleaseReceiverEngine enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("ReleaseReceiverEngine adapter is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverAdapter_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("ReleaseReceiverEngine error.");
    }
    return ret;
}

int32_t AVTransReceiverTransport::Pause()
{
    DHLOGI("AVTransReceiverTransport Pause enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("Pause error. receiver adapter is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return receiverAdapter_->SetParameter(AVTransTag::ENGINE_PAUSE, "");
}

int32_t AVTransReceiverTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    (void)localParam;
    (void)remoteParam;
    DHLOGI("AVTransReceiverTransport Restart enter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("Restart error. receiver adapter is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return receiverAdapter_->SetParameter(AVTransTag::ENGINE_RESUME, "");
}

int32_t AVTransReceiverTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("ReceiverEngine feed audiodata not support.");
    (void)audioData;
    return DH_SUCCESS;
}

int32_t AVTransReceiverTransport::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote. type: %u, content: %s.", type, content.c_str());
    if (receiverAdapter_ == nullptr) {
        DHLOGE("FeedAudioData receiver adapter is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    int32_t ret = receiverAdapter_->SendMessageToRemote(message);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send message to remote engine failed");
    }
    return ret;
}

void AVTransReceiverTransport::OnEngineEvent(const AVTransEvent &event)
{
    if (transCallback_ == nullptr) {
        DHLOGE("Trans callback is nullptr.");
        return;
    }
    transCallback_->OnEngineTransEvent(event);
}

void AVTransReceiverTransport::OnEngineMessage(const std::shared_ptr<AVTransMessage> &message)
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

void AVTransReceiverTransport::OnEngineDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer)
{
    DHLOGI("On Engine Data available");
    if (buffer == nullptr) {
        DHLOGE("The parameter is nullptr");
        return;
    }
    auto bufferData = buffer->GetBufferData(0);
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufferData->GetSize());
    int32_t ret = memcpy_s(audioData->Data(), audioData->Capacity(), bufferData->GetAddress(), bufferData->GetSize());
    if (ret != EOK) {
        DHLOGE("Copy audio data failed, error code %d.", ret);
        return;
    }
    transCallback_->OnEngineTransDataAvailable(audioData);
}

int32_t AVTransReceiverTransport::SetParameter(const AudioParam &audioParam)
{
    DHLOGI("SetParameter.");
    if (receiverAdapter_ == nullptr) {
        DHLOGE("SetParameter error. adapter is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_RATE, std::to_string(audioParam.comParam.sampleRate));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_FORMAT, std::to_string(AudioSampleFormat::SAMPLE_F32LE));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_CHANNEL_MASK, std::to_string(audioParam.comParam.channelMask));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_CHANNEL_LAYOUT, std::to_string(audioParam.comParam.channelMask));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_BIT_RATE, std::to_string(AUDIO_SET_HISTREAMER_BIT_RATE));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_FRAME_SIZE, std::to_string(audioParam.comParam.frameSize));
    receiverAdapter_->SetParameter(AVTransTag::AUDIO_CODEC_TYPE, std::to_string(audioParam.comParam.codecType));
    receiverAdapter_->SetParameter(AVTransTag::ENGINE_READY, OWNER_NAME_D_SPEAKER);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS