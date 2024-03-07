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
    DHLOGI("Init av receiver engine.");
    if (receiverAdapter_ == nullptr) {
        receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    }
    int32_t ret = receiverAdapter_->Initialize(providerPtr, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init av receiver adapter failed.");
        return ret;
    }
    if (receiverAdapter_->RegisterAdapterCallback(shared_from_this()) != DH_SUCCESS) {
        DHLOGE("Register callback error.");
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
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->CreateControlChannel(devId_);
}

int32_t AVTransReceiverTransport::Start()
{
    DHLOGI("Start av receiver engine.");
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->Start();
}

int32_t AVTransReceiverTransport::Stop()
{
    DHLOGI("Stop av receiver engine.");
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->Stop();
}

int32_t AVTransReceiverTransport::Release()
{
    DHLOGI("Release av receiver engine.");
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->Release();
}

int32_t AVTransReceiverTransport::Pause()
{
    DHLOGI("Pause av receiver engine.");
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->SetParameter(AVTransTag::ENGINE_PAUSE, "");
}

int32_t AVTransReceiverTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Restart av receiver engine.");
    (void)localParam;
    (void)remoteParam;
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    return receiverAdapter_->SetParameter(AVTransTag::ENGINE_RESUME, "");
}

int32_t AVTransReceiverTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("Receiver engine not support.");
    (void)audioData;
    return DH_SUCCESS;
}

int32_t AVTransReceiverTransport::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote. type: %{public}u, content: %{public}s.", type, content.c_str());
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    return receiverAdapter_->SendMessageToRemote(message);
}

void AVTransReceiverTransport::OnEngineEvent(const AVTransEvent &event)
{
    CHECK_NULL_VOID(transCallback_);
    transCallback_->OnEngineTransEvent(event);
}

void AVTransReceiverTransport::OnEngineMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    CHECK_NULL_VOID(transCallback_);
    transCallback_->OnEngineTransMessage(message);
}

void AVTransReceiverTransport::OnEngineDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer)
{
    DHLOGD("On data availabled.");
    CHECK_NULL_VOID(buffer);
    auto bufferData = buffer->GetBufferData(0);
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufferData->GetSize());
    int32_t ret = memcpy_s(audioData->Data(), audioData->Capacity(), bufferData->GetAddress(), bufferData->GetSize());
    if (ret != EOK) {
        DHLOGE("Copy audio data failed, error code %{public}d.", ret);
        return;
    }
    CHECK_NULL_VOID(transCallback_);
    transCallback_->OnEngineTransDataAvailable(audioData);
}

int32_t AVTransReceiverTransport::SetParameter(const AudioParam &audioParam)
{
    DHLOGI("SetParameter.");
    CHECK_NULL_RETURN(receiverAdapter_, ERR_DH_AUDIO_NULLPTR);
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