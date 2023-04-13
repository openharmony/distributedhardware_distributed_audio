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

#include "audio_encode_transport.h"

#include "audio_data_channel.h"
#include "audio_encoder_processor.h"
#include "audio_param.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioEncodeTransport"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioEncodeTransport::SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
    const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType)
{
    if (callback == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    dataTransCallback_ = callback;
    context_ = std::make_shared<AudioTransportContext>();
    context_->SetTransportStatus(TRANSPORT_STATE_STOP);
    auto ret = InitAudioEncodeTrans(localParam, remoteParam, capType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init audio encode transport, ret: %d.", ret);
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    capType_ = capType;
    DHLOGI("SetUp success.");
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::Start()
{
    DHLOGI("Start audio encode transport.");
    if (audioChannel_ == nullptr || context_ == nullptr) {
        DHLOGE("Audio channel or context is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (capType_ == CAP_SPK && audioChannel_->OpenSession() != DH_SUCCESS) {
        DHLOGE("Audio channel open session failed.");
        return ERR_DH_AUDIO_TRANS_SESSION_NOT_OPEN;
    }
    int32_t ret = context_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start failed ret: %d.", ret);
        audioChannel_->CloseSession();
        return ret;
    }
    DHLOGI("Start success.");
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::Stop()
{
    DHLOGI("Stop audio encode transport.");
    if (context_ == nullptr) {
        DHLOGE("Context is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context_->Stop();
}

int32_t AudioEncodeTransport::Pause()
{
    DHLOGI("Pause.");
    if (context_ == nullptr) {
        DHLOGE("Context is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context_->Pause();
}

int32_t AudioEncodeTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Restart.");
    int32_t ret = RegisterProcessorListener(localParam, remoteParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Restart failed, register processor listener failed ret: %d.", ret);
        processor_ = nullptr;
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    if (context_ == nullptr) {
        DHLOGE("Context is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context_->Restart(localParam, remoteParam);
}

int32_t AudioEncodeTransport::Release()
{
    DHLOGI("Release audio encode transport.");
    bool releaseStatus = true;
    int32_t ret;
    if (processor_ != nullptr) {
        ret = processor_->ReleaseAudioProcessor();
        if (ret != DH_SUCCESS) {
            DHLOGE("Release audio processor failed, ret: %d.", ret);
            releaseStatus = false;
        }
    }
    if (audioChannel_ != nullptr) {
        ret = audioChannel_->ReleaseSession();
        if (ret != DH_SUCCESS) {
            DHLOGE("Release session failed, ret: %d.", ret);
            releaseStatus = false;
        }
    }
    if (!releaseStatus) {
        DHLOGE("The releaseStatus is false: %d.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    DHLOGI("Release success.");
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("Feed audio data.");
    if (!processor_) {
        DHLOGE("Processor is null, setup first.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }

    int32_t ret = processor_->FeedAudioProcessor(audioData);
    if (ret != DH_SUCCESS) {
        DHLOGE("Feed audio processor failed, ret: %d.", ret);
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::InitAudioEncodeTrans(const AudioParam &localParam,
    const AudioParam &remoteParam, const PortCapType capType)
{
    int32_t ret = RegisterChannelListener(capType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register channel listener failed, ret: %d.", ret);
        audioChannel_ = nullptr;
        return ERR_DH_AUDIO_TRANS_ERROR;
    }

    ret = RegisterProcessorListener(localParam, remoteParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register processor listener failed, ret: %d.", ret);
        processor_ = nullptr;
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::RegisterChannelListener(const PortCapType capType)
{
    DHLOGI("Register channel listener.");
    audioChannel_ = std::make_shared<AudioDataChannel>(peerDevId_);
    int32_t result = (capType == CAP_SPK) ?
        audioChannel_->CreateSession(shared_from_this(), DATA_SPEAKER_SESSION_NAME) :
        audioChannel_->CreateSession(shared_from_this(), DATA_MIC_SESSION_NAME);
    if (result != DH_SUCCESS) {
        DHLOGE("CreateSession failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    if (context_ == nullptr) {
        DHLOGE("Register channel listener error. state Context is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    context_->SetAudioChannel(audioChannel_);
    return DH_SUCCESS;
}

int32_t AudioEncodeTransport::RegisterProcessorListener(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Register processor listener.");
    processor_ = std::make_shared<AudioEncoderProcessor>();
    if (audioChannel_ == nullptr) {
        DHLOGE("Create audio processor failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }

    auto ret = processor_->ConfigureAudioProcessor(localParam.comParam, remoteParam.comParam, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Configure audio processor failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    if (context_ == nullptr) {
        DHLOGE("Register processor listener error. state Context is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    context_->SetAudioProcessor(processor_);
    return DH_SUCCESS;
}

void AudioEncodeTransport::OnSessionOpened()
{
    DHLOGI("On channel session opened.");
    auto cbObj = dataTransCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("On channel session opened. callback is nullptr.");
        return;
    }
    cbObj->OnStateChange(AudioEventType::DATA_OPENED);
}

void AudioEncodeTransport::OnSessionClosed()
{
    DHLOGI("On channel session close.");
    auto cbObj = dataTransCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("On channel session closed. callback is nullptr.");
        return;
    }
    cbObj->OnStateChange(AudioEventType::DATA_CLOSED);
}

void AudioEncodeTransport::OnDataReceived(const std::shared_ptr<AudioData> &data)
{
    (void)data;
}

void AudioEncodeTransport::OnEventReceived(const AudioEvent &event)
{
    (void)event;
}

void AudioEncodeTransport::OnAudioDataDone(const std::shared_ptr<AudioData> &outputData)
{
    DHLOGI("On audio data done.");
    if (!audioChannel_) {
        DHLOGE("Channel is null, setup first.");
        return;
    }
    int32_t ret = audioChannel_->SendData(outputData);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send data failed ret: %d.", ret);
        return;
    }
}

void AudioEncodeTransport::OnStateNotify(const AudioEvent &event)
{
    (void)event;
}
} // namespace DistributedHardware
} // namespace OHOS
