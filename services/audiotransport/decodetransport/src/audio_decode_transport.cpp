/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "audio_decode_transport.h"

#include "audio_data_channel.h"
#include "audio_direct_processor.h"
#include "audio_param.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDecodeTransport"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioDecodeTransport::SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
    const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType)
{
    CHECK_NULL_RETURN(callback, ERR_DH_AUDIO_TRANS_ERROR);
    dataTransCallback_ = callback;
    context_ = std::make_shared<AudioTransportContext>();
    context_->SetTransportStatus(TRANSPORT_STATE_STOP);
    int32_t ret = InitAudioDecodeTransport(localParam, remoteParam, capType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init audio encode transport, ret: %d.", ret);
        return ret;
    }
    capType_ = capType;
    DHLOGI("SetUp success.");
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::Start()
{
    DHLOGI("Start audio decode transport.");
    CHECK_NULL_RETURN(audioChannel_, ERR_DH_AUDIO_NULLPTR);
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);

    if (capType_ == CAP_MIC && audioChannel_->OpenSession() != DH_SUCCESS) {
        DHLOGE("Audio channel open session failed.");
        return ERR_DH_AUDIO_TRANS_SESSION_NOT_OPEN;
    }
    int32_t ret = context_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Context start failed ret: %d.", ret);
        audioChannel_->CloseSession();
        return ret;
    }
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::Stop()
{
    DHLOGI("Stop audio decode transport.");
    if (audioChannel_ != nullptr) {
        audioChannel_->CloseSession();
    }
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);
    return context_->Stop();
}

int32_t AudioDecodeTransport::Pause()
{
    DHLOGI("Pause.");
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);
    return context_->Pause();
}

int32_t AudioDecodeTransport::Restart(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Restart.");
    int32_t ret = RegisterProcessorListener(localParam, remoteParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register processor listener failed, ret: %d.", ret);
        processor_ = nullptr;
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);
    return context_->Restart(localParam, remoteParam);
}

int32_t AudioDecodeTransport::Release()
{
    DHLOGI("Release audio decode transport.");
    bool releaseStatus = true;
    if (processor_ != nullptr) {
        int32_t ret = processor_->ReleaseAudioProcessor();
        if (ret != DH_SUCCESS) {
            DHLOGE("Release audio processor failed, ret: %d.", ret);
            releaseStatus = false;
        }
    }
    if (audioChannel_ != nullptr) {
        int32_t ret = audioChannel_->ReleaseSession();
        if (ret != DH_SUCCESS) {
            DHLOGE("Release session failed, ret: %d.", ret);
            releaseStatus = false;
        }
    }
    if (!releaseStatus) {
        DHLOGE("The releaseStatus is false.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    DHLOGI("Release success.");
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::FeedAudioData(std::shared_ptr<AudioData> &audioData)
{
    (void)audioData;
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::CreateCtrl()
{
    DHLOGI("create ctrl not support.");
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::InitEngine(IAVEngineProvider *providerPtr)
{
    (void)providerPtr;
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    (void)type;
    (void)content;
    (void)dstDevId;
    DHLOGI("Send message not support.");
    return DH_SUCCESS;
}

void AudioDecodeTransport::OnSessionOpened()
{
    DHLOGI("On channel session opened.");
    auto cbObj = dataTransCallback_.lock();
    CHECK_NULL_VOID(cbObj);
    cbObj->OnStateChange(AudioEventType::DATA_OPENED);
}

void AudioDecodeTransport::OnSessionClosed()
{
    DHLOGI("On channel session closed.");
    auto cbObj = dataTransCallback_.lock();
    CHECK_NULL_VOID(cbObj);
    cbObj->OnStateChange(AudioEventType::DATA_CLOSED);
}

void AudioDecodeTransport::OnDataReceived(const std::shared_ptr<AudioData> &data)
{
    DHLOGI("On audio data received.");
    CHECK_NULL_VOID(processor_);
    if (processor_->FeedAudioProcessor(data) != DH_SUCCESS) {
        DHLOGE("Feed audio processor failed.");
    }
}

void AudioDecodeTransport::OnEventReceived(const AudioEvent &event)
{
    (void)event;
}

void AudioDecodeTransport::OnAudioDataDone(const std::shared_ptr<AudioData> &outputData)
{
    DHLOGI("On audio data done.");
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    auto cbObj = dataTransCallback_.lock();
    CHECK_NULL_VOID(cbObj);
    cbObj->OnDecodeTransDataDone(outputData);
}

void AudioDecodeTransport::OnStateNotify(const AudioEvent &event)
{
    (void)event;
}

int32_t AudioDecodeTransport::InitAudioDecodeTransport(const AudioParam &localParam,
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
    audioParam_ = remoteParam;
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::RegisterChannelListener(const PortCapType capType)
{
    DHLOGI("Register Channel Listener.");
    audioChannel_ = std::make_shared<AudioDataChannel>(peerDevId_);
    int32_t result = (capType == CAP_SPK) ?
        audioChannel_->CreateSession(shared_from_this(), DATA_SPEAKER_SESSION_NAME) :
        audioChannel_->CreateSession(shared_from_this(), DATA_MIC_SESSION_NAME);
    if (result != DH_SUCCESS) {
        DHLOGE("Create session failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);
    context_->SetAudioChannel(audioChannel_);
    return DH_SUCCESS;
}

int32_t AudioDecodeTransport::RegisterProcessorListener(const AudioParam &localParam, const AudioParam &remoteParam)
{
    DHLOGI("Register processor listener.");
    if (localParam.renderOpts.renderFlags == MMAP_MODE || localParam.captureOpts.capturerFlags == MMAP_MODE) {
        DHLOGI("Use direct processor, renderFlags: %d, capturerFlags: %d.",
            localParam.renderOpts.renderFlags, localParam.captureOpts.capturerFlags);
        processor_ = std::make_shared<AudioDirectProcessor>();
    }
    int32_t ret = processor_->ConfigureAudioProcessor(localParam.comParam, remoteParam.comParam, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Configure audio processor failed.");
        return ret;
    }
    CHECK_NULL_RETURN(context_, ERR_DH_AUDIO_NULLPTR);
    context_->SetAudioProcessor(processor_);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
