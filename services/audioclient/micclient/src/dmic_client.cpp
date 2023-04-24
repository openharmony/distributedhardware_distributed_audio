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

#include "dmic_client.h"

#include <chrono>

#include "daudio_constants.h"
#include "daudio_hisysevent.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DMicClient"

namespace OHOS {
namespace DistributedHardware {
DMicClient::~DMicClient()
{
    if (micTrans_ != nullptr) {
        DHLOGI("Release mic client.");
        StopCapture();
    }
}

int32_t DMicClient::OnStateChange(const AudioEventType type)
{
    DHLOGI("On state change type: %d.", type);
    AudioEvent event;
    event.content = "";
    switch (type) {
        case AudioEventType::DATA_OPENED: {
            isBlocking_.store(true);
            isCaptureReady_.store(true);
            captureDataThread_ = std::thread(&DMicClient::CaptureThreadRunning, this);
            event.type = AudioEventType::MIC_OPENED;
            break;
        }
        case AudioEventType::DATA_CLOSED: {
            event.type = AudioEventType::MIC_CLOSED;
            break;
        }
        default:
            DHLOGE("Invalid parameter type: %d.", type);
            return ERR_DH_AUDIO_CLIENT_STATE_IS_INVALID;
    }

    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is nullptr.");
        return ERR_DH_AUDIO_CLIENT_EVENT_CALLBACK_IS_NULL;
    }
    cbObj->NotifyEvent(event);
    return DH_SUCCESS;
}

int32_t DMicClient::SetUp(const AudioParam &param)
{
    DHLOGI("Set up mic client, param: {sampleRate: %d, bitFormat: %d," +
        "channelMask: %d, sourceType: %d, capturerFlags: %d, frameSize: %d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.captureOpts.sourceType,
        param.captureOpts.capturerFlags, param.comParam.frameSize);
    audioParam_ = param;
    AudioStandard::AudioCapturerOptions capturerOptions = {
        {
            static_cast<AudioStandard::AudioSamplingRate>(audioParam_.comParam.sampleRate),
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            static_cast<AudioStandard::AudioSampleFormat>(audioParam_.comParam.bitFormat),
            static_cast<AudioStandard::AudioChannel>(audioParam_.comParam.channelMask),
        },
        {
            static_cast<AudioStandard::SourceType>(audioParam_.captureOpts.sourceType),
            0,
        }
    };
    std::lock_guard<std::mutex> lck(devMtx_);
    audioCapturer_ = AudioStandard::AudioCapturer::Create(capturerOptions);
    if (audioCapturer_ == nullptr) {
        DHLOGE("Audio capturer create failed.");
        return ERR_DH_AUDIO_CLIENT_CREATE_CAPTURER_FAILED;
    }

    micTrans_ = std::make_shared<AudioEncodeTransport>(devId_);
    int32_t ret = micTrans_->SetUp(audioParam_, audioParam_, shared_from_this(), CAP_MIC);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans setup failed.");
        return ret;
    }
    clientStatus_ = AudioStatus::STATUS_READY;
    return DH_SUCCESS;
}

int32_t DMicClient::Release()
{
    DHLOGI("Release mic client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if ((clientStatus_ != AudioStatus::STATUS_READY && clientStatus_ != AudioStatus::STATUS_STOP) ||
        micTrans_ == nullptr) {
        DHLOGE("Mic status is wrong or mic trans is null, %d.", (int32_t)clientStatus_);
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    bool status = true;
    if (!audioCapturer_->Release()) {
        DHLOGE("Audio capturer release failed.");
        status = false;
    }
    int32_t ret = micTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans release failed.");
        status = false;
    }
    micTrans_ = nullptr;
    clientStatus_ = AudioStatus::STATUS_IDLE;
    if (!status) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DMicClient::StartCapture()
{
    DHLOGI("Start capturer.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (audioCapturer_ == nullptr || micTrans_ == nullptr || clientStatus_ != AudioStatus::STATUS_READY) {
        DHLOGE("Audio capturer init failed or mic status wrong, status: %d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio init failed or mic status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }

    if (!audioCapturer_->Start()) {
        DHLOGE("Audio capturer start failed.");
        audioCapturer_->Release();
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_CLIENT_CAPTURER_START_FAILED,
            "daudio capturer start failed.");
        return ERR_DH_AUDIO_CLIENT_CAPTURER_START_FAILED;
    }

    int32_t ret = micTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans start failed.");
        micTrans_->Release();
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret, "daudio mic trans start failed.");
        return ret;
    }
    clientStatus_ = AudioStatus::STATUS_START;
    return DH_SUCCESS;
}

void DMicClient::CaptureThreadRunning()
{
    DHLOGI("Start the capturer thread.");
    if (pthread_setname_np(pthread_self(), CAPTURETHREAD) != DH_SUCCESS) {
        DHLOGE("Capture data thread setname failed.");
    }
    while (isCaptureReady_.load()) {
        std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(audioParam_.comParam.frameSize);
        size_t bytesRead = 0;
        bool errorFlag = false;
        while (bytesRead < audioParam_.comParam.frameSize) {
            int32_t len = audioCapturer_->Read(*(audioData->Data() + bytesRead),
                audioParam_.comParam.frameSize - bytesRead, isBlocking_.load());
            if (len >= 0) {
                bytesRead += static_cast<size_t>(len);
            } else {
                errorFlag = true;
                break;
            }
        }
        if (errorFlag) {
            DHLOGI("Bytes read failed.");
            break;
        }

        int32_t ret = micTrans_->FeedAudioData(audioData);
        if (ret != DH_SUCCESS) {
            DHLOGE("Failed to send data.");
        }
    }
}

int32_t DMicClient::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    (void)audioData;
    return DH_SUCCESS;
}

int32_t DMicClient::StopCapture()
{
    DHLOGI("Stop capturer.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (clientStatus_ != AudioStatus::STATUS_START || !isCaptureReady_.load()) {
        DHLOGE("Capturee is not start or mic status wrong, status: %d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio capturer is not start or mic status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    if (audioCapturer_ == nullptr || micTrans_ == nullptr) {
        DHLOGE("The capturer or mictrans is not instantiated.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL,
            ERR_DH_AUDIO_CLIENT_CAPTURER_OR_MICTRANS_INSTANCE, "daudio capturer or mictrans is not instantiated.");
        return ERR_DH_AUDIO_CLIENT_CAPTURER_OR_MICTRANS_INSTANCE;
    }

    isBlocking_.store(false);
    isCaptureReady_.store(false);
    if (captureDataThread_.joinable()) {
        captureDataThread_.join();
    }

    bool status = true;
    int32_t ret = micTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans stop failed.");
        status = false;
    }
    if (!audioCapturer_->Stop()) {
        DHLOGE("Audio capturer stop failed.");
        status = false;
    }
    clientStatus_ = AudioStatus::STATUS_STOP;
    if (!status) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

void DMicClient::SetAttrs(const std::string &devId, const std::shared_ptr<IAudioEventCallback> &callback)
{
    DHLOGE("Set attrs, not support yet.");
}
} // DistributedHardware
} // OHOS
