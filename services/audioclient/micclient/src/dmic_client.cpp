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
#include "daudio_sink_hidumper.h"
#include "daudio_sink_manager.h"

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

void DMicClient::OnEngineTransEvent(const AVTransEvent &event)
{
    if (event.type == EventType::EVENT_START_SUCCESS) {
        OnStateChange(DATA_OPENED);
    } else if ((event.type == EventType::EVENT_STOP_SUCCESS) ||
        (event.type == EventType::EVENT_CHANNEL_CLOSED) ||
        (event.type == EventType::EVENT_START_FAIL)) {
        OnStateChange(DATA_CLOSED);
    }
}

void DMicClient::OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    DHLOGI("On Engine message");
    if (message == nullptr) {
        DHLOGE("The parameter is nullptr");
        return;
    }
    DAudioSinkManager::GetInstance().HandleDAudioNotify(message->dstDevId_, message->dstDevId_,
        static_cast<int32_t>(message->type_), message->content_);
}

int32_t DMicClient::InitSenderEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("Init SenderEngine");
    if (micTrans_ == nullptr) {
        micTrans_ = std::make_shared<AVTransSenderTransport>(devId_, shared_from_this());
    }
    int32_t ret = micTrans_->InitEngine(providerPtr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic client initialize av sender adapter failed.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    return DH_SUCCESS;
}

int32_t DMicClient::OnStateChange(const AudioEventType type)
{
    DHLOGD("On state change type: %d.", type);
    AudioEvent event;
    event.content = "";
    switch (type) {
        case AudioEventType::DATA_OPENED: {
            isBlocking_.store(true);
            if (audioParam_.captureOpts.capturerFlags != MMAP_MODE) {
                isCaptureReady_.store(true);
                captureDataThread_ = std::thread(&DMicClient::CaptureThreadRunning, this);
            }
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

int32_t DMicClient::AudioFwkClientSetUp()
{
    AudioStandard::AudioCapturerOptions capturerOptions = {
        {
            static_cast<AudioStandard::AudioSamplingRate>(audioParam_.comParam.sampleRate),
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            static_cast<AudioStandard::AudioSampleFormat>(audioParam_.comParam.bitFormat),
            static_cast<AudioStandard::AudioChannel>(audioParam_.comParam.channelMask),
        },
        {
            static_cast<AudioStandard::SourceType>(audioParam_.captureOpts.sourceType),
            audioParam_.captureOpts.capturerFlags == MMAP_MODE ? AudioStandard::STREAM_FLAG_FAST : 0,
        }
    };
    std::lock_guard<std::mutex> lck(devMtx_);
    audioCapturer_ = AudioStandard::AudioCapturer::Create(capturerOptions);
    if (audioCapturer_ == nullptr) {
        DHLOGE("Audio capturer create failed.");
        return ERR_DH_AUDIO_CLIENT_CREATE_CAPTURER_FAILED;
    }
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        int32_t ret = audioCapturer_->SetCapturerReadCallback(shared_from_this());
        if (ret != DH_SUCCESS) {
            DHLOGE("Client save read callback failed.");
            return ERR_DH_AUDIO_CLIENT_CREATE_CAPTURER_FAILED;
        }
    }
    return TransSetUp();
}

int32_t DMicClient::TransSetUp()
{
    if (micTrans_ == nullptr) {
        DHLOGE("mic trans in engine should be init by dev.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = micTrans_->SetUp(audioParam_, audioParam_, shared_from_this(), CAP_MIC);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans setup failed.");
        return ret;
    }
    clientStatus_ = AudioStatus::STATUS_READY;
    return DH_SUCCESS;
}

int32_t DMicClient::SetUp(const AudioParam &param)
{
    DHLOGI("Set up mic client, param: {sampleRate: %d, bitFormat: %d," +
        "channelMask: %d, sourceType: %d, capturerFlags: %d, frameSize: %d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.captureOpts.sourceType,
        param.captureOpts.capturerFlags, param.comParam.frameSize);
    audioParam_ = param;
    return AudioFwkClientSetUp();
}

int32_t DMicClient::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote.");
    if (type != static_cast<uint32_t>(NOTIFY_OPEN_MIC_RESULT) &&
        type != static_cast<uint32_t>(NOTIFY_CLOSE_MIC_RESULT)) {
        DHLOGE("event type is not NOTIFY_OPEN_MIC or NOTIFY_CLOSE_MIC. type: %u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (micTrans_ == nullptr) {
        DHLOGE("mic trans is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    micTrans_->SendMessage(type, content, dstDevId);
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
    bool isReleaseError = false;
    if (audioCapturer_ == nullptr || !audioCapturer_->Release()) {
        DHLOGE("Audio capturer release failed.");
        isReleaseError = true;
    }
    int32_t ret = micTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans release failed.");
        isReleaseError = true;
    }
    micTrans_ = nullptr;
    clientStatus_ = AudioStatus::STATUS_IDLE;
    if (isReleaseError) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DMicClient::StartCapture()
{
    DHLOGI("Start capturer.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (micTrans_ == nullptr || clientStatus_ != AudioStatus::STATUS_READY) {
        DHLOGE("Audio capturer init failed or mic status wrong, status: %d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio init failed or mic status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    if (audioCapturer_ == nullptr) {
        DHLOGE("audio capturer is nullptr.");
        return ERR_DH_AUDIO_CLIENT_CAPTURER_START_FAILED;
    }
    if (!audioCapturer_->Start()) {
        DHLOGE("Audio capturer start failed.");
        audioCapturer_->Release();
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL,
            ERR_DH_AUDIO_CLIENT_CAPTURER_START_FAILED, "daudio capturer start failed.");
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

void DMicClient::AudioFwkCaptureData()
{
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(audioParam_.comParam.frameSize);
    size_t bytesRead = 0;
    bool errorFlag = false;
    int64_t startTime = GetNowTimeUs();
    if (audioCapturer_ == nullptr) {
        DHLOGE("audio capturer is nullptr");
        return;
    }
    while (bytesRead < audioParam_.comParam.frameSize) {
        int32_t len = audioCapturer_->Read(*(audioData->Data() + bytesRead),
            audioParam_.comParam.frameSize - bytesRead, isBlocking_.load());
        if (len >= 0) {
            bytesRead += static_cast<size_t>(len);
        } else {
            errorFlag = true;
            break;
        }
        int64_t endTime = GetNowTimeUs();
        if (IsOutDurationRange(startTime, endTime, lastCaptureStartTime_)) {
            DHLOGE("This time capture spend: %lld, The interval of capture this time and the last time: %lld",
                endTime - startTime, startTime - lastCaptureStartTime_);
        }
        lastCaptureStartTime_ = startTime;
    }
    if (errorFlag) {
        DHLOGE("Bytes read failed.");
        return;
    }
#ifdef DUMP_DMICCLIENT_FILE
    if (DaudioSinkHidumper::GetInstance().GetFlagStatus()) {
        SaveFile(FILE_NAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
    }
#endif
    int64_t startTransTime = GetNowTimeUs();
    int32_t ret = micTrans_->FeedAudioData(audioData);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to send data.");
    }
    int64_t endTransTime = GetNowTimeUs();
    if (IsOutDurationRange(startTransTime, endTransTime, lastTransStartTime_)) {
        DHLOGE("This time send data spend: %lld, The interval of send data this time and the last time: %lld",
            endTransTime - startTransTime, startTransTime - lastTransStartTime_);
    }
    lastTransStartTime_ = startTransTime;
}

void DMicClient::CaptureThreadRunning()
{
    DHLOGD("Start the capturer thread.");
    if (pthread_setname_np(pthread_self(), CAPTURETHREAD) != DH_SUCCESS) {
        DHLOGE("Capture data thread setname failed.");
    }
    while (isCaptureReady_.load()) {
        AudioFwkCaptureData();
    }
}

int32_t DMicClient::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    (void)audioData;
    return DH_SUCCESS;
}

void DMicClient::OnReadData(size_t length)
{
    AudioStandard::BufferDesc bufDesc;
    if (audioCapturer_ == nullptr) {
        DHLOGE("audioCapturer is nullptr.");
        return;
    }
    int32_t ret = audioCapturer_->GetBufferDesc(bufDesc);
    if (ret != DH_SUCCESS || bufDesc.buffer == nullptr || bufDesc.bufLength == 0) {
        DHLOGE("Get buffer desc failed. On read data.");
        return;
    }
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(audioParam_.comParam.frameSize);
    if (audioData->Capacity() != bufDesc.bufLength) {
        DHLOGE("Audio data length is not equal to buflength. datalength: %d, bufLength: %d",
            audioData->Capacity(), bufDesc.bufLength);
    }
    if (memcpy_s(audioData->Data(), audioData->Capacity(), bufDesc.buffer, bufDesc.bufLength) != EOK) {
        DHLOGE("Copy audio data failed.");
    }
    audioCapturer_->Enqueue(bufDesc);
    if (micTrans_ == nullptr) {
        DHLOGE("Mic trans is nullptr.");
        return;
    }
    if (micTrans_->FeedAudioData(audioData) != DH_SUCCESS) {
        DHLOGE("Failed to send data.");
    }
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
    if (micTrans_ == nullptr) {
        DHLOGE("The capturer or mictrans is not instantiated.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL,
            ERR_DH_AUDIO_CLIENT_CAPTURER_OR_MICTRANS_INSTANCE, "daudio capturer or mictrans is not instantiated.");
        return ERR_DH_AUDIO_CLIENT_CAPTURER_OR_MICTRANS_INSTANCE;
    }

    isBlocking_.store(false);
    if (audioParam_.captureOpts.capturerFlags != MMAP_MODE) {
        isCaptureReady_.store(false);
        if (captureDataThread_.joinable()) {
            captureDataThread_.join();
        }
    }

    bool status = true;
    int32_t ret = micTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans stop failed.");
        status = false;
    }
    if (audioCapturer_ == nullptr || !audioCapturer_->Stop()) {
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
