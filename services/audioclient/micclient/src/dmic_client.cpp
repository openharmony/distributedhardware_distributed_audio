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

#include "cJSON.h"

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
    CHECK_NULL_VOID(message);
    DHLOGI("On Engine message, type : %{public}s.", GetEventNameByType(message->type_).c_str());
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
        return ERR_DH_AUDIO_NULLPTR;
    }
    return DH_SUCCESS;
}

int32_t DMicClient::OnStateChange(const AudioEventType type)
{
    DHLOGD("On state change type: %{public}d.", type);
    AudioEvent event;
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);

    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    event.content = std::string(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
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
            DHLOGE("Invalid parameter type: %{public}d.", type);
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }

    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(audioCapturer_, ERR_DH_AUDIO_CLIENT_CAPTURER_CREATE_FAILED);
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        int32_t ret = audioCapturer_->SetCapturerReadCallback(shared_from_this());
        if (ret != DH_SUCCESS) {
            DHLOGE("Client save read callback failed.");
            return ERR_DH_AUDIO_CLIENT_CAPTURER_CREATE_FAILED;
        }
    }
    return TransSetUp();
}

int32_t DMicClient::TransSetUp()
{
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Set up mic client, param: {sampleRate: %{public}d, bitFormat: %{public}d,"
        "channelMask: %{public}d, sourceType: %{public}d, capturerFlags: %{public}d, frameSize: %{public}d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.captureOpts.sourceType,
        param.captureOpts.capturerFlags, param.comParam.frameSize);
    audioParam_ = param;
    return AudioFwkClientSetUp();
}

int32_t DMicClient::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote.");
    if (type != static_cast<uint32_t>(NOTIFY_OPEN_MIC_RESULT) &&
        type != static_cast<uint32_t>(NOTIFY_OPEN_CTRL_RESULT) &&
        type != static_cast<uint32_t>(NOTIFY_CLOSE_MIC_RESULT) &&
        type != static_cast<uint32_t>(CLOSE_MIC)) {
        DHLOGE("event type is not NOTIFY_OPEN_MIC or NOTIFY_CLOSE_MIC or"
            "CLOSE_MIC or OPEN_CTRL. type: %{public}u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
    micTrans_->SendMessage(type, content, dstDevId);
    return DH_SUCCESS;
}

int32_t DMicClient::Release()
{
    DHLOGI("Release mic client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_SA_STATUS_ERR);
    if (clientStatus_ != AudioStatus::STATUS_READY && clientStatus_ != AudioStatus::STATUS_STOP) {
        DHLOGE("Mic status is wrong, %{public}d.", (int32_t)clientStatus_);
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
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_SA_STATUS_ERR);
    CHECK_NULL_RETURN(audioCapturer_, ERR_DH_AUDIO_NULLPTR);

    if (clientStatus_ != AudioStatus::STATUS_READY) {
        DHLOGE("Audio capturer init failed or mic status wrong, status: %{public}d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio init failed or mic status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
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
    CHECK_NULL_VOID(audioCapturer_);

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
            DHLOGE("This time capture spend: %{public}" PRId64" us, The interval of capture this time and "
                "the last time: %{public}" PRId64" us", endTime - startTime, startTime - lastCaptureStartTime_);
        }
        lastCaptureStartTime_ = startTime;
    }
    if (errorFlag) {
        DHLOGE("Bytes read failed.");
        return;
    }
    if (isPauseStatus_.load()) {
        memset_s(audioData->Data(), audioData->Size(), 0, audioData->Size());
    }
#ifdef DUMP_DMICCLIENT_FILE
    if (DaudioSinkHidumper::GetInstance().QueryDumpDataFlag()) {
        SaveFile(MIC_CLIENT_FILENAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
    }
#endif
    int64_t startTransTime = GetNowTimeUs();
    int32_t ret = micTrans_->FeedAudioData(audioData);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to send data.");
    }
    int64_t endTransTime = GetNowTimeUs();
    if (IsOutDurationRange(startTransTime, endTransTime, lastTransStartTime_)) {
        DHLOGE("This time send data spend: %{public}" PRId64" us, The interval of send data this time and "
            "the last time: %{public}" PRId64" us",
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
    CHECK_NULL_VOID(audioCapturer_);
    
    if (audioCapturer_->GetBufferDesc(bufDesc) != DH_SUCCESS || bufDesc.bufLength == 0) {
        DHLOGE("Get buffer desc failed.");
        return;
    }
    CHECK_NULL_VOID(bufDesc.buffer);

    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(audioParam_.comParam.frameSize);
    if (audioData->Capacity() != bufDesc.bufLength) {
        uint64_t capacity = static_cast<uint64_t>(audioData->Capacity());
        uint64_t bufLength = static_cast<uint64_t>(bufDesc.bufLength);
        DHLOGE("Audio data length is not equal to buflength. datalength: %{public}" PRIu64
            ", bufLength: %{public}" PRIu64, capacity, bufLength);
    }
    if (memcpy_s(audioData->Data(), audioData->Capacity(), bufDesc.buffer, bufDesc.bufLength) != EOK) {
        DHLOGE("Copy audio data failed.");
    }

    if (isPauseStatus_.load()) {
        memset_s(audioData->Data(), audioData->Size(), 0, audioData->Size());
    }
    audioCapturer_->Enqueue(bufDesc);

    CHECK_NULL_VOID(micTrans_);
    if (micTrans_->FeedAudioData(audioData) != DH_SUCCESS) {
        DHLOGE("Failed to send data.");
    }
}

int32_t DMicClient::StopCapture()
{
    DHLOGI("Stop capturer.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (clientStatus_ != AudioStatus::STATUS_START) {
        DHLOGE("Capturee is not start or mic status wrong, status: %{public}d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio capturer is not start or mic status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);

    isBlocking_.store(false);
    if (audioParam_.captureOpts.capturerFlags != MMAP_MODE && isCaptureReady_.load()) {
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

int32_t DMicClient::PauseCapture()
{
    DHLOGI("Pause capture.");
    isPauseStatus_.store(true);
    return DH_SUCCESS;
}

int32_t DMicClient::ResumeCapture()
{
    DHLOGI("Resume capture.");
    isPauseStatus_.store(false);
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
