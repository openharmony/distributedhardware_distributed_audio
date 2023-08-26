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
            isCaptureReady_.store(true);
            if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
                frameIndex_ = 0;
            }
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

void DMicClient::AdapterDescFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }
    if (dataBlock->adapterName != nullptr) {
        free(dataBlock->adapterName);
        dataBlock->adapterName = nullptr;
    }
    if (dataBlock->ports != nullptr) {
        free(dataBlock->ports);
        dataBlock->ports = nullptr;
    }
    if (freeSelf) {
        free(dataBlock);
        dataBlock = nullptr;
    }
}

void DMicClient::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if (descsLen > 0 && descs != nullptr && (*descs) != nullptr) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AdapterDescFree(&(*descs)[i], false);
        }
        free(*descs);
        *descs = nullptr;
    }
}

int32_t DMicClient::GetAudioManager()
{
    audioManager_ = IAudioManagerGet(false);
    if (audioManager_ == nullptr) {
        DHLOGE("Get audio manager fail");
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DMicClient::GetAdapter()
{
    size_t adapterSize = sizeof(struct AudioAdapterDescriptor) * (MAX_AUDIO_ADAPTER_DESC);
    struct AudioAdapterDescriptor *descs = reinterpret_cast<struct AudioAdapterDescriptor *>(malloc(adapterSize));
    if (descs == nullptr) {
        DHLOGE("malloc for descs failed");
        return ERR_DH_AUDIO_FAILED;
    }
    if (memset_s(descs, adapterSize, 0, adapterSize) != EOK) {
        DHLOGE("memset for descs failed");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    uint32_t size = MAX_AUDIO_ADAPTER_DESC;
    if (audioManager_ == nullptr) {
        DHLOGE("AudioManager is nullptr");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = audioManager_->GetAllAdapters(audioManager_, descs, &size);
    if (size == 0 || descs == nullptr || ret != 0) {
        DHLOGE("Get audio adapters failed. ret : %d.", ret);
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    struct AudioAdapterDescriptor *primaryDesc = nullptr;
    if (GetPrimaryDesc(descs, &primaryDesc) != DH_SUCCESS) {
        return ERR_DH_AUDIO_FAILED;
    }
    ret = audioManager_->LoadAdapter(audioManager_, primaryDesc, &audioAdapter_);
    if (ret != DH_SUCCESS || audioAdapter_ == nullptr) {
        DHLOGE("Load primary adapter failed.");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
    (void)audioAdapter_->InitAllPorts(audioAdapter_);
    return DH_SUCCESS;
}

int32_t DMicClient::GetPrimaryDesc(struct AudioAdapterDescriptor *descs, struct AudioAdapterDescriptor
    **primaryDesc)
{
    uint32_t size = MAX_AUDIO_ADAPTER_DESC;
    for (uint32_t index = 0; index < size; index++) {
        auto desc = &descs[index];
        if (desc == nullptr || desc->adapterName == nullptr) {
            continue;
        }
        if (!strcmp(desc->adapterName, ADAPTERNAME)) {
            *primaryDesc = desc;
            break;
        }
    }
    if (*primaryDesc == nullptr) {
        DHLOGE("Find primary adapter failed.");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    if (strcpy_s(adapterName_, PATH_LEN, (*primaryDesc)->adapterName) < 0) {
        DHLOGE("Strcpy adapter name failed.");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

void DMicClient::ReleaseHDFAudioDevice()
{
    if (micInUse_) {
        return;
    }
    if (audioManager_ != nullptr && audioManager_->UnloadAdapter != nullptr) {
        audioManager_->UnloadAdapter(audioManager_, adapterName_);
        IAudioAdapterRelease(audioAdapter_, false);
        audioAdapter_ = nullptr;
        IAudioManagerRelease(audioManager_, false);
        audioManager_ = nullptr;
    }
}

int32_t DMicClient::InitHDFAudioDevice()
{
    if (micInUse_) {
        return DH_SUCCESS;
    }
    if (GetAudioManager() != DH_SUCCESS) {
        DHLOGE("Get audio manager failed");
        ReleaseHDFAudioDevice();
        return ERR_DH_AUDIO_FAILED;
    }

    if (GetAdapter() != DH_SUCCESS) {
        DHLOGE("Get audio adapter failed");
        ReleaseHDFAudioDevice();
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

void DMicClient::GenerateAttr(const AudioParam &param)
{
    captureDesc_.portId = PORT_ID;
    captureDesc_.pins = AudioPortPin::PIN_IN_MIC;
    captureDesc_.desc = strdup(DEVNAME);
    captureAttr_.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    captureAttr_.interleaved = 0;
    captureAttr_.type = AUDIO_IN_MEDIA;
    captureAttr_.period = BUFFER_PERIOD_SIZE;
    captureAttr_.isBigEndian = false;
    captureAttr_.isSignedData = true;
    captureAttr_.stopThreshold = INT_32_MAX;
    captureAttr_.silenceThreshold = AUDIO_BUFFER_SIZE;
    captureAttr_.channelCount = param.comParam.channelMask;
    captureAttr_.sampleRate = param.comParam.sampleRate;
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
            0,
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

int32_t DMicClient::HdfClientSetUp()
{
    if (InitHDFAudioDevice() != DH_SUCCESS) {
        DHLOGE("Init hdf audio device failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    GenerateAttr(audioParam_);

    if (audioAdapter_ == nullptr) {
        DHLOGE("audio adapter is null");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = audioAdapter_->CreateCapture(audioAdapter_, &captureDesc_, &captureAttr_,
        &hdfCapture_, &captureId_);
    if (ret != DH_SUCCESS || hdfCapture_ == nullptr) {
        DHLOGE("CreateCapture failed, ret: %d.", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    micInUse_ = true;
    DHLOGI("Create hdf audio capture success");
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

int32_t DMicClient::HdfClientRelease()
{
    DHLOGI("Release hdf mic client.");
    if (audioAdapter_ != nullptr) {
        audioAdapter_->DestroyCapture(audioAdapter_, captureId_);
    }
    IAudioCaptureRelease(hdfCapture_, false);
    hdfCapture_ = nullptr;
    micInUse_ = false;
    ReleaseHDFAudioDevice();
    DHLOGI("Release hdf audio capture success.");
    return TransRelease();
}

int32_t DMicClient::TransRelease()
{
    if (micTrans_ == nullptr) {
        DHLOGE("Mic trans is nullptr.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (micTrans_->Release() != DH_SUCCESS) {
        DHLOGE("Mic trans release failed.");
    }
    micTrans_ = nullptr;
    clientStatus_ = AudioStatus::STATUS_IDLE;
    return DH_SUCCESS;
}

int32_t DMicClient::HdfClientStartCapture()
{
    if (hdfCapture_ == nullptr) {
        DHLOGE("Audio capturer is nullptr, can not start.");
        return ERR_DH_AUDIO_FAILED;
    }
    hdfCapture_->Start(hdfCapture_);
    DHLOGI("Start hdf capture success.");
    return DH_SUCCESS;
}

void DMicClient::HdfCaptureAudioData(uint32_t lengthPerCapture, const uint32_t lengthPerTrans,
    const uint32_t len)
{
    auto audioData = std::make_shared<AudioData>(lengthPerCapture);
    uint64_t size = 0;
    if (hdfCapture_ == nullptr) {
        DHLOGE("hdf capture is nullptr.");
        return;
    }
    hdfCapture_->CaptureFrame(hdfCapture_, reinterpret_cast<int8_t *>(audioData->Data()),
        &lengthPerCapture, &size);
    DHLOGD("CaptureFrame success, framesize: %d", lengthPerCapture);

    for (uint32_t i = 0; i < len; i++) {
        std::shared_ptr<AudioData> data = std::make_shared<AudioData>(lengthPerTrans);
        if (memcpy_s(data->Data(), lengthPerTrans, audioData->Data() + lengthPerTrans * i,
            lengthPerTrans) != EOK) {
            DHLOGE("Copy audio data %d failed.", i);
        }
        int32_t ret = micTrans_->FeedAudioData(data);
        if (ret != DH_SUCCESS) {
            DHLOGE("Failed to send data %d.", i);
        }
    }
}

int32_t DMicClient::SetUp(const AudioParam &param)
{
    DHLOGI("Set up mic client, param: {sampleRate: %d, bitFormat: %d," +
        "channelMask: %d, sourceType: %d, capturerFlags: %d, frameSize: %d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.captureOpts.sourceType,
        param.captureOpts.capturerFlags, param.comParam.frameSize);
    audioParam_ = param;
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        return HdfClientSetUp();
    }
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
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        return HdfClientRelease();
    }
    if (audioCapturer_ == nullptr || !audioCapturer_->Release()) {
        DHLOGE("Audio capturer release failed.");
    }
    return TransRelease();
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
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        HdfClientStartCapture();
    } else {
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
    if (DaudioSinkHidumper::GetInstance().GetFlagStatus()) {
        SaveFile(FILE_NAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
    }
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
    uint32_t lengthPerCapture;
    uint32_t lengthPerTrans;
    uint32_t len;
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        lengthPerCapture = (audioParam_.comParam.sampleRate * audioParam_.comParam.bitFormat *
            FORMATNUM * audioParam_.comParam.channelMask) / FRAME_PER_SECOND;
        lengthPerTrans = audioParam_.comParam.frameSize;
        len = lengthPerCapture / lengthPerTrans;
    }
    while (isCaptureReady_.load()) {
        if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
            DHLOGD("Capture frameIndex: %lld.", frameIndex_);
            HdfCaptureAudioData(lengthPerCapture, lengthPerTrans, len);
            ++frameIndex_;
        } else {
            AudioFwkCaptureData();
        }
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
    if (audioParam_.captureOpts.capturerFlags == MMAP_MODE) {
        if (hdfCapture_ != nullptr) {
            hdfCapture_->Stop(hdfCapture_);
        }
    } else {
        if (audioCapturer_ == nullptr || !audioCapturer_->Stop()) {
            DHLOGE("Audio capturer stop failed.");
            status = false;
        }
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
