/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dmic_dev.h"

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hidumper.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_source_manager.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DMicDev"

namespace OHOS {
namespace DistributedHardware {
static constexpr size_t DATA_QUEUE_EXT_SIZE = 20;
void DMicDev::OnEngineTransEvent(const AVTransEvent &event)
{
    if (event.type == EventType::EVENT_START_SUCCESS) {
        OnStateChange(DATA_OPENED);
    } else if ((event.type == EventType::EVENT_STOP_SUCCESS) ||
        (event.type == EventType::EVENT_CHANNEL_CLOSED) ||
        (event.type == EventType::EVENT_START_FAIL)) {
        OnStateChange(DATA_CLOSED);
    }
}

void DMicDev::OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    DHLOGI("On Engine message, type : %{public}s.", GetEventNameByType(message->type_).c_str());
    DAudioSourceManager::GetInstance().HandleDAudioNotify(message->dstDevId_, message->dstDevId_,
        message->type_, message->content_);
}

void DMicDev::OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGD("On Engine Data available");
    OnDecodeTransDataDone(audioData);
}

int32_t DMicDev::InitReceiverEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    if (micTrans_ == nullptr) {
        micTrans_ = std::make_shared<AVTransReceiverTransport>(devId_, shared_from_this());
    }
    int32_t ret = micTrans_->InitEngine(providerPtr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic dev initialize av receiver adapter failed.");
        return ret;
    }
    ret = micTrans_->CreateCtrl();
    if (ret != DH_SUCCESS) {
        DHLOGE("Create ctrl channel failed. micdev");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DMicDev::InitSenderEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    return DH_SUCCESS;
}

int32_t DMicDev::EnableDevice(const int32_t dhId, const std::string &capability)
{
    DHLOGI("Enable IO device, device pin: %{public}d.", dhId);
    int32_t ret = DAudioHdiHandler::GetInstance().RegisterAudioDevice(devId_, dhId, capability, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Register device failed, ret: %{public}d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_REGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio register device failed.");
        return ret;
    }
    dhId_ = dhId;
    return DH_SUCCESS;
}

int32_t DMicDev::DisableDevice(const int32_t dhId)
{
    DHLOGI("Disable IO device, device pin: %{public}d.", dhId);
    int32_t ret = DAudioHdiHandler::GetInstance().UnRegisterAudioDevice(devId_, dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("UnRegister failed, ret: %{public}d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_UNREGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio unregister device failed.");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DMicDev::CreateStream(const int32_t streamId)
{
    DHLOGI("Open stream of mic device streamId: %{public}d.", streamId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        cJSON_Delete(jParam);
        DHLOGE("Failed to create JSON data.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string jsonDataStr(jsonData);
    AudioEvent event(AudioEventType::OPEN_MIC, jsonDataStr);
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_OPEN, devId_, std::to_string(dhId_),
        "daudio mic device open success.");
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    return DH_SUCCESS;
}

int32_t DMicDev::DestroyStream(const int32_t streamId)
{
    DHLOGI("Close stream of mic device streamId: %{public}d.", streamId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        cJSON_Delete(jParam);
        DHLOGE("Failed to create JSON data.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string jsonDataStr(jsonData);
    AudioEvent event(AudioEventType::CLOSE_MIC, jsonDataStr);
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_CLOSE, devId_, std::to_string(dhId_),
        "daudio mic device close success.");
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    curPort_ = 0;
    return DH_SUCCESS;
}

int32_t DMicDev::SetParameters(const int32_t streamId, const AudioParamHDF &param)
{
    DHLOGD("Set mic parameters {samplerate: %{public}d, channelmask: %{public}d, format: %{public}d, "
        "period: %{public}d, framesize: %{public}d, ext{%{public}s}}.", param.sampleRate,
        param.channelMask, param.bitFormat, param.period, param.frameSize, param.ext.c_str());
    curPort_ = dhId_;
    paramHDF_ = param;

    param_.comParam.sampleRate = paramHDF_.sampleRate;
    param_.comParam.channelMask = paramHDF_.channelMask;
    param_.comParam.bitFormat = paramHDF_.bitFormat;
    param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    param_.comParam.frameSize = paramHDF_.frameSize;
    if (paramHDF_.streamUsage == StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION) {
        param_.captureOpts.sourceType = SOURCE_TYPE_VOICE_COMMUNICATION;
    } else {
        param_.captureOpts.sourceType = SOURCE_TYPE_MIC;
    }
    param_.captureOpts.capturerFlags = paramHDF_.capturerFlags;
    return DH_SUCCESS;
}

int32_t DMicDev::NotifyEvent(const int32_t streamId, const AudioEvent &event)
{
    DHLOGD("Notify mic event, type: %{public}d.", event.type);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);
    switch (event.type) {
        case AudioEventType::AUDIO_START:
            curStatus_ = AudioStatus::STATUS_START;
            isExistedEmpty_.store(false);
            break;
        case AudioEventType::AUDIO_STOP:
            curStatus_ = AudioStatus::STATUS_STOP;
            isExistedEmpty_.store(false);
            break;
        default:
            break;
    }
    AudioEvent audioEvent(event.type, event.content);
    cbObj->NotifyEvent(audioEvent);
    return DH_SUCCESS;
}

int32_t DMicDev::SetUp()
{
    DHLOGI("Set up mic device.");
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = micTrans_->SetUp(param_, param_, shared_from_this(), CAP_MIC);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans set up failed. ret: %{public}d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DMicDev::Start()
{
    DHLOGI("Start mic device.");
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = micTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic trans start failed, ret: %{public}d.", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lck(channelWaitMutex_);
    auto status = channelWaitCond_.wait_for(lck, std::chrono::seconds(CHANNEL_WAIT_SECONDS),
        [this]() { return isTransReady_.load(); });
    if (!status) {
        DHLOGE("Wait channel open timeout(%{public}ds).", CHANNEL_WAIT_SECONDS);
        return ERR_DH_AUDIO_SA_WAIT_TIMEOUT;
    }
    isOpened_.store(true);
    return DH_SUCCESS;
}

int32_t DMicDev::Pause()
{
    DHLOGI("Not support.");
    return DH_SUCCESS;
}

int32_t DMicDev::Restart()
{
    DHLOGI("Not surpport.");
    return DH_SUCCESS;
}

int32_t DMicDev::Stop()
{
    DHLOGI("Stop mic device.");
    CHECK_NULL_RETURN(micTrans_, DH_SUCCESS);
    isOpened_.store(false);
    isTransReady_.store(false);
    int32_t ret = micTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop mic trans failed, ret: %{public}d.", ret);
    }
    return DH_SUCCESS;
}

int32_t DMicDev::Release()
{
    DHLOGI("Release mic device.");
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
        DHLOGI("UnInit ashmem success.");
    }
    CHECK_NULL_RETURN(micTrans_, DH_SUCCESS);

    int32_t ret = micTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release mic trans failed, ret: %{public}d.", ret);
        return ret;
    }
    dumpFlag_.store(false);
    return DH_SUCCESS;
}

bool DMicDev::IsOpened()
{
    return isOpened_.load();
}

int32_t DMicDev::WriteStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data)
{
    (void)streamId;
    (void)data;
    return DH_SUCCESS;
}

int32_t DMicDev::ReadStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data)
{
    int64_t startTime = GetNowTimeUs();
    if (curStatus_ != AudioStatus::STATUS_START) {
        DHLOGE("Distributed audio is not starting status.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    uint32_t queSize = dataQueue_.size();
    if (insertFrameCnt_ >= queSize || queSize == 0) {
        ++insertFrameCnt_;
        isExistedEmpty_.store(true);
        DHLOGD("Data queue is empty, count :%{public}u.", insertFrameCnt_);
        data = std::make_shared<AudioData>(param_.comParam.frameSize);
    } else {
        while (insertFrameCnt_ > 0) {
            DHLOGD("Data discard, count: %{public}u", insertFrameCnt_);
            dataQueue_.pop();
            --insertFrameCnt_;
        }
        data = dataQueue_.front();
        dataQueue_.pop();
    }
#ifdef DUMP_DMICDEV_FILE
    if (DaudioHidumper::GetInstance().QueryDumpDataFlag()) {
        if (!dumpFlag_) {
            AudioEvent event(NOTIFY_HDF_MIC_DUMP, "");
            NotifyHdfAudioEvent(event, dhId_);
            dumpFlag_.store(true);
        }
        SaveFile(MIC_DEV_FILENAME, const_cast<uint8_t*>(data->Data()), data->Size());
    }
#endif
    int64_t endTime = GetNowTimeUs();
    if (IsOutDurationRange(startTime, endTime, lastReadStartTime_)) {
        DHLOGE("This time read data spend: %{public}" PRId64" us, The interval of read data this time and "
            "the last time: %{public}" PRId64" us", endTime - startTime, startTime - lastReadStartTime_);
    }
    lastReadStartTime_ = startTime;
    return DH_SUCCESS;
}

int32_t DMicDev::ReadMmapPosition(const int32_t streamId, uint64_t &frames, CurrentTimeHDF &time)
{
    DHLOGD("Read mmap position. frames: %{public}" PRIu64", tvsec: %{public}" PRId64", tvNSec:%{public}" PRId64,
        writeNum_, writeTvSec_, writeTvNSec_);
    frames = writeNum_;
    time.tvSec = writeTvSec_;
    time.tvNSec = writeTvNSec_;
    return DH_SUCCESS;
}

int32_t DMicDev::RefreshAshmemInfo(const int32_t streamId,
    int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans)
{
    DHLOGD("RefreshAshmemInfo: fd:%{public}d, ashmemLength: %{public}d, lengthPerTrans: %{public}d",
        fd, ashmemLength, lengthPerTrans);
    if (param_.captureOpts.capturerFlags == MMAP_MODE) {
        DHLOGD("DMic dev low-latency mode");
        if (ashmem_ != nullptr) {
            return DH_SUCCESS;
        }
        ashmem_ = new Ashmem(fd, ashmemLength);
        ashmemLength_ = ashmemLength;
        lengthPerTrans_ = lengthPerTrans;
        DHLOGD("Create ashmem success. fd:%{public}d, ashmem length: %{public}d, lengthPreTrans: %{public}d",
            fd, ashmemLength_, lengthPerTrans_);
        bool mapRet = ashmem_->MapReadAndWriteAshmem();
        if (!mapRet) {
            DHLOGE("Mmap ashmem failed.");
            return ERR_DH_AUDIO_NULLPTR;
        }
    }
    return DH_SUCCESS;
}

int32_t DMicDev::MmapStart()
{
    CHECK_NULL_RETURN(ashmem_, ERR_DH_AUDIO_NULLPTR);
    std::lock_guard<std::mutex> lock(writeAshmemMutex_);
    frameIndex_ = 0;
    startTime_ = 0;
    isEnqueueRunning_.store(true);
    enqueueDataThread_ = std::thread(&DMicDev::EnqueueThread, this);
    if (pthread_setname_np(enqueueDataThread_.native_handle(), ENQUEUE_THREAD) != DH_SUCCESS) {
        DHLOGE("Enqueue data thread setname failed.");
    }
    return DH_SUCCESS;
}

void DMicDev::EnqueueThread()
{
    writeIndex_ = 0;
    writeNum_ = 0;
    int64_t timeIntervalns = static_cast<int64_t>(paramHDF_.period * AUDIO_NS_PER_SECOND / AUDIO_MS_PER_SECOND);
    DHLOGD("Enqueue thread start, lengthPerWrite length: %{public}d, interval: %{public}d.", lengthPerTrans_,
        paramHDF_.period);
    FillJitterQueue();
    while (ashmem_ != nullptr && isEnqueueRunning_.load()) {
        int64_t timeOffset = UpdateTimeOffset(frameIndex_, timeIntervalns, startTime_);
        DHLOGD("Write frameIndex: %{public}" PRId64", timeOffset: %{public}" PRId64, frameIndex_, timeOffset);
        std::shared_ptr<AudioData> audioData = nullptr;
        {
            std::lock_guard<std::mutex> lock(dataQueueMtx_);
            if (dataQueue_.empty()) {
                DHLOGD("Data queue is Empty.");
                audioData = std::make_shared<AudioData>(param_.comParam.frameSize);
            } else {
                audioData = dataQueue_.front();
                dataQueue_.pop();
            }
        }
#ifdef DUMP_DMICDEV_FILE
    if (DaudioHidumper::GetInstance().QueryDumpDataFlag()) {
        SaveFile(MIC_LOWLATENCY_FILENAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
    }
#endif
        bool writeRet = ashmem_->WriteToAshmem(audioData->Data(), audioData->Size(), writeIndex_);
        if (writeRet) {
            DHLOGD("Write to ashmem success! write index: %{public}d, writeLength: %{public}d.",
                writeIndex_, lengthPerTrans_);
        } else {
            DHLOGE("Write data to ashmem failed.");
        }
        writeIndex_ += lengthPerTrans_;
        if (writeIndex_ >= ashmemLength_) {
            writeIndex_ = 0;
        }
        writeNum_ += static_cast<uint64_t>(CalculateSampleNum(param_.comParam.sampleRate, paramHDF_.period));
        GetCurrentTime(writeTvSec_, writeTvNSec_);
        frameIndex_++;
        AbsoluteSleep(startTime_ + frameIndex_ * timeIntervalns - timeOffset);
    }
}

void DMicDev::FillJitterQueue()
{
    while (isEnqueueRunning_.load()) {
        {
            std::lock_guard<std::mutex> lock(dataQueueMtx_);
            if (dataQueue_.size() >= (LOW_LATENCY_JITTER_TIME_MS / paramHDF_.period)) {
                break;
            }
        }
        usleep(MMAP_WAIT_FRAME_US);
    }
    DHLOGD("Mic jitter data queue fill end.");
}

int32_t DMicDev::MmapStop()
{
    std::lock_guard<std::mutex> lock(writeAshmemMutex_);
    isEnqueueRunning_.store(false);
    if (enqueueDataThread_.joinable()) {
        enqueueDataThread_.join();
    }
    DHLOGI("Mic mmap stop end.");
    return DH_SUCCESS;
}

AudioParam DMicDev::GetAudioParam() const
{
    return param_;
}

int32_t DMicDev::NotifyHdfAudioEvent(const AudioEvent &event, const int32_t portId)
{
    int32_t ret = DAudioHdiHandler::GetInstance().NotifyEvent(devId_, portId, 0, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify event: %{public}d, result: %{public}s.", event.type, event.content.c_str());
    }
    return DH_SUCCESS;
}

int32_t DMicDev::OnStateChange(const AudioEventType type)
{
    DHLOGD("On mic device state change, type: %{public}d", type);
    AudioEvent event;
    switch (type) {
        case AudioEventType::DATA_OPENED:
            isTransReady_.store(true);
            channelWaitCond_.notify_one();
            event.type = AudioEventType::MIC_OPENED;
            break;
        case AudioEventType::DATA_CLOSED:
            isTransReady_.store(false);
            event.type = AudioEventType::MIC_CLOSED;
            break;
        default:
            break;
    }
    event.content = GetCJsonString(KEY_DH_ID, std::to_string(dhId_).c_str());
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);
    cbObj->NotifyEvent(event);
    return DH_SUCCESS;
}

int32_t DMicDev::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote.");
    if (type != static_cast<uint32_t>(OPEN_MIC) && type != static_cast<uint32_t>(CLOSE_MIC)) {
        DHLOGE("Send message to remote. not OPEN_MIC or CLOSE_MIC. type: %{public}u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
    micTrans_->SendMessage(type, content, dstDevId);
    return DH_SUCCESS;
}

int32_t DMicDev::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    CHECK_NULL_RETURN(audioData, ERR_DH_AUDIO_NULLPTR);
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    dataQueSize_ = curStatus_ != AudioStatus::STATUS_START ?
        (param_.captureOpts.capturerFlags == MMAP_MODE ? LOW_LATENCY_DATA_QUEUE_HALF_SIZE : DATA_QUEUE_HALF_SIZE) :
        (param_.captureOpts.capturerFlags == MMAP_MODE ? LOW_LATENCY_DATA_QUEUE_MAX_SIZE : DATA_QUEUE_MAX_SIZE);
    if (isExistedEmpty_.load()) {
        dataQueSize_ = param_.captureOpts.capturerFlags == MMAP_MODE ? dataQueSize_ : DATA_QUEUE_EXT_SIZE;
    }
    uint64_t queueSize;
    while (dataQueue_.size() > dataQueSize_) {
        queueSize = static_cast<uint64_t>(dataQueue_.size());
        DHLOGD("Data queue overflow. buf current size: %{public}" PRIu64, queueSize);
        dataQueue_.pop();
    }
    dataQueue_.push(audioData);
    queueSize = static_cast<uint64_t>(dataQueue_.size());
    DHLOGD("Push new mic data, buf len: %{public}" PRIu64, queueSize);
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
