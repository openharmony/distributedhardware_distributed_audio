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

#include "dspeaker_dev.h"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <securec.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hidumper.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_source_manager.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DSpeakerDev"

namespace OHOS {
namespace DistributedHardware {
int32_t DSpeakerDev::EnableDevice(const int32_t dhId, const std::string &capability)
{
    DHLOGI("Enable IO device, device pin: %d.", dhId);
    int32_t ret = DAudioHdiHandler::GetInstance().RegisterAudioDevice(devId_, dhId, capability, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Register device failed, ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_REGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio register device failed.");
        return ret;
    }
    dhId_ = dhId;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::DisableDevice(const int32_t dhId)
{
    DHLOGI("Disable IO device, device pin: %d.", dhId);
    int32_t ret = DAudioHdiHandler::GetInstance().UnRegisterAudioDevice(devId_, dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("UnRegister failed, ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_UNREGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio unregister device failed.");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::InitReceiverEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::InitSenderEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitSenderEngine enter");
    if (speakerTrans_ == nullptr) {
        speakerTrans_ = std::make_shared<AVTransSenderTransport>(devId_, shared_from_this());
    }
    int32_t ret = speakerTrans_->InitEngine(providerPtr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker dev initialize av sender adapter failed.");
        return ret;
    }
    ret = speakerTrans_->CreateCtrl();
    if (ret != DH_SUCCESS) {
        DHLOGE("Create ctrl channel failed.");
    }
    return ret;
}

void DSpeakerDev::OnEngineTransEvent(const AVTransEvent &event)
{
    if (event.type == EventType::EVENT_START_SUCCESS) {
        OnStateChange(DATA_OPENED);
    } else if ((event.type == EventType::EVENT_STOP_SUCCESS) ||
        (event.type == EventType::EVENT_CHANNEL_CLOSED) ||
        (event.type == EventType::EVENT_START_FAIL)) {
        OnStateChange(DATA_CLOSED);
    }
}

void DSpeakerDev::OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    DHLOGI("On Engine message, type : %s.", GetEventNameByType(message->type_).c_str());
    DAudioSourceManager::GetInstance().HandleDAudioNotify(message->dstDevId_, message->dstDevId_,
        message->type_, message->content_);
}

int32_t DSpeakerDev::OpenDevice(const std::string &devId, const int32_t dhId)
{
    DHLOGI("Open speaker device devId: %s, dhId: %d.", GetAnonyString(devId).c_str(), dhId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string jsonDataStr(jsonData);
    AudioEvent event(AudioEventType::OPEN_SPEAKER, jsonDataStr);
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_OPEN, devId, std::to_string(dhId),
        "daudio spk device open success.");
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::CloseDevice(const std::string &devId, const int32_t dhId)
{
    DHLOGI("Close speaker device devId: %s, dhId: %d.", GetAnonyString(devId).c_str(), dhId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string jsonDataStr(jsonData);
    AudioEvent event(AudioEventType::OPEN_SPEAKER, jsonDataStr);
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_CLOSE, devId, std::to_string(dhId),
        "daudio spk device close success.");
    curPort_ = 0;
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param)
{
    DHLOGD("Set speaker parameters {samplerate: %d, channelmask: %d, format: %d, streamusage: %d, period: %d, "
        "framesize: %d, renderFlags: %d, ext{%s}}.",
        param.sampleRate, param.channelMask, param.bitFormat, param.streamUsage, param.period, param.frameSize,
        param.renderFlags, param.ext.c_str());
    curPort_ = dhId;
    paramHDF_ = param;

    param_.comParam.sampleRate = paramHDF_.sampleRate;
    param_.comParam.channelMask = paramHDF_.channelMask;
    param_.comParam.bitFormat = paramHDF_.bitFormat;
    param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    param_.comParam.frameSize = paramHDF_.frameSize;
    param_.renderOpts.contentType = CONTENT_TYPE_MUSIC;
    param_.renderOpts.renderFlags = paramHDF_.renderFlags;
    param_.renderOpts.streamUsage = paramHDF_.streamUsage;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::NotifyEvent(const std::string &devId, int32_t dhId, const AudioEvent &event)
{
    DHLOGD("Notify speaker event.");
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_NULLPTR);
    AudioEvent audioEvent(event.type, event.content);
    cbObj->NotifyEvent(audioEvent);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::SetUp()
{
    DHLOGI("Set up speaker device.");
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);

    int32_t ret = speakerTrans_->SetUp(param_, param_, shared_from_this(), CAP_SPK);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans set up failed. ret:%d", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Start()
{
    DHLOGI("Start speaker device.");
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speakerTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans start failed, ret: %d.", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lck(channelWaitMutex_);
    auto status = channelWaitCond_.wait_for(lck, std::chrono::seconds(CHANNEL_WAIT_SECONDS),
        [this]() { return isTransReady_.load(); });
    if (!status) {
        DHLOGE("Wait channel open timeout(%ds).", CHANNEL_WAIT_SECONDS);
        return ERR_DH_AUDIO_SA_WAIT_TIMEOUT;
    }
    isOpened_.store(true);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Stop()
{
    DHLOGI("Stop speaker device.");
    CHECK_NULL_RETURN(speakerTrans_, DH_SUCCESS);
    isOpened_.store(false);
    isTransReady_.store(false);
    int32_t ret = speakerTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker trans failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Release()
{
    DHLOGI("Release speaker device.");
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
        DHLOGI("UnInit ashmem success.");
    }
    CHECK_NULL_RETURN(speakerTrans_, DH_SUCCESS);
    int32_t ret = speakerTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker trans failed, ret: %d.", ret);
    }
    dumpFlag_.store(false);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Pause()
{
    DHLOGI("Pause.");
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speakerTrans_->Pause();
    if (ret != DH_SUCCESS) {
        DHLOGE("Pause speaker trans failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Pause success.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Restart()
{
    DHLOGI("Restart.");
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speakerTrans_->Restart(param_, param_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Restart speaker trans failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Restart success.");
    return DH_SUCCESS;
}

bool DSpeakerDev::IsOpened()
{
    return isOpened_.load();
}

int32_t DSpeakerDev::ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data)
{
    (void)devId;
    (void)dhId;
    (void)data;
    DHLOGI("Dspeaker dev not support read stream data.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data)
{
    DHLOGD("Write stream data, dhId:%d", dhId);
    int64_t startTime = GetNowTimeUs();
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
#ifdef DUMP_DSPEAKERDEV_FILE
    if (DaudioHidumper::GetInstance().QueryDumpDataFlag()) {
        if (!dumpFlag_) {
            AudioEvent event(NOTIFY_HDF_SPK_DUMP, "");
            NotifyHdfAudioEvent(event, dhId);
            dumpFlag_.store(true);
        }
        SaveFile(SPK_DEV_FILENAME, const_cast<uint8_t*>(data->Data()), data->Size());
    }
#endif
    int32_t ret = speakerTrans_->FeedAudioData(data);
    if (ret != DH_SUCCESS) {
        DHLOGE("Write stream data failed, ret: %d.", ret);
        return ret;
    }
    int64_t endTime = GetNowTimeUs();
    if (IsOutDurationRange(startTime, endTime, lastwriteStartTime_)) {
        DHLOGE("This time write data spend: %lld us, The interval of write data this time and the last time: %lld us",
            endTime - startTime, startTime - lastwriteStartTime_);
    }
    lastwriteStartTime_ = startTime;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::ReadMmapPosition(const std::string &devId, const int32_t dhId,
    uint64_t &frames, CurrentTimeHDF &time)
{
    DHLOGD("Read mmap position. frames: %lu, tvsec: %lu, tvNSec:%lu",
        readNum_, readTvSec_, readTvNSec_);
    frames = readNum_;
    time.tvSec = readTvSec_;
    time.tvNSec = readTvNSec_;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::RefreshAshmemInfo(const std::string &devId, const int32_t dhId,
    int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans)
{
    DHLOGD("RefreshAshmemInfo: fd:%d, ashmemLength: %d, lengthPerTrans: %d", fd, ashmemLength, lengthPerTrans);
    if (param_.renderOpts.renderFlags == MMAP_MODE) {
        DHLOGI("DSpeaker dev low-latency mode");
        if (ashmem_ != nullptr) {
            return DH_SUCCESS;
        }
        ashmem_ = new Ashmem(fd, ashmemLength);
        ashmemLength_ = ashmemLength;
        lengthPerTrans_ = lengthPerTrans;
        DHLOGI("Create ashmem success. fd:%d, ashmem length: %d, lengthPreTrans: %d",
            fd, ashmemLength_, lengthPerTrans_);
        bool mapRet = ashmem_->MapReadAndWriteAshmem();
        if (!mapRet) {
            DHLOGE("Mmap ashmem failed.");
            return ERR_DH_AUDIO_NULLPTR;
        }
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::MmapStart()
{
    CHECK_NULL_RETURN(ashmem_, ERR_DH_AUDIO_NULLPTR);
    isEnqueueRunning_.store(true);
    enqueueDataThread_ = std::thread(&DSpeakerDev::EnqueueThread, this);
    if (pthread_setname_np(enqueueDataThread_.native_handle(), ENQUEUE_THREAD) != DH_SUCCESS) {
        DHLOGE("Enqueue data thread setname failed.");
    }
    return DH_SUCCESS;
}

void DSpeakerDev::EnqueueThread()
{
    readIndex_ = 0;
    readNum_ = 0;
    frameIndex_ = 0;
    DHLOGI("Enqueue thread start, lengthPerRead length: %d.", lengthPerTrans_);
    while (ashmem_ != nullptr && isEnqueueRunning_.load()) {
        int64_t timeOffset = UpdateTimeOffset(frameIndex_, LOW_LATENCY_INTERVAL_NS,
            startTime_);
        DHLOGD("Read frameIndex: %lld, timeOffset: %lld.", frameIndex_, timeOffset);
        auto readData = ashmem_->ReadFromAshmem(lengthPerTrans_, readIndex_);
        DHLOGI("Read from ashmem success! read index: %d, readLength: %d.", readIndex_, lengthPerTrans_);
        std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(lengthPerTrans_);
        if (readData != nullptr) {
            const uint8_t *readAudioData = reinterpret_cast<const uint8_t *>(readData);
            if (memcpy_s(audioData->Data(), audioData->Capacity(), readAudioData, param_.comParam.frameSize) != EOK) {
                DHLOGE("Copy audio data failed.");
            }
        }
        CHECK_NULL_VOID(speakerTrans_);
#ifdef DUMP_DSPEAKERDEV_FILE
    if (DaudioHidumper::GetInstance().QueryDumpDataFlag()) {
        SaveFile(SPK_LOWLATENCY_FILENAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
    }
#endif
        int32_t ret = speakerTrans_->FeedAudioData(audioData);
        if (ret != DH_SUCCESS) {
            DHLOGE("Speaker enqueue thread, write stream data failed, ret: %d.", ret);
        }
        readIndex_ += lengthPerTrans_;
        if (readIndex_ >= ashmemLength_) {
            readIndex_ = 0;
        }
        readNum_ += static_cast<uint64_t>(CalculateSampleNum(param_.comParam.sampleRate, timeInterval_));
        GetCurrentTime(readTvSec_, readTvNSec_);
        frameIndex_++;
        AbsoluteSleep(startTime_ + frameIndex_ * LOW_LATENCY_INTERVAL_NS - timeOffset);
    }
}

int32_t DSpeakerDev::MmapStop()
{
    isEnqueueRunning_.store(false);
    if (enqueueDataThread_.joinable()) {
        enqueueDataThread_.join();
    }
    DHLOGI("Spk mmap stop end.");
    return DH_SUCCESS;
}

AudioParam DSpeakerDev::GetAudioParam() const
{
    return param_;
}

int32_t DSpeakerDev::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote.");
    if (type != static_cast<uint32_t>(OPEN_SPEAKER) && type != static_cast<uint32_t>(CLOSE_SPEAKER) &&
        type != static_cast<uint32_t>(CHANGE_PLAY_STATUS) && type != static_cast<uint32_t>(VOLUME_SET) &&
        type != static_cast<uint32_t>(VOLUME_MUTE_SET)) {
        DHLOGE("Send message to remote. not OPEN_SPK or CLOSE_SPK. type: %u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
    speakerTrans_->SendMessage(type, content, dstDevId);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::NotifyHdfAudioEvent(const AudioEvent &event, const int32_t portId)
{
    int32_t ret = DAudioHdiHandler::GetInstance().NotifyEvent(devId_, portId, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify event: %d, result: %s.", event.type, event.content.c_str());
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::OnStateChange(const AudioEventType type)
{
    DHLOGI("On speaker device state change, type: %d.", type);
    AudioEvent event;
    switch (type) {
        case AudioEventType::DATA_OPENED:
            isTransReady_.store(true);
            channelWaitCond_.notify_all();
            event.type = AudioEventType::SPEAKER_OPENED;
            break;
        case AudioEventType::DATA_CLOSED:
            isOpened_.store(false);
            isTransReady_.store(false);
            event.type = AudioEventType::SPEAKER_CLOSED;
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

int32_t DSpeakerDev::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    (void) audioData;
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
