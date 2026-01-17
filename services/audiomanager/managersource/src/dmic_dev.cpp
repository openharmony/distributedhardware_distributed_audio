/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <ctime>
#include <mutex>
#include <string>
#include <thread>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hidumper.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_radar.h"
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
    std::lock_guard<std::mutex> lock(ringbufferMutex_);
    CHECK_NULL_VOID(ringBuffer_);
    CHECK_NULL_VOID(audioData);
    CHECK_AND_RETURN_LOG(ringBuffer_->RingBufferInsert(audioData->Data(),
        static_cast<int32_t>(audioData->Capacity())) != DH_SUCCESS, "RingBufferInsert failed.");
    DHLOGD("Ringbuffer insert one");
    int64_t timestamp = audioData->GetPts();
    std::lock_guard<std::mutex> timeLock(ptsMutex_);
    ptsMap_[frameInIndex_] = timestamp;
    frameInIndex_++;
    if (frameInIndex_ == indexFlag_) {
        timestamp = audioData->GetPtsSpecial();
        ptsMap_[frameInIndex_] = timestamp;
        DHLOGD("audioData->GetPtsSpecial(): %{public}" PRId64", index: %{public}" PRIu64, timestamp, frameInIndex_);
        frameInIndex_ = 0;
    }
}

void DMicDev::ReadFromRingbuffer()
{
    std::shared_ptr<AudioData> sendData = std::make_shared<AudioData>(frameSize_);
    bool canRead = false;
    while (isRingbufferOn_.load()) {
        CHECK_NULL_VOID(ringBuffer_);
        canRead = false;
        {
            std::lock_guard<std::mutex> lock(ringbufferMutex_);
            if (ringBuffer_->CanBufferReadLen(frameSize_)) {
                canRead = true;
            }
        }
        if (!canRead) {
            DHLOGD("Can not read from ringbuffer.");
            std::this_thread::sleep_for(std::chrono::milliseconds(RINGBUFFER_WAIT_SECONDS));
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(ringbufferMutex_);
            if (ringBuffer_->RingBufferGetData(sendData->Data(), sendData->Capacity()) != DH_SUCCESS) {
                DHLOGE("Read ringbuffer failed.");
                continue;
            }
        }
        SendToProcess(sendData);
    }
}

void DMicDev::SendToProcess(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGD("On Engine Data available");
    CHECK_NULL_VOID(audioData);
    int64_t pts = 0;
    {
        std::lock_guard<std::mutex> lock(ptsMutex_);
        auto iter = ptsMap_.find(frameOutIndex_);
        if (iter != ptsMap_.end()) {
            pts = iter->second;
            audioData->SetPts(pts);
            ptsMap_.erase(iter);
        } else {
            DHLOGI("iter == ptsMap_.end()");
        }
        frameOutIndex_++;
        if (frameOutIndex_ == frameOutIndexFlag_) {
            frameOutIndex_ = 0;
        }
    }
    DHLOGD("Set timestamp %{public}" PRId64 " for frame index %{public}" PRIu64, audioData->GetPts(), frameOutIndex_);
    framnum_++;
    DHLOGD("current frame index: %{public}" PRIu64, framnum_);
    if (echoCannelOn_) {
#ifdef ECHO_CANNEL_ENABLE
        CHECK_NULL_VOID(echoManager_);
        echoManager_->OnMicDataReceived(audioData);
#endif
    } else {
        OnDecodeTransDataDone(audioData);
    }
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
    return DH_SUCCESS;
}

int32_t DMicDev::InitSenderEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    return DH_SUCCESS;
}

int32_t DMicDev::InitCtrlTrans()
{
    DHLOGI("InitCtrlTrans enter");
    if (micCtrlTrans_ == nullptr) {
        micCtrlTrans_ = std::make_shared<DaudioSourceCtrlTrans>(devId_,
            SESSIONNAME_MIC_SOURCE, SESSIONNAME_MIC_SINK, shared_from_this());
    }
    int32_t ret = micCtrlTrans_->SetUp(shared_from_this());
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Mic ctrl SetUp failed.");
    ret = micCtrlTrans_->Start();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Mic ctrl Start failed.");
    return ret;
}

void DMicDev::OnCtrlTransEvent(const AVTransEvent &event)
{
    if (event.type == EventType::EVENT_START_SUCCESS) {
        OnStateChange(DATA_OPENED);
    } else if ((event.type == EventType::EVENT_STOP_SUCCESS) ||
        (event.type == EventType::EVENT_CHANNEL_CLOSED) ||
        (event.type == EventType::EVENT_START_FAIL)) {
        OnStateChange(DATA_CLOSED);
    }
}

void DMicDev::OnCtrlTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    DHLOGI("On Engine message, type : %{public}s.", GetEventNameByType(message->type_).c_str());
    DAudioSourceManager::GetInstance().HandleDAudioNotify(message->dstDevId_, message->dstDevId_,
        message->type_, message->content_);
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
    GetCodecCaps(capability);
    return DH_SUCCESS;
}

void DMicDev::AddToVec(std::vector<AudioCodecType> &container, const AudioCodecType value)
{
    auto it = std::find(container.begin(), container.end(), value);
    if (it == container.end()) {
        container.push_back(value);
    }
}

void DMicDev::GetCodecCaps(const std::string &capability)
{
    auto pos = capability.find(AAC);
    if (pos != std::string::npos) {
        AddToVec(codec_, AudioCodecType::AUDIO_CODEC_AAC_EN);
        DHLOGI("Daudio codec cap: AAC");
    }
    pos = capability.find(OPUS);
    if (pos != std::string::npos) {
        AddToVec(codec_, AudioCodecType::AUDIO_CODEC_OPUS);
        DHLOGI("Daudio codec cap: OPUS");
    }
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

bool DMicDev::IsMimeSupported(const AudioCodecType coder)
{
    auto iter = std::find(codec_.begin(), codec_.end(), coder);
    if (iter == codec_.end()) {
        DHLOGI("devices have no cap: %{public}d", static_cast<int>(coder));
        return false;
    }
    return true;
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
    streamId_ = streamId;
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DaudioRadar::GetInstance().ReportMicOpen("Start", MicOpen::CREATE_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
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
    DaudioRadar::GetInstance().ReportMicClose("DestroyStream", MicClose::DESTROY_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    return DH_SUCCESS;
}

int32_t DMicDev::SetParameters(const int32_t streamId, const AudioParamHDF &param)
{
    DHLOGD("Set mic parameters {samplerate: %{public}d, channelmask: %{public}d, format: %{public}d, "
        "period: %{public}d, framesize: %{public}d, ext{%{public}s}}.", param.sampleRate,
        param.channelMask, param.bitFormat, param.period, param.frameSize, param.ext.c_str());
    if (param.capturerFlags == MMAP_MODE && param.period != MMAP_NORMAL_PERIOD && param.period != MMAP_VOIP_PERIOD) {
        DHLOGE("The period is invalid : %{public}" PRIu32, param.period);
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    curPort_ = dhId_;
    paramHDF_ = param;

    param_.comParam.sampleRate = paramHDF_.sampleRate;
    param_.comParam.channelMask = paramHDF_.channelMask;
    param_.comParam.bitFormat = paramHDF_.bitFormat;
    param_.comParam.frameSize = paramHDF_.frameSize;
    if (paramHDF_.streamUsage == StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION) {
        param_.captureOpts.sourceType = SOURCE_TYPE_VOICE_COMMUNICATION;
    } else {
        param_.captureOpts.sourceType = SOURCE_TYPE_MIC;
    }
    param_.captureOpts.capturerFlags = paramHDF_.capturerFlags;
    if (paramHDF_.capturerFlags == MMAP_MODE) {
        lowLatencyHalfSize_ = LOW_LATENCY_JITTER_TIME_MS / paramHDF_.period;
        lowLatencyMaxfSize_ = LOW_LATENCY_JITTER_MAX_TIME_MS / paramHDF_.period;
    }
    param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    if (paramHDF_.streamUsage == StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION &&
        IsMimeSupported(AudioCodecType::AUDIO_CODEC_OPUS)) {
        param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_OPUS;
    } else if (IsMimeSupported(AudioCodecType::AUDIO_CODEC_AAC_EN)) {
        param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC_EN;
    }
    DHLOGI("codecType : %{public}d.", static_cast<int>(param_.comParam.codecType));
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
            isStartStatus_.store(true);
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
    frameSize_ = static_cast<int32_t>(param_.comParam.frameSize);
    {
        std::lock_guard<std::mutex> lock(ringbufferMutex_);
        ringBuffer_ = std::make_unique<DaudioRingBuffer>();
        ringBuffer_->RingBufferInit(frameData_);
        CHECK_NULL_RETURN(frameData_, ERR_DH_AUDIO_NULLPTR);
    }
    isRingbufferOn_.store(true);
    ringbufferThread_ = std::thread([ptr = shared_from_this()]() {
        if (!ptr) {
            return;
        }
        ptr->ReadFromRingbuffer();
    });
    echoCannelOn_ = false;
    DHLOGI("echoCannelOn_: %{public}d", echoCannelOn_);
#ifdef ECHO_CANNEL_ENABLE
    if (echoCannelOn_ && echoManager_ == nullptr) {
        echoManager_ = std::make_shared<DAudioEchoCannelManager>();
    }
    AudioCommonParam info;
    info.sampleRate = param_.comParam.sampleRate;
    info.channelMask = param_.comParam.channelMask;
    info.bitFormat = param_.comParam.bitFormat;
    info.frameSize = param_.comParam.frameSize;
    if (echoManager_ != nullptr) {
        echoManager_->SetUp(info, shared_from_this());
    }
#endif
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_MIC_READ_FROM_BUF_NAME, &dumpFileCommn_);
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_LOWLATENCY_MIC_FROM_BUF_NAME, &dumpFileFast_);
    return DH_SUCCESS;
}

int32_t DMicDev::Start()
{
    DHLOGI("Start mic device.");
    CHECK_NULL_RETURN(micTrans_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = micTrans_->Start();
    DaudioRadar::GetInstance().ReportMicOpenProgress("Start", MicOpen::TRANS_START, ret);
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
    DaudioRadar::GetInstance().ReportMicCloseProgress("Stop", MicClose::STOP_TRANS, ret);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "micTrans stop failed, ret: %{public}d.", ret);
#ifdef ECHO_CANNEL_ENABLE
    CHECK_NULL_RETURN(echoManager_, DH_SUCCESS);
    ret = echoManager_->Stop();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Echo manager stop failed, ret: %{public}d.", ret);
#endif
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
    AVsyncDeintAshmem();
    avSyncParam_.fd = -1;
    avSyncParam_.sharedMemLen = 0;
    DHLOGI("AVsync mode closed");
    {
        std::lock_guard<std::mutex> lock(dataQueueMtx_);
        dataQueue_.clear();
    }
    if (micCtrlTrans_ != nullptr) {
        int32_t res = micCtrlTrans_->Release();
        CHECK_AND_RETURN_RET_LOG(res != DH_SUCCESS, res, "Mic ctrl Release failed.");
    }
    CHECK_NULL_RETURN(micTrans_, DH_SUCCESS);
    int32_t ret = micTrans_->Release();
    DaudioRadar::GetInstance().ReportMicCloseProgress("Release", MicClose::RELEASE_TRANS, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Release mic trans failed, ret: %{public}d.", ret);
        return ret;
    }
    isRingbufferOn_.store(false);
    if (ringbufferThread_.joinable()) {
        ringbufferThread_.join();
    }
    {
        std::lock_guard<std::mutex> lock(ringbufferMutex_);
        ringBuffer_ = nullptr;
        if (frameData_ != nullptr) {
            delete[] frameData_;
            frameData_ = nullptr;
        }
    }
#ifdef ECHO_CANNEL_ENABLE
    if (echoManager_ != nullptr) {
        echoManager_->Release();
        echoManager_ = nullptr;
    }
#endif
    DumpFileUtil::CloseDumpFile(&dumpFileCommn_);
    DumpFileUtil::CloseDumpFile(&dumpFileFast_);
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

int32_t DMicDev::ReadTimeStampFromAVsync(int64_t &timePts)
{
    CHECK_AND_RETURN_RET_LOG(!IsAVsync() || avsyncAshmem_ == nullptr, DH_SUCCESS,
        "Ashmem is nullptr or IsAVsync is false.");
    auto syncData = avsyncAshmem_->ReadFromAshmem(avSyncParam_.sharedMemLen, 0);
    AVsyncShareData *readSyncShareData = reinterpret_cast<AVsyncShareData *>(const_cast<void *>(syncData));
    while (!readSyncShareData->lock && IsAVsync()) {
        DHLOGE("AVsync lock is false");
        syncData = avsyncAshmem_->ReadFromAshmem(avSyncParam_.sharedMemLen, 0);
        readSyncShareData = reinterpret_cast<AVsyncShareData *>(const_cast<void *>(syncData));
    }
    readSyncShareData->lock = 0;
    bool ret = avsyncAshmem_->WriteToAshmem(static_cast<void*>(readSyncShareData), sizeof(AVsyncShareData), 0);
    CHECK_AND_RETURN_RET_LOG(!ret, ERR_DH_AUDIO_FAILED, "Write avsync data failed.");
    timePts = static_cast<int64_t>(readSyncShareData->video_current_pts);
    readSyncShareData->lock = 1;
    ret = avsyncAshmem_->WriteToAshmem(static_cast<void*>(readSyncShareData), sizeof(AVsyncShareData), 0);
    CHECK_AND_RETURN_RET_LOG(!ret, ERR_DH_AUDIO_FAILED, "Write avsync data failed.");
    DHLOGD("readSyncShareData->audio_current_pts: %{public}" PRId64", readSyncShareData->audio_update_clock: "
        "%{public}" PRId64, readSyncShareData->audio_current_pts, readSyncShareData->audio_update_clock);
    return DH_SUCCESS;
}

int32_t DMicDev::WriteTimeStampToAVsync(const int64_t timePts)
{
    CHECK_AND_RETURN_RET_LOG(!IsAVsync() || avsyncAshmem_ == nullptr, DH_SUCCESS,
        "Ashmem is nullptr or IsAVsync is false.");
    auto syncData = avsyncAshmem_->ReadFromAshmem(avSyncParam_.sharedMemLen, 0);
    AVsyncShareData *readSyncShareData = reinterpret_cast<AVsyncShareData *>(const_cast<void *>(syncData));
    while (!readSyncShareData->lock && IsAVsync()) {
        DHLOGE("AVsync lock is false");
        syncData = avsyncAshmem_->ReadFromAshmem(avSyncParam_.sharedMemLen, 0);
        readSyncShareData = reinterpret_cast<AVsyncShareData *>(const_cast<void *>(syncData));
    }
    readSyncShareData->lock = 0;
    bool ret = avsyncAshmem_->WriteToAshmem(static_cast<void*>(readSyncShareData), sizeof(AVsyncShareData), 0);
    CHECK_AND_RETURN_RET_LOG(!ret, ERR_DH_AUDIO_FAILED, "Write avsync data failed.");
    struct timespec time = {0, 0};
    clock_gettime(CLOCK_REALTIME, &time);
    int64_t updatePts = static_cast<int64_t>(time.tv_sec) * TIME_CONVERSION_STOU +
        static_cast<int64_t>(time.tv_nsec) / TIME_CONVERSION_NTOU;
    readSyncShareData->lock = 1;
    readSyncShareData->audio_current_pts = static_cast<uint64_t>(timePts);
    readSyncShareData->audio_update_clock = static_cast<uint64_t>(updatePts);
    ret = avsyncAshmem_->WriteToAshmem(static_cast<void*>(readSyncShareData), sizeof(AVsyncShareData), 0);
    CHECK_AND_RETURN_RET_LOG(!ret, ERR_DH_AUDIO_FAILED, "Write avsync data failed.");
    DHLOGD("readSyncShareData->audio_current_pts: %{public}" PRId64", readSyncShareData->audio_update_clock: "
        "%{public}" PRId64, readSyncShareData->audio_current_pts, readSyncShareData->audio_update_clock);
    return DH_SUCCESS;
}

uint32_t DMicDev::GetQueSize()
{
    return dataQueue_.size();
}

bool DMicDev::IsAVsync()
{
    bool isAVsync = false;
    std::lock_guard<std::mutex> lock(avSyncMutex_);
    isAVsync = avSyncParam_.isAVsync;
    return isAVsync;
}

int32_t DMicDev::AVsyncMacthScene(std::shared_ptr<AudioData> &data)
{
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    if (GetQueSize() < scene_ && isStartStatus_.load()) {
        int64_t videoPts = 0;
        int64_t audioPts = 0;
        int32_t ret = ReadTimeStampFromAVsync(videoPts);
        CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED, "ReadTimeStampFromAVsync failed.");
        if (GetQueSize() != 0) {
            CHECK_NULL_RETURN(dataQueue_.front(), ERR_DH_AUDIO_FAILED);
            audioPts = dataQueue_.front()->GetPts();
        }
        int64_t diff = static_cast<int64_t>(audioPts/TIME_CONVERSION_NTOU - videoPts/TIME_CONVERSION_STOU);
        DHLOGI("diff: %{public}" PRId64", videoPts: %{public}" PRId64
            ", audioPts: %{public}" PRId64, diff, videoPts, audioPts);
        if (diff > DADUIO_TIME_DIFF_MAX || GetQueSize() == 0) {
            data = std::make_shared<AudioData>(param_.comParam.frameSize);
        } else {
            isStartStatus_.store(false);
            data = dataQueue_.front();
            dataQueue_.pop_front();
        }
        return DH_SUCCESS;
    }
    isStartStatus_.store(false);
    if (GetQueSize() == 0) {
        isExistedEmpty_.store(true);
        DHLOGD("Data queue is empty");
        data = std::make_shared<AudioData>(param_.comParam.frameSize);
    } else {
        data = dataQueue_.front();
        dataQueue_.pop_front();
    }
    return DH_SUCCESS;
}

int32_t DMicDev::GetAudioDataFromQueue(std::shared_ptr<AudioData> &data)
{
    if (IsAVsync()) {
        int32_t ret = AVsyncMacthScene(data);
        if (ret != DH_SUCCESS) {
            DHLOGD("AVsyncMacthScene failed, insert empty frame");
            data = std::make_shared<AudioData>(param_.comParam.frameSize);
        }
    } else {
        std::lock_guard<std::mutex> lock(dataQueueMtx_);
        if (GetQueSize() == 0) {
            isExistedEmpty_.store(true);
            DHLOGD("Data queue is empty");
            data = std::make_shared<AudioData>(param_.comParam.frameSize);
        } else {
            data = dataQueue_.front();
            dataQueue_.pop_front();
        }
    }
    return DH_SUCCESS;
}

int32_t DMicDev::ReadStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data)
{
    int64_t startTime = GetNowTimeUs();
    if (curStatus_ != AudioStatus::STATUS_START) {
        DHLOGE("Distributed audio is not starting status.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = GetAudioDataFromQueue(data);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS || data == nullptr, ERR_DH_AUDIO_NULLPTR, "GetAudioData failed");
    ret = WriteTimeStampToAVsync(data->GetPts());
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED, "WriteTimeStampToAVsync failed");
    DHLOGD("Read stream data audioPts: %{public}" PRId64, data->GetPts());
    DumpFileUtil::WriteDumpFile(dumpFileCommn_, static_cast<void *>(data->Data()), data->Size());
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
        if (ashmemLength < ASHMEM_MAX_LEN) {
            ashmem_ = sptr<Ashmem>(new Ashmem(fd, ashmemLength));
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
    enqueueDataThread_ = std::thread([ptr = shared_from_this()]() {
        if (!ptr) {
            return;
        }
        ptr->EnqueueThread();
    });
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
                dataQueue_.pop_front();
            }
            if (audioData == nullptr) {
                DHLOGD("The audioData is nullptr.");
                continue;
            }
            DumpFileUtil::WriteDumpFile(dumpFileFast_, static_cast<void *>(audioData->Data()), audioData->Size());
            bool writeRet = ashmem_->WriteToAshmem(audioData->Data(), audioData->Size(), writeIndex_);
            if (writeRet) {
                DHLOGD("Write to ashmem success! write index: %{public}d, writeLength: %{public}d.",
                    writeIndex_, lengthPerTrans_);
            } else {
                DHLOGE("Write data to ashmem failed.");
            }
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
            if (paramHDF_.period == 0) {
                DHLOGE("DMicDev paramHDF_.period is zero");
                break;
            }
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
    int32_t ret = DAudioHdiHandler::GetInstance().NotifyEvent(devId_, portId, streamId_, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify event: %{public}d, result: %{public}s, streamId: %{public}d.",
            event.type, event.content.c_str(), streamId_);
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
    DHLOGD("Send message to remote.");
    if (type != static_cast<uint32_t>(OPEN_MIC) && type != static_cast<uint32_t>(CLOSE_MIC)) {
        DHLOGE("Send message to remote. not OPEN_MIC or CLOSE_MIC. type: %{public}u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    CHECK_NULL_RETURN(micCtrlTrans_, ERR_DH_AUDIO_NULLPTR);
    micCtrlTrans_->SendAudioEvent(type, content, dstDevId);
    return DH_SUCCESS;
}

int32_t DMicDev::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    CHECK_NULL_RETURN(audioData, ERR_DH_AUDIO_NULLPTR);
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    dataQueSize_ = curStatus_ != AudioStatus::STATUS_START ?
        (param_.captureOpts.capturerFlags == MMAP_MODE ? lowLatencyHalfSize_ : scene_) :
        (param_.captureOpts.capturerFlags == MMAP_MODE ? lowLatencyMaxfSize_ : scene_ + scene_);
    if (isExistedEmpty_.load()) {
        dataQueSize_ = param_.captureOpts.capturerFlags == MMAP_MODE ? dataQueSize_ : DATA_QUEUE_EXT_SIZE;
    }
    uint64_t queueSize;
    while (dataQueue_.size() > dataQueSize_) {
        queueSize = static_cast<uint64_t>(dataQueue_.size());
        DHLOGI("Data queue overflow. buf current size: %{public}" PRIu64, queueSize);
        dataQueue_.pop_front();
    }
    std::shared_ptr<AudioData> writeAudioData = std::make_shared<AudioData>(param_.comParam.frameSize);
    if (memcpy_s(writeAudioData->Data(), writeAudioData->Capacity(), audioData->Data(), audioData->Capacity()) != EOK) {
        DHLOGE("Copy audio data failed");
    }
    writeAudioData->SetPts(audioData->GetPts());
    dataQueue_.push_back(writeAudioData);
    queueSize = static_cast<uint64_t>(dataQueue_.size());
    DHLOGD("Push new mic data, buf len: %{public}" PRIu64", audioPts: %{public}" PRId64,
        queueSize, audioData->GetPts());
    return DH_SUCCESS;
}

int32_t DMicDev::AVsyncRefreshAshmem(int32_t fd, int32_t ashmemLength)
{
    DHLOGD("AVsync mode: fd:%{public}d, ashmemLength: %{public}d", fd, ashmemLength);
    CHECK_AND_RETURN_RET_LOG(avsyncAshmem_ != nullptr, DH_SUCCESS, "AvsyncAshmem_ is not nullptr");
    if (ashmemLength < ASHMEM_MAX_LEN && fd > 0) {
        avsyncAshmem_ = sptr<Ashmem>(new Ashmem(fd, ashmemLength));
        ashmemLength_ = ashmemLength;
        DHLOGD("Create ashmem success. fd:%{public}d, ashmem length: %{public}d", fd, ashmemLength_);
        bool mapRet = avsyncAshmem_->MapReadAndWriteAshmem();
        CHECK_AND_RETURN_RET_LOG(!mapRet, ERR_DH_AUDIO_NULLPTR, "Mmap ashmem failed.");
    }
    return DH_SUCCESS;
}

void DMicDev::AVsyncDeintAshmem()
{
    if (avsyncAshmem_ != nullptr) {
        avsyncAshmem_->UnmapAshmem();
        avsyncAshmem_->CloseAshmem();
        avsyncAshmem_ = nullptr;
    }
}

int32_t DMicDev::UpdateWorkModeParam(const std::string &devId, const std::string &dhId, const AudioAsyncParam &param)
{
    std::lock_guard<std::mutex> lock(avSyncMutex_);
    avSyncParam_ = param;
    if (avSyncParam_.isAVsync) {
        auto ret = AVsyncRefreshAshmem(avSyncParam_.fd, avSyncParam_.sharedMemLen);
        CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "AVsyncRefreshAshmemInfo failed");
        scene_ = avSyncParam_.scene == static_cast<uint32_t>(AudioAVScene::BROADCAST) ?
            DATA_QUEUE_BROADCAST_SIZE : DATA_QUEUE_VIDEOCALL_SIZE;
        DHLOGI("AVsync mode opened");
    } else {
        AVsyncDeintAshmem();
        avSyncParam_.fd = -1;
        avSyncParam_.sharedMemLen = 0;
        DHLOGI("AVsync mode closed");
    }
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
