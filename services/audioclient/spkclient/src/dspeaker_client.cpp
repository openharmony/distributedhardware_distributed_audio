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

#include "dspeaker_client.h"

#include "cJSON.h"

#include "daudio_constants.h"
#include "daudio_hisysevent.h"
#include "daudio_sink_hidumper.h"
#include "daudio_util.h"
#include "daudio_sink_manager.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DSpeakerClient"

namespace OHOS {
namespace DistributedHardware {
DSpeakerClient::~DSpeakerClient()
{
    DHLOGD("Release speaker client.");
}

void DSpeakerClient::OnEngineTransEvent(const AVTransEvent &event)
{
    if (event.type == EventType::EVENT_START_SUCCESS) {
        OnStateChange(DATA_OPENED);
    } else if ((event.type == EventType::EVENT_STOP_SUCCESS) ||
        (event.type == EventType::EVENT_CHANNEL_CLOSED) ||
        (event.type == EventType::EVENT_START_FAIL)) {
        OnStateChange(DATA_CLOSED);
    }
}

void DSpeakerClient::OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    CHECK_NULL_VOID(message);
    DHLOGI("On Engine message, type : %{public}s.", GetEventNameByType(message->type_).c_str());
    DAudioSinkManager::GetInstance().HandleDAudioNotify(message->dstDevId_, message->dstDevId_,
        static_cast<int32_t>(message->type_), message->content_);
}

void DSpeakerClient::OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("On Engine Data available");
    OnDecodeTransDataDone(audioData);
}

int32_t DSpeakerClient::InitReceiverEngine(IAVEngineProvider *providerPtr)
{
    DHLOGI("InitReceiverEngine enter.");
    if (speakerTrans_ == nullptr) {
        speakerTrans_ = std::make_shared<AVTransReceiverTransport>(devId_, shared_from_this());
    }
    int32_t ret = speakerTrans_->InitEngine(providerPtr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Spk client initialize av receiver adapter failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerClient::CreateAudioRenderer(const AudioParam &param)
{
    DHLOGD("Set up spk client: {sampleRate: %{public}d, bitFormat: %{public}d, channelMask: %{public}d,"
        "frameSize: %{public}d, contentType: %{public}d, renderFlags: %{public}d, streamUsage: %{public}d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.comParam.frameSize,
        param.renderOpts.contentType, param.renderOpts.renderFlags, param.renderOpts.streamUsage);
    audioParam_ = param;
    if (audioParam_.renderOpts.streamUsage == STREAM_USAGE_VOICE_COMMUNICATION) {
        audioParam_.renderOpts.renderFlags = NORMAL_MODE;
    }
    AudioStandard::AudioRendererOptions rendererOptions = {
        {
            static_cast<AudioStandard::AudioSamplingRate>(audioParam_.comParam.sampleRate),
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            static_cast<AudioStandard::AudioSampleFormat>(audioParam_.comParam.bitFormat),
            static_cast<AudioStandard::AudioChannel>(audioParam_.comParam.channelMask),
        },
        {
            static_cast<AudioStandard::ContentType>(audioParam_.renderOpts.contentType),
            static_cast<AudioStandard::StreamUsage>(audioParam_.renderOpts.streamUsage),
            audioParam_.renderOpts.renderFlags == MMAP_MODE ? AudioStandard::STREAM_FLAG_FAST : 0,
        }
    };
    std::lock_guard<std::mutex> lck(devMtx_);
    audioRenderer_ = AudioStandard::AudioRenderer::Create(rendererOptions);
    CHECK_NULL_RETURN(audioRenderer_, ERR_DH_AUDIO_CLIENT_RENDER_CREATE_FAILED);

    audioRenderer_ ->SetRendererCallback(shared_from_this());
    if (audioParam_.renderOpts.renderFlags != MMAP_MODE) {
        return DH_SUCCESS;
    }
    int32_t ret = audioRenderer_->SetRendererWriteCallback(shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Client save write callback failed.");
        return ERR_DH_AUDIO_CLIENT_RENDER_CREATE_FAILED;
    }
    return DH_SUCCESS;
}

void DSpeakerClient::OnWriteData(size_t length)
{
    AudioStandard::BufferDesc bufDesc;
    CHECK_NULL_VOID(audioRenderer_);
    if (audioRenderer_->GetBufferDesc(bufDesc) != DH_SUCCESS || bufDesc.bufLength == 0) {
        DHLOGE("Get buffer desc failed.");
        return;
    }
    CHECK_NULL_VOID(bufDesc.buffer);

    std::shared_ptr<AudioData> audioData = nullptr;
    {
        std::unique_lock<std::mutex> spkLck(dataQueueMtx_);
        if (dataQueue_.empty()) {
            audioData = std::make_shared<AudioData>(bufDesc.bufLength);
            DHLOGI("Pop spk data, dataQueue is empty. write empty data.");
        } else {
            audioData = dataQueue_.front();
            dataQueue_.pop();
            uint64_t queueSize = static_cast<uint64_t>(dataQueue_.size());
            DHLOGI("Pop spk data, dataQueue size: %{public}" PRIu64, queueSize);
        }
    }
    if (audioData->Capacity() != bufDesc.bufLength) {
        uint64_t capacity = static_cast<uint64_t>(audioData->Capacity());
        uint64_t bufLength = static_cast<uint64_t>(bufDesc.bufLength);
        DHLOGE("Audio data length is not equal to buflength. datalength: %{public}" PRIu64
            ", bufLength: %{public}" PRIu64, capacity, bufLength);
    }
    if (memcpy_s(bufDesc.buffer, bufDesc.bufLength, audioData->Data(), audioData->Capacity()) != EOK) {
        DHLOGE("Copy audio data failed.");
    }
    audioRenderer_->Enqueue(bufDesc);
}

int32_t DSpeakerClient::SetUp(const AudioParam &param)
{
    int32_t ret = CreateAudioRenderer(param);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set up failed, Create Audio renderer failed.");
        return ret;
    }
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);

    ret = speakerTrans_->SetUp(audioParam_, audioParam_, shared_from_this(), CAP_SPK);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans setup failed.");
        return ret;
    }
    ret = speakerTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans start failed.");
        return ret;
    }
    auto pid = getprocpid();
    ret = AudioStandard::AudioSystemManager::GetInstance()->RegisterVolumeKeyEventCallback(pid, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to register volume key event callback.");
        return ret;
    }
    clientStatus_ = AudioStatus::STATUS_READY;
    return DH_SUCCESS;
}

int32_t DSpeakerClient::Release()
{
    DHLOGI("Release spk client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (clientStatus_ != AudioStatus::STATUS_READY && clientStatus_ != AudioStatus::STATUS_STOP) {
        DHLOGE("Speaker status %{public}d is wrong.", (int32_t)clientStatus_);
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    bool isSucess = true;
    if (speakerTrans_ != nullptr) {
        if (speakerTrans_->Stop() != DH_SUCCESS) {
            DHLOGE("Speaker trans stop failed.");
            isSucess = false;
        }
        if (speakerTrans_->Release() != DH_SUCCESS) {
            DHLOGE("Speaker trans release failed.");
            isSucess = false;
        }
        speakerTrans_ = nullptr;
    }

    int32_t ret = AudioStandard::AudioSystemManager::GetInstance()->UnregisterVolumeKeyEventCallback(getprocpid());
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to unregister volume key event callback, error code %{public}d.", ret);
        isSucess = false;
    }
    if (audioRenderer_ != nullptr && !audioRenderer_->Release()) {
        DHLOGE("Audio renderer release failed.");
        isSucess = false;
        audioRenderer_ = nullptr;
    }
    clientStatus_ = AudioStatus::STATUS_IDLE;
    return isSucess ? DH_SUCCESS : ERR_DH_AUDIO_CLIENT_RENDER_RELEASE_FAILED;
}

int32_t DSpeakerClient::StartRender()
{
    DHLOGI("Start spk client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    CHECK_NULL_RETURN(audioRenderer_, ERR_DH_AUDIO_SA_STATUS_ERR);

    if (!audioRenderer_->Start()) {
        DHLOGE("Audio renderer start failed.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_CLIENT_RENDER_STARTUP_FAILURE,
            "daudio renderer start failed.");
        return ERR_DH_AUDIO_CLIENT_RENDER_STARTUP_FAILURE;
    }
    if (audioParam_.renderOpts.renderFlags != MMAP_MODE) {
        isRenderReady_.store(true);
        renderDataThread_ = std::thread(&DSpeakerClient::PlayThreadRunning, this);
    }
    clientStatus_ = AudioStatus::STATUS_START;
    return DH_SUCCESS;
}

int32_t DSpeakerClient::StopRender()
{
    DHLOGI("Stop spk client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (clientStatus_ != AudioStatus::STATUS_START) {
        DHLOGE("Renderer is not start or spk status wrong, status: %{public}d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio renderer is not start or spk status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    if (audioRenderer_ == nullptr) {
        DHLOGE("Audio renderer is nullptr.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_NULLPTR,
            "daudio renderer is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    if (audioParam_.renderOpts.renderFlags != MMAP_MODE) {
        if (isRenderReady_.load()) {
            isRenderReady_.store(false);
            if (renderDataThread_.joinable()) {
                renderDataThread_.join();
            }
        }
    }

    if (!audioRenderer_->Stop()) {
        DHLOGE("Audio renderer stop failed");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_CLIENT_RENDER_STOP_FAILED,
            "daudio renderer stop failed.");
        return ERR_DH_AUDIO_CLIENT_RENDER_STOP_FAILED;
    }
    clientStatus_ = AudioStatus::STATUS_STOP;
    return DH_SUCCESS;
}

void DSpeakerClient::PlayThreadRunning()
{
    DHLOGD("Start the renderer thread.");
    if (pthread_setname_np(pthread_self(), RENDERTHREAD) != DH_SUCCESS) {
        DHLOGE("Render data thread setname failed.");
    }

    FillJitterQueue();
    while (audioRenderer_ != nullptr && isRenderReady_.load()) {
        int64_t startTime = GetNowTimeUs();
        std::shared_ptr<AudioData> audioData = nullptr;
        {
            std::unique_lock<std::mutex> spkLck(dataQueueMtx_);
            dataQueueCond_.wait_for(spkLck, std::chrono::milliseconds(REQUEST_DATA_WAIT),
                [this]() { return !dataQueue_.empty(); });
            if (dataQueue_.empty()) {
                continue;
            }
            audioData = dataQueue_.front();
            dataQueue_.pop();
            uint64_t queueSize = static_cast<uint64_t>(dataQueue_.size());
            DHLOGD("Pop spk data, dataqueue size: %{public}" PRIu64, queueSize);
        }
#ifdef DUMP_DSPEAKERCLIENT_FILE
        if (DaudioSinkHidumper::GetInstance().QueryDumpDataFlag()) {
            SaveFile(SPK_CLIENT_FILENAME, const_cast<uint8_t*>(audioData->Data()), audioData->Size());
        }
#endif
        int32_t writeOffSet = 0;
        while (writeOffSet < static_cast<int32_t>(audioData->Capacity())) {
            int32_t writeLen = audioRenderer_->Write(audioData->Data() + writeOffSet,
                static_cast<int32_t>(audioData->Capacity()) - writeOffSet);
            uint64_t capacity = static_cast<uint64_t>(audioData->Capacity());
            DHLOGD("Write audio render, write len: %{public}d, raw len: %{public}" PRIu64", offset: %{public}d",
                writeLen, capacity, writeOffSet);
            if (writeLen < 0) {
                break;
            }
            writeOffSet += writeLen;
        }
        int64_t endTime = GetNowTimeUs();
        if (IsOutDurationRange(startTime, endTime, lastPlayStartTime_)) {
            DHLOGE("This time play spend: %{public}" PRId64" us, The interval of play this time and "
                "the last time: %{public}" PRId64" us", endTime - startTime, startTime - lastPlayStartTime_);
        }
        lastPlayStartTime_ = startTime;
    }
}

void DSpeakerClient::FillJitterQueue()
{
    while (isRenderReady_.load()) {
        {
            std::lock_guard<std::mutex> lock(dataQueueMtx_);
            if (dataQueue_.size() >= DATA_QUEUE_SIZE) {
                break;
            }
        }
        usleep(SLEEP_TIME);
    }
}

void DSpeakerClient::FlushJitterQueue()
{
    while (isRenderReady_.load()) {
        {
            std::lock_guard<std::mutex> lock(dataQueueMtx_);
            if (dataQueue_.empty()) {
                break;
            }
        }
        usleep(SLEEP_TIME);
    }
}

int32_t DSpeakerClient::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("Write stream buffer.");
    int64_t startTime = GetNowTimeUs();
    CHECK_NULL_RETURN(audioData, ERR_DH_AUDIO_NULLPTR);

    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    while (dataQueue_.size() > DATA_QUEUE_MAX_SIZE) {
        DHLOGD("Data queue overflow.");
        dataQueue_.pop();
    }
    dataQueue_.push(audioData);
    dataQueueCond_.notify_all();
    uint64_t queueSize = static_cast<uint64_t>(dataQueue_.size());
    DHLOGI("Push new spk data, buf len: %{public}" PRIu64, queueSize);
    int64_t endTime = GetNowTimeUs();
    if (IsOutDurationRange(startTime, endTime, lastReceiveStartTime_)) {
        DHLOGE("This time receivce data spend: %{public}" PRId64" us, Receivce data this time and "
            "the last time: %{public}" PRId64" us", endTime - startTime, startTime - lastReceiveStartTime_);
    }
    lastReceiveStartTime_ = startTime;
    return DH_SUCCESS;
}

int32_t DSpeakerClient::OnStateChange(const AudioEventType type)
{
    DHLOGD("On state change. type: %{public}d", type);
    AudioEvent event;
    switch (type) {
        case AudioEventType::DATA_OPENED: {
            event.type = AudioEventType::SPEAKER_OPENED;
            event.content = GetVolumeLevel();
            break;
        }
        case AudioEventType::DATA_CLOSED: {
            event.type = AudioEventType::SPEAKER_CLOSED;
            event.content = GetCJsonString(KEY_DH_ID, std::to_string(dhId_).c_str());
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

string DSpeakerClient::GetVolumeLevel()
{
    DHLOGD("Get the volume level.");
    AudioStandard::AudioStreamType streamType = AudioStandard::AudioStreamType::STREAM_DEFAULT;
    auto volumeType = static_cast<AudioStandard::AudioVolumeType>(1);
    int32_t volumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetVolume(volumeType);
    int32_t maxVolumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetMaxVolume(volumeType);
    int32_t minVolumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetMinVolume(volumeType);
    bool isUpdateUi = false;
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, "");

    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    cJSON_AddStringToObject(jParam, KEY_CHANGE_TYPE, FIRST_VOLUME_CHANAGE);
    cJSON_AddStringToObject(jParam, AUDIO_STREAM_TYPE, std::to_string(streamType).c_str());
    cJSON_AddStringToObject(jParam, VOLUME_LEVEL.c_str(), std::to_string(volumeLevel).c_str());
    cJSON_AddStringToObject(jParam, IS_UPDATEUI, std::to_string(isUpdateUi).c_str());
    cJSON_AddStringToObject(jParam, MAX_VOLUME_LEVEL, std::to_string(maxVolumeLevel).c_str());
    cJSON_AddStringToObject(jParam, MIN_VOLUME_LEVEL, std::to_string(minVolumeLevel).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return "";
    }
    std::string str(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DHLOGD("Get the volume level result, event: %{public}s.", str.c_str());
    return str;
}

void DSpeakerClient::OnVolumeKeyEvent(AudioStandard::VolumeEvent volumeEvent)
{
    DHLOGD("Volume change event.");
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    CHECK_NULL_VOID(cbObj);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
 
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    cJSON_AddStringToObject(jParam, KEY_CHANGE_TYPE, VOLUME_CHANAGE);
    cJSON_AddStringToObject(jParam, AUDIO_STREAM_TYPE, std::to_string(volumeEvent.volumeType).c_str());
    cJSON_AddStringToObject(jParam, VOLUME_LEVEL.c_str(), std::to_string(volumeEvent.volume).c_str());
    cJSON_AddStringToObject(jParam, IS_UPDATEUI, std::to_string(volumeEvent.updateUi).c_str());
    cJSON_AddStringToObject(jParam, VOLUME_GROUP_ID, std::to_string(volumeEvent.volumeGroupId).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return;
    }
    std::string str(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DHLOGD("Volume change notification result, event: %{public}s.", str.c_str());

    AudioEvent audioEvent(VOLUME_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

void DSpeakerClient::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    DHLOGD("Audio focus interrupt event.");
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    CHECK_NULL_VOID(cbObj);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);

    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    cJSON_AddStringToObject(jParam, KEY_CHANGE_TYPE, INTERRUPT_EVENT);
    cJSON_AddStringToObject(jParam, VOLUME_EVENT_TYPE, std::to_string(interruptEvent.eventType).c_str());
    cJSON_AddStringToObject(jParam, FORCE_TYPE, std::to_string(interruptEvent.forceType).c_str());
    cJSON_AddStringToObject(jParam, HINT_TYPE, std::to_string(interruptEvent.hintType).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return;
    }
    std::string str(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DHLOGD("Audio focus oninterrupt notification result, event: %{public}s.", str.c_str());

    AudioEvent audioEvent(AUDIO_FOCUS_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

void DSpeakerClient::OnStateChange(const AudioStandard::RendererState state,
    const AudioStandard::StateChangeCmdType __attribute__((unused)) cmdType)
{
    DHLOGD("On render state change. state: %{public}d", state);
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    CHECK_NULL_VOID(cbObj);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);

    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId_).c_str());
    cJSON_AddStringToObject(jParam, KEY_CHANGE_TYPE, RENDER_STATE_CHANGE_EVENT);
    cJSON_AddStringToObject(jParam, KEY_STATE, std::to_string(state).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return;
    }
    std::string str(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DHLOGD("Audio render state changes notification result, event: %{public}s.", str.c_str());

    AudioEvent audioEvent(AUDIO_RENDER_STATE_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

int32_t DSpeakerClient::SetAudioParameters(const AudioEvent &event)
{
    DHLOGD("Set the volume, arg: %{public}s.", event.content.c_str());

    int32_t audioVolumeType;
    int32_t ret = GetAudioParamInt(event.content, AUDIO_VOLUME_TYPE, audioVolumeType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio volume type failed.");
        return ret;
    }
    auto volumeType = static_cast<AudioStandard::AudioVolumeType>(audioVolumeType);
    DHLOGD("Audio volume type, volumeType = %{public}d.", volumeType);
    if (event.type != VOLUME_SET) {
        DHLOGE("Invalid parameter.");
        return ERR_DH_AUDIO_CLIENT_PARAM_ERROR;
    }

    int32_t audioVolumeLevel;
    ret = GetAudioParamInt(event.content, VOLUME_LEVEL, audioVolumeLevel);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio volume level failed.");
        return ret;
    }
    DHLOGD("volume level = %{public}d.", audioVolumeLevel);
    ret = AudioStandard::AudioSystemManager::GetInstance()->SetVolume(volumeType, audioVolumeLevel);
    if (ret != DH_SUCCESS) {
        DHLOGE("Voloume set failed.");
        return ERR_DH_AUDIO_CLIENT_SET_VOLUME_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerClient::SetMute(const AudioEvent &event)
{
    DHLOGD("Set mute, arg: %{public}s.", event.content.c_str());
    int32_t audioVolumeType;
    int32_t ret = GetAudioParamInt(event.content, AUDIO_VOLUME_TYPE, audioVolumeType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio volume type failed.");
        return ret;
    }

    bool muteStatus = false;
    ret = GetAudioParamBool(event.content, STREAM_MUTE_STATUS, muteStatus);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get mute status failed.");
        return ret;
    }

    auto volumeType = static_cast<AudioStandard::AudioVolumeType>(audioVolumeType);
    DHLOGD("Audio volume type, volumeType = %{public}d.", volumeType);
    if (event.type != VOLUME_MUTE_SET) {
        DHLOGE("Invalid parameter.");
        return ERR_DH_AUDIO_CLIENT_PARAM_ERROR;
    }
    ret = AudioStandard::AudioSystemManager::GetInstance()->SetMute(volumeType, muteStatus);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mute set failed.");
        return ERR_DH_AUDIO_CLIENT_SET_MUTE_FAILED;
    }
    return DH_SUCCESS;
}

void DSpeakerClient::Pause()
{
    DHLOGI("Pause and flush");
    FlushJitterQueue();
    if (audioParam_.renderOpts.renderFlags != MMAP_MODE) {
        isRenderReady_.store(false);
        if (renderDataThread_.joinable()) {
            renderDataThread_.join();
        }
    }

    if (speakerTrans_ == nullptr || speakerTrans_->Pause() != DH_SUCCESS) {
        DHLOGE("Speaker trans Pause failed.");
    }
    if (audioRenderer_ != nullptr) {
        audioRenderer_->Flush();
        audioRenderer_->Pause();
    }
    clientStatus_ = AudioStatus::STATUS_START;
    isRenderReady_.store(true);
}

void DSpeakerClient::ReStart()
{
    DHLOGI("ReStart");
    if (speakerTrans_ == nullptr || speakerTrans_->Restart(audioParam_, audioParam_) != DH_SUCCESS) {
        DHLOGE("Speaker trans Restart failed.");
    }
    if (audioParam_.renderOpts.renderFlags != MMAP_MODE) {
        isRenderReady_.store(true);
        renderDataThread_ = std::thread(&DSpeakerClient::PlayThreadRunning, this);
    }
    if (audioRenderer_ != nullptr) {
        audioRenderer_->Start();
    }
    clientStatus_ = AudioStatus::STATUS_START;
}

int32_t DSpeakerClient::SendMessage(uint32_t type, std::string content, std::string dstDevId)
{
    DHLOGI("Send message to remote.");
    if (type != static_cast<uint32_t>(NOTIFY_OPEN_SPEAKER_RESULT) &&
        type != static_cast<uint32_t>(NOTIFY_OPEN_CTRL_RESULT) &&
        type != static_cast<uint32_t>(NOTIFY_CLOSE_SPEAKER_RESULT) &&
        type != static_cast<uint32_t>(VOLUME_CHANGE) &&
        type != static_cast<uint32_t>(AUDIO_FOCUS_CHANGE) &&
        type != static_cast<uint32_t>(AUDIO_RENDER_STATE_CHANGE)) {
        DHLOGE("event type is not NOTIFY_OPEN_SPK or NOTIFY_CLOSE_SPK or OPEN_CTRL. type:%{public}u", type);
        return ERR_DH_AUDIO_NULLPTR;
    }
    CHECK_NULL_RETURN(speakerTrans_, ERR_DH_AUDIO_NULLPTR);
    speakerTrans_->SendMessage(type, content, dstDevId);
    return DH_SUCCESS;
}

void DSpeakerClient::PlayStatusChange(const std::string &args)
{
    DHLOGI("Play status change, args: %{public}s.", args.c_str());
    std::string changeType = ParseStringFromArgs(args, KEY_CHANGE_TYPE);
    if (changeType == AUDIO_EVENT_RESTART) {
        ReStart();
    } else if (changeType == AUDIO_EVENT_PAUSE) {
        Pause();
    } else {
        DHLOGE("Play status error.");
    }
}

void DSpeakerClient::SetAttrs(const std::string &devId, const std::shared_ptr<IAudioEventCallback> &callback)
{
    DHLOGE("Set attrs, not support yet.");
}
} // DistributedHardware
} // OHOS
