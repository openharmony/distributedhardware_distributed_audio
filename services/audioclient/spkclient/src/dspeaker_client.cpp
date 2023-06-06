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

#include "daudio_constants.h"
#include "daudio_hisysevent.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DSpeakerClient"

namespace OHOS {
namespace DistributedHardware {
DSpeakerClient::~DSpeakerClient()
{
    DHLOGD("Release speaker client.");
}

int32_t DSpeakerClient::SetUp(const AudioParam &param)
{
    DHLOGD("Set up spk client: {sampleRate: %d, bitFormat: %d, channelMask: %d," +
        "frameSize: %d, contentType: %d, renderFlags: %d, streamUsage: %d}.",
        param.comParam.sampleRate, param.comParam.bitFormat, param.comParam.channelMask, param.comParam.frameSize,
        param.renderOpts.contentType, param.renderOpts.renderFlags, param.renderOpts.streamUsage);
    audioParam_ = param;
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
            0,
        }
    };
    std::lock_guard<std::mutex> lck(devMtx_);
    audioRenderer_ = AudioStandard::AudioRenderer::Create(rendererOptions);
    if (audioRenderer_ == nullptr) {
        DHLOGE("Audio renderer create failed.");
        return ERR_DH_AUDIO_CLIENT_CREATE_RENDER_FAILED;
    }
    audioRenderer_ ->SetRendererCallback(shared_from_this());

    speakerTrans_ = std::make_shared<AudioDecodeTransport>(devId_);
    int32_t ret = speakerTrans_->SetUp(audioParam_, audioParam_, shared_from_this(), CAP_SPK);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans setup failed.");
        return ret;
    }
    ret = speakerTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans start failed.");
        return ret;
    }

    auto pid = getpid();
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
        DHLOGE("Speaker status %d is wrong.", (int32_t)clientStatus_);
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

    int32_t ret = AudioStandard::AudioSystemManager::GetInstance()->UnregisterVolumeKeyEventCallback(getpid());
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to unregister volume key event callback, error code %d.", ret);
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
    if (audioRenderer_ == nullptr || clientStatus_ != AudioStatus::STATUS_READY) {
        DHLOGE("Audio renderer init failed or spk status wrong, status: %d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio renderer init failed or spk status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    if (!audioRenderer_->Start()) {
        DHLOGE("Audio renderer start failed.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_CLIENT_RENDER_STARTUP_FAILURE,
            "daudio renderer start failed.");
        return ERR_DH_AUDIO_CLIENT_RENDER_STARTUP_FAILURE;
    }
    isRenderReady_.store(true);
    renderDataThread_ = std::thread(&DSpeakerClient::PlayThreadRunning, this);
    clientStatus_ = AudioStatus::STATUS_START;
    return DH_SUCCESS;
}

int32_t DSpeakerClient::StopRender()
{
    DHLOGI("Stop spk client.");
    std::lock_guard<std::mutex> lck(devMtx_);
    if (clientStatus_ != AudioStatus::STATUS_START || !isRenderReady_.load()) {
        DHLOGE("Renderer is not start or spk status wrong, status: %d.", (int32_t)clientStatus_);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_SA_STATUS_ERR,
            "daudio renderer is not start or spk status wrong.");
        return ERR_DH_AUDIO_SA_STATUS_ERR;
    }
    if (audioRenderer_ == nullptr) {
        DHLOGE("Audio renderer is nullptr.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_CLIENT_RENDER_OR_TRANS_IS_NULL,
            "daudio renderer is nullptr.");
        return ERR_DH_AUDIO_CLIENT_RENDER_OR_TRANS_IS_NULL;
    }

    FlushJitterQueue();
    isRenderReady_.store(false);
    if (renderDataThread_.joinable()) {
        renderDataThread_.join();
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
            DHLOGD("Pop spk data, dataqueue size: %d.", dataQueue_.size());
        }

        int32_t writeOffSet = 0;
        while (writeOffSet < static_cast<int32_t>(audioData->Capacity())) {
            int32_t writeLen = audioRenderer_->Write(audioData->Data() + writeOffSet,
                static_cast<int32_t>(audioData->Capacity()) - writeOffSet);
            DHLOGD("Write audio render, write len: %d, raw len: %d, offset: %d", writeLen, audioData->Capacity(),
                writeOffSet);
            if (writeLen < 0) {
                break;
            }
            writeOffSet += writeLen;
        }
    }
}

void DSpeakerClient::FillJitterQueue()
{
    while (true) {
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
    while (true) {
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
    if (audioData == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_CLIENT_PARAM_IS_NULL;
    }
    std::lock_guard<std::mutex> lock(dataQueueMtx_);
    while (dataQueue_.size() > DATA_QUEUE_MAX_SIZE) {
        DHLOGD("Data queue overflow.");
        dataQueue_.pop();
    }
    dataQueue_.push(audioData);
    dataQueueCond_.notify_all();
    DHLOGI("Push new spk data, buf len: %d.", dataQueue_.size());
    return DH_SUCCESS;
}

int32_t DSpeakerClient::OnStateChange(const AudioEventType type)
{
    DHLOGD("On state change. type: %d", type);
    AudioEvent event;
    switch (type) {
        case AudioEventType::DATA_OPENED: {
            event.type = AudioEventType::SPEAKER_OPENED;
            event.content = GetVolumeLevel();
            break;
        }
        case AudioEventType::DATA_CLOSED: {
            event.type = AudioEventType::SPEAKER_CLOSED;
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

string DSpeakerClient::GetVolumeLevel()
{
    DHLOGD("Get the volume level.");
    std::stringstream ss;
    AudioStandard::AudioStreamType streamType = AudioStandard::AudioStreamType::STREAM_DEFAULT;
    auto volumeType = static_cast<AudioStandard::AudioVolumeType>(1);
    int32_t volumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetVolume(volumeType);
    int32_t maxVolumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetMaxVolume(volumeType);
    int32_t minVolumeLevel = AudioStandard::AudioSystemManager::GetInstance()->GetMinVolume(volumeType);
    bool isUpdateUi = false;
    ss << "FIRST_VOLUME_CHANAGE;"
       << "AUDIO_STREAM_TYPE=" << streamType << ";"
       << "VOLUME_LEVEL=" << volumeLevel << ";"
       << "IS_UPDATEUI=" << isUpdateUi << ";"
       << "MAX_VOLUME_LEVEL=" << maxVolumeLevel << ";"
       << "MIN_VOLUME_LEVEL=" << minVolumeLevel << ";";
    std::string str = ss.str();
    DHLOGD("Get the volume level result, event: %s.", str.c_str());
    return str;
}

void DSpeakerClient::OnVolumeKeyEvent(AudioStandard::VolumeEvent volumeEvent)
{
    DHLOGD("Volume change event.");
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is nullptr.");
        return;
    }
    std::stringstream ss;
    ss << "VOLUME_CHANAGE;"
       << "AUDIO_STREAM_TYPE=" << volumeEvent.volumeType << ";"
       << "VOLUME_LEVEL=" << volumeEvent.volume << ";"
       << "IS_UPDATEUI=" << volumeEvent.updateUi << ";"
       << "VOLUME_GROUP_ID=" << volumeEvent.volumeGroupId << ";";
    std::string str = ss.str();
    DHLOGD("Volume change notification result, event: %s.", str.c_str());

    AudioEvent audioEvent(VOLUME_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

void DSpeakerClient::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    DHLOGD("Audio focus interrupt event.");
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is nullptr.");
        return;
    }
    std::stringstream ss;
    ss << "INTERRUPT_EVENT;"
       << "EVENT_TYPE=" << interruptEvent.eventType << ";"
       << "FORCE_TYPE=" << interruptEvent.forceType << ";"
       << "HINT_TYPE=" << interruptEvent.hintType << ";";
    std::string str = ss.str();
    DHLOGD("Audio focus oninterrupt notification result, event: %s.", str.c_str());

    AudioEvent audioEvent(AUDIO_FOCUS_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

void DSpeakerClient::OnStateChange(const AudioStandard::RendererState state,
    const AudioStandard::StateChangeCmdType __attribute__((unused)) cmdType)
{
    DHLOGD("On render state change. state: %d", state);
    std::shared_ptr<IAudioEventCallback> cbObj = eventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is nullptr.");
        return;
    }
    std::stringstream ss;
    ss << "RENDER_STATE_CHANGE_EVENT;"
       << "STATE=" << state << ";";
    std::string str = ss.str();
    DHLOGD("Audio render state changes notification result, event: %s.", str.c_str());

    AudioEvent audioEvent(AUDIO_RENDER_STATE_CHANGE, str);
    cbObj->NotifyEvent(audioEvent);
}

int32_t DSpeakerClient::SetAudioParameters(const AudioEvent &event)
{
    DHLOGD("Set the volume, arg: %s.", event.content.c_str());

    int32_t audioVolumeType;
    int32_t ret = GetAudioParamInt(event.content, AUDIO_VOLUME_TYPE, audioVolumeType);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio volume type failed.");
        return ret;
    }
    auto volumeType = static_cast<AudioStandard::AudioVolumeType>(audioVolumeType);
    DHLOGD("Audio volume type, volumeType = %d.", volumeType);
    if (event.type != VOLUME_SET) {
        DHLOGE("Invalid parameter.");
        return ERR_DH_AUDIO_CLIENT_INVALID_VOLUME_PARAMETER;
    }

    int32_t audioVolumeLevel;
    ret = GetAudioParamInt(event.content, VOLUME_LEVEL, audioVolumeLevel);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio volume level failed.");
        return ret;
    }
    DHLOGD("volume level = %d.", audioVolumeLevel);
    ret = AudioStandard::AudioSystemManager::GetInstance()->SetVolume(volumeType, audioVolumeLevel);
    if (ret != DH_SUCCESS) {
        DHLOGE("Voloume set failed.");
        return ERR_DH_AUDIO_CLIENT_SET_VOLUME_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerClient::SetMute(const AudioEvent &event)
{
    DHLOGD("Set mute, arg: %s.", event.content.c_str());
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
    DHLOGD("Audio volume type, volumeType = %d.", volumeType);
    if (event.type != VOLUME_MUTE_SET) {
        DHLOGE("Invalid parameter.");
        return ERR_DH_AUDIO_CLIENT_INVALID_VOLUME_PARAMETER;
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
    isRenderReady_.store(false);
    if (renderDataThread_.joinable()) {
        renderDataThread_.join();
    }
    if (speakerTrans_ == nullptr || speakerTrans_->Pause() != DH_SUCCESS) {
        DHLOGE("Speaker trans Pause failed.");
    }

    if (audioRenderer_ != nullptr) {
        audioRenderer_->Flush();
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
    isRenderReady_.store(true);
    renderDataThread_ = std::thread(&DSpeakerClient::PlayThreadRunning, this);
    clientStatus_ = AudioStatus::STATUS_START;
}

void DSpeakerClient::PlayStatusChange(const std::string &args)
{
    DHLOGD("Play status change, args: %s.", args.c_str());
    if (args == AUDIO_EVENT_RESTART) {
        ReStart();
    } else if (args == AUDIO_EVENT_PAUSE) {
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
