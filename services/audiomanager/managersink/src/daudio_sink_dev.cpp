/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "daudio_sink_dev.h"

#include <random>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_sink_manager.h"
#include "daudio_util.h"
#include "task_impl.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkDev"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkDev::DAudioSinkDev(const std::string &devId) : devId_(devId)
{
    DHLOGI("Distributed audio sink device constructed, devId: %s.", GetAnonyString(devId).c_str());
    memberFuncMap_[OPEN_CTRL] = &DAudioSinkDev::NotifyOpenCtrlChannel;
    memberFuncMap_[CLOSE_CTRL] = &DAudioSinkDev::NotifyCloseCtrlChannel;
    memberFuncMap_[CTRL_OPENED] = &DAudioSinkDev::NotifyCtrlOpened;
    memberFuncMap_[CTRL_CLOSED] = &DAudioSinkDev::NotifyCtrlClosed;
    memberFuncMap_[SET_PARAM] = &DAudioSinkDev::NotifySetParam;
    memberFuncMap_[AUDIO_FOCUS_CHANGE] = &DAudioSinkDev::NotifyFocusChange;
    memberFuncMap_[AUDIO_RENDER_STATE_CHANGE] = &DAudioSinkDev::NotifyRenderStateChange;
    memberFuncMap_[OPEN_SPEAKER] = &DAudioSinkDev::NotifyOpenSpeaker;
    memberFuncMap_[CLOSE_SPEAKER] = &DAudioSinkDev::NotifyCloseSpeaker;
    memberFuncMap_[SPEAKER_OPENED] = &DAudioSinkDev::NotifySpeakerOpened;
    memberFuncMap_[SPEAKER_CLOSED] = &DAudioSinkDev::NotifySpeakerClosed;
    memberFuncMap_[OPEN_MIC] = &DAudioSinkDev::NotifyOpenMic;
    memberFuncMap_[CLOSE_MIC] = &DAudioSinkDev::NotifyCloseMic;
    memberFuncMap_[MIC_OPENED] = &DAudioSinkDev::NotifyMicOpened;
    memberFuncMap_[MIC_CLOSED] = &DAudioSinkDev::NotifyMicClosed;
    memberFuncMap_[VOLUME_SET] = &DAudioSinkDev::NotifySetVolume;
    memberFuncMap_[VOLUME_MUTE_SET] = &DAudioSinkDev::NotifySetMute;
    memberFuncMap_[VOLUME_CHANGE] = &DAudioSinkDev::NotifyVolumeChange;
    memberFuncMap_[CHANGE_PLAY_STATUS] = &DAudioSinkDev::NotifyPlayStatusChange;
}

DAudioSinkDev::~DAudioSinkDev()
{
    DHLOGI("Distributed audio sink device destructed, devId: %s.", GetAnonyString(devId_).c_str());
}

int32_t DAudioSinkDev::AwakeAudioDev()
{
    constexpr size_t capacity = 20;
    taskQueue_ = std::make_shared<TaskQueue>(capacity);
    taskQueue_->Start();
    return DH_SUCCESS;
}

void DAudioSinkDev::SleepAudioDev()
{
    if (taskQueue_ == nullptr) {
        DHLOGI("Task queue already stop.");
        return;
    }
    taskQueue_->Stop();
    taskQueue_ = nullptr;
}

void DAudioSinkDev::NotifyEvent(const AudioEvent &audioEvent)
{
    DHLOGI("Notify event, eventType: %d.", (int32_t)audioEvent.type);

    std::map<AudioEventType, DAudioSinkDevFunc>::iterator iter = memberFuncMap_.find(audioEvent.type);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid eventType.");
        return;
    }
    DAudioSinkDevFunc &func = iter->second;
    (this->*func)(audioEvent);
}

int32_t DAudioSinkDev::NotifyOpenCtrlChannel(const AudioEvent &audioEvent)
{
    DHLOGI("Notify open ctrl channel.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskOpenCtrlChannel, audioEvent.content, "Sink Open Ctrl",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyCloseCtrlChannel(const AudioEvent &audioEvent)
{
    DHLOGI("Notify close ctrl channel.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseCtrlChannel, audioEvent.content, "Sink Close Ctrl",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyCtrlOpened(const AudioEvent &audioEvent)
{
    DHLOGI("Notify ctrl opened.");
    (void)audioEvent;
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::NotifyCtrlClosed(const AudioEvent &audioEvent)
{
    DHLOGI("Notify ctrl closed.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseCtrlChannel, "", "Sink Close Ctrl",
        &DAudioSinkDev::OnTaskResult);
    taskQueue_->Produce(task);
    task = GenerateTask(this, &DAudioSinkDev::TaskCloseDSpeaker, "", "Sink Close Speaker",
        &DAudioSinkDev::OnTaskResult);
    taskQueue_->Produce(task);
    task = GenerateTask(this, &DAudioSinkDev::TaskCloseDMic, "", "Sink Close Mic", &DAudioSinkDev::OnTaskResult);
    taskQueue_->Produce(task);
    DAudioSinkManager::GetInstance().OnSinkDevReleased(devId_);
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::NotifyOpenSpeaker(const AudioEvent &audioEvent)
{
    DHLOGI("Notify open speaker.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskOpenDSpeaker, audioEvent.content,
        "Sink Open Speaker", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyCloseSpeaker(const AudioEvent &audioEvent)
{
    DHLOGI("Notify close speaker.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseDSpeaker, audioEvent.content,
        "Sink Close Speaker", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifySpeakerOpened(const AudioEvent &audioEvent)
{
    DHLOGI("Notify speaker opened.");
    if (speakerClient_ == nullptr || taskQueue_ == nullptr) {
        DHLOGE("Speaker client or task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speakerClient_->StartRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start render failed. ret: %d.", ret);
        return ret;
    }
    DHLOGI("Notify primary volume.");
    auto task = GenerateTask(this, &DAudioSinkDev::TaskVolumeChange, audioEvent.content,
        "Sink Notify Vol Change", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifySpeakerClosed(const AudioEvent &audioEvent)
{
    (void)audioEvent;
    DHLOGI("Notify speaker closed.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseDSpeaker, "", "Sink Close Speaker",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyMicOpened(const AudioEvent &audioEvent)
{
    (void)audioEvent;
    DHLOGI("Notify mic opened.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::NotifyMicClosed(const AudioEvent &audioEvent)
{
    DHLOGI("Notify mic closed.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseDMic, "", "Sink Close Mic", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyOpenMic(const AudioEvent &audioEvent)
{
    DHLOGI("Notify open dMic.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskOpenDMic, audioEvent.content, "Sink Open Mic",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyCloseMic(const AudioEvent &audioEvent)
{
    DHLOGI("Notify close dMic.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskCloseDMic, audioEvent.content, "Sink Close Mic",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifySetParam(const AudioEvent &audioEvent)
{
    DHLOGI("Notify set param.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskSetParameter, audioEvent.content, "Sink Set Param",
        &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifySetVolume(const AudioEvent &audioEvent)
{
    DHLOGI("Notify set volume.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskSetVolume, audioEvent.content,
        "Sink Notify SetVolume", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifySetMute(const AudioEvent &audioEvent)
{
    DHLOGI("Notify set mute.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskSetMute, audioEvent.content,
        "Sink NotifySetMute", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyVolumeChange(const AudioEvent &audioEvent)
{
    DHLOGI("Notify volume change.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskVolumeChange, audioEvent.content,
        "Sink Notify Volume Change", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyFocusChange(const AudioEvent &audioEvent)
{
    DHLOGI("Notify focus change.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskFocusChange, audioEvent.content,
        "Sink Notify Focus Change", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyRenderStateChange(const AudioEvent &audioEvent)
{
    DHLOGI("Notify render state change.");
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskRenderStateChange, audioEvent.content,
        "Sink Notify Render State Change", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::NotifyPlayStatusChange(const AudioEvent &audioEvent)
{
    DHLOGI("Notify play status change, content: %s.", audioEvent.content.c_str());
    if (taskQueue_ == nullptr) {
        DHLOGE("Task queue is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto task = GenerateTask(this, &DAudioSinkDev::TaskPlayStatusChange, audioEvent.content,
        "Sink Notify Play Status Change", &DAudioSinkDev::OnTaskResult);
    return taskQueue_->Produce(task);
}

int32_t DAudioSinkDev::TaskOpenCtrlChannel(const std::string &args)
{
    DHLOGI("Open ctrl channel.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        return ERR_DH_AUDIO_FAILED;
    }

    if (audioCtrlMgr_ != nullptr && audioCtrlMgr_->IsOpened()) {
        DHLOGI("Ctrl channel already opened.");
        NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, jParam[KEY_DH_ID], DH_SUCCESS);
        return DH_SUCCESS;
    }

    audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId_, shared_from_this());
    int32_t ret = audioCtrlMgr_->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("SetUp ctrl mgr failed, ret: %d.", ret);
        NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, jParam[KEY_DH_ID], ERR_DH_AUDIO_FAILED);
        return ret;
    }

    NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, jParam[KEY_DH_ID], DH_SUCCESS);
    DHLOGI("Open ctrl channel success, notify open ctrl result.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskCloseCtrlChannel(const std::string &args)
{
    (void)args;
    DHLOGI("Close ctrl channel.");
    if (audioCtrlMgr_ == nullptr) {
        DHLOGI("Ctrl channel already closed.");
        return DH_SUCCESS;
    }

    int32_t ret = audioCtrlMgr_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop ctrl mgr failed, ret: %d.", ret);
    }
    ret = audioCtrlMgr_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release ctrl mgr failed, ret: %d.", ret);
    }
    audioCtrlMgr_ = nullptr;
    DHLOGI("Close ctrl channel success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDSpeaker(const std::string &args)
{
    DHLOGI("Open speaker device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        return ERR_DH_AUDIO_FAILED;
    }
    spkDhId_ = jParam[KEY_DH_ID];
    AudioParam audioParam;
    int32_t ret = from_json(jParam[KEY_AUDIO_PARAM], audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        return ret;
    }

    if (speakerClient_ == nullptr) {
        if (audioParam.renderOpts.renderFlags == NORMAL_MODE) {
            speakerClient_ = std::make_shared<DSpeakerClient>(devId_, shared_from_this());
        }
    }

    if (speakerClient_ == nullptr) {
        speakerClient_ = std::make_shared<DSpeakerClient>(devId_, shared_from_this());
    }
    ret = speakerClient_->SetUp(audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Setup speaker failed, ret: %d.", ret);
        NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, spkDhId_, ERR_DH_AUDIO_FAILED);
        return ERR_DH_AUDIO_FAILED;
    }

    NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, spkDhId_, ret);
    DHLOGI("Open speaker device task end, notify source ret %d.", ret);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDSpeaker(const std::string &args)
{
    (void)args;
    DHLOGI("Close speaker device.");
    if (speakerClient_ == nullptr) {
        DHLOGI("Speaker client is null or already closed.");
        NotifySourceDev(NOTIFY_CLOSE_SPEAKER_RESULT, spkDhId_, DH_SUCCESS);
        return DH_SUCCESS;
    }

    bool closeStatus = true;
    int32_t ret = speakerClient_->StopRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker client failed, ret: %d.", ret);
        closeStatus = false;
    }
    ret = speakerClient_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker client failed, ret: %d.", ret);
        closeStatus = false;
    }
    speakerClient_ = nullptr;

    closeStatus ? NotifySourceDev(NOTIFY_CLOSE_SPEAKER_RESULT, spkDhId_, DH_SUCCESS) :
        NotifySourceDev(NOTIFY_CLOSE_SPEAKER_RESULT, spkDhId_, ERR_DH_AUDIO_FAILED);
    DHLOGI("Close speaker device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Open mic device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        return ERR_DH_AUDIO_FAILED;
    }
    micDhId_ = jParam[KEY_DH_ID];
    AudioParam audioParam;
    int32_t ret = from_json(jParam[KEY_AUDIO_PARAM], audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        return ret;
    }

    do {
        if (micClient_ == nullptr) {
            if (audioParam.captureOpts.capturerFlags == NORMAL_MODE) {
                micClient_ = std::make_shared<DMicClient>(devId_, shared_from_this());
            }
        }
        ret = micClient_->SetUp(audioParam);
        if (ret != DH_SUCCESS) {
            DHLOGE("Set up mic failed, ret: %d.", ret);
            break;
        }
        ret = micClient_->StartCapture();
        if (ret != DH_SUCCESS) {
            DHLOGE("Start capture failed, ret: %d.", ret);
            break;
        }
    } while (false);
    NotifySourceDev(NOTIFY_OPEN_MIC_RESULT, micDhId_, ret);
    DHLOGI("Open mic device task end, notify source ret %d.", ret);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDMic(const std::string &args)
{
    (void)args;
    DHLOGI("Close mic device.");
    if (micClient_ == nullptr) {
        DHLOGI("Mic client is null or already closed.");
        NotifySourceDev(NOTIFY_CLOSE_MIC_RESULT, micDhId_, DH_SUCCESS);
        return DH_SUCCESS;
    }

    bool closeStatus = true;
    int32_t ret = micClient_->StopCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop mic client failed, ret: %d.", ret);
        closeStatus = false;
    }
    ret = micClient_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release mic client failed, ret: %d.", ret);
        closeStatus = false;
    }
    micClient_ = nullptr;

    closeStatus ? NotifySourceDev(NOTIFY_CLOSE_MIC_RESULT, micDhId_, DH_SUCCESS) :
        NotifySourceDev(NOTIFY_CLOSE_MIC_RESULT, micDhId_, ERR_DH_AUDIO_FAILED);
    DHLOGI("Close mic device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskSetParameter(const std::string &args)
{
    DHLOGI("Set audio param.");
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, args);

    if (speakerClient_ == nullptr) {
        return ERR_DH_AUDIO_SA_SPEAKER_CLIENT_NOT_INIT;
    }
    return speakerClient_->SetAudioParameters(event);
}

int32_t DAudioSinkDev::TaskSetVolume(const std::string &args)
{
    DHLOGI("Set audio volume.");
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    AudioEvent event(AudioEventType::VOLUME_SET, args);
    int32_t ret = speakerClient_->SetAudioParameters(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Volume set failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Set audio volume success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskSetMute(const std::string &args)
{
    DHLOGI("Set audio mute.");
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    AudioEvent event(AudioEventType::VOLUME_MUTE_SET, args);
    int32_t ret = speakerClient_->SetMute(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set mute failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Set mute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskVolumeChange(const std::string &args)
{
    DHLOGI("Audio volume changed.");
    AudioEvent event(AudioEventType::VOLUME_CHANGE, args);
    if (audioCtrlMgr_ == nullptr) {
        return ERR_DH_AUDIO_SA_SINKCTRLMGR_NOT_INIT;
    }
    return audioCtrlMgr_->SendAudioEvent(event);
}

int32_t DAudioSinkDev::TaskFocusChange(const std::string &args)
{
    DHLOGI("Audio focus changed.");
    AudioEvent event(AudioEventType::AUDIO_FOCUS_CHANGE, args);
    if (audioCtrlMgr_ == nullptr) {
        return ERR_DH_AUDIO_SA_SINKCTRLMGR_NOT_INIT;
    }
    return audioCtrlMgr_->SendAudioEvent(event);
}

int32_t DAudioSinkDev::TaskRenderStateChange(const std::string &args)
{
    DHLOGI("Audio render state changed.");
    AudioEvent event(AudioEventType::AUDIO_RENDER_STATE_CHANGE, args);
    if (audioCtrlMgr_ == nullptr) {
        return ERR_DH_AUDIO_SA_SINKCTRLMGR_NOT_INIT;
    }
    return audioCtrlMgr_->SendAudioEvent(event);
}

int32_t DAudioSinkDev::TaskPlayStatusChange(const std::string &args)
{
    DHLOGI("Play status change, content: %s.", args.c_str());
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speakerClient_->PlayStatusChange(args);
    DHLOGI("Play status change success.");
    return DH_SUCCESS;
}

void DAudioSinkDev::OnTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)resultCode;
    (void)result;
    (void)funcName;
    DHLOGI("On task result. resultCode: %d, funcName: %s", resultCode, funcName.c_str());
}

void DAudioSinkDev::NotifySourceDev(const AudioEventType type, const std::string dhId, const int32_t result)
{
    std::random_device rd;
    const uint32_t randomTaskCode = rd();
    json jEvent;
    jEvent[KEY_DH_ID] = dhId;
    jEvent[KEY_RESULT] = result;
    jEvent[KEY_EVENT_TYPE] = type;
    jEvent[KEY_RANDOM_TASK_CODE] = std::to_string(randomTaskCode);

    DHLOGI("notify source dev, random task code: %s", std::to_string(randomTaskCode).c_str());
    DAudioSinkManager::GetInstance().DAudioNotify(devId_, dhId, type, jEvent.dump());
}

int32_t DAudioSinkDev::from_json(const json &j, AudioParam &audioParam)
{
    if (!JsonParamCheck(j,
        { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT, KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE })) {
        return ERR_DH_AUDIO_FAILED;
    }
    j.at(KEY_SAMPLING_RATE).get_to(audioParam.comParam.sampleRate);
    j.at(KEY_CHANNELS).get_to(audioParam.comParam.channelMask);
    j.at(KEY_FORMAT).get_to(audioParam.comParam.bitFormat);
    j.at(KEY_FRAMESIZE).get_to(audioParam.comParam.frameSize);
    j.at(KEY_SOURCE_TYPE).get_to(audioParam.captureOpts.sourceType);
    j.at(KEY_CONTENT_TYPE).get_to(audioParam.renderOpts.contentType);
    j.at(KEY_STREAM_USAGE).get_to(audioParam.renderOpts.streamUsage);
    j.at(KEY_RENDER_FLAGS).get_to(audioParam.renderOpts.renderFlags);
    j.at(KEY_CAPTURE_FLAGS).get_to(audioParam.captureOpts.capturerFlags);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
