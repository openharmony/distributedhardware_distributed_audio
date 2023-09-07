/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
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
    DHLOGD("Distributed audio sink device constructed, devId: %s.", GetAnonyString(devId).c_str());
}

DAudioSinkDev::~DAudioSinkDev()
{
    DHLOGD("Distributed audio sink device destructed, devId: %s.", GetAnonyString(devId_).c_str());
}

int32_t DAudioSinkDev::AwakeAudioDev()
{
    auto runner = AppExecFwk::EventRunner::Create(true);
    if (runner == nullptr) {
        DHLOGE("Create runner failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    handler_ = std::make_shared<DAudioSinkDev::SinkEventHandler>(runner, shared_from_this());
    return DH_SUCCESS;
}

void DAudioSinkDev::SleepAudioDev()
{
    if (handler_ == nullptr) {
        DHLOGI("Event handler is already stoped.");
        return;
    }
    while (!handler_->IsIdle()) {
        DHLOGD("Event handler is proccesing.");
    }
}

int32_t DAudioSinkDev::InitAVTransEngines(const ChannelState channelState, IAVEngineProvider *providerPtr)
{
    DHLOGI("Init InitAVTransEngines");
    if (channelState == ChannelState::UNKNOWN || providerPtr == nullptr) {
        DHLOGE("The channel type is invalid.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (channelState == ChannelState::MIC_CONTROL_OPENED) {
        // only supports normal audio channel mode
        micClient_ = std::make_shared<DMicClient>(devId_, shared_from_this());
        micClient_->InitSenderEngine(providerPtr);
    }

    if (channelState == ChannelState::SPK_CONTROL_OPENED) {
        speakerClient_ = std::make_shared<DSpeakerClient>(devId_, shared_from_this());
        speakerClient_->InitReceiverEngine(providerPtr);
    }
    return DH_SUCCESS;
}

void DAudioSinkDev::NotifyEvent(const AudioEvent &audioEvent)
{
    DHLOGD("Notify event, eventType: %d.", (int32_t)audioEvent.type);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    if (handler_ == nullptr) {
        DHLOGE("The event handler is null.");
        return;
    }
    if (handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGD("Send event success.");
    }
}

int32_t DAudioSinkDev::TaskOpenCtrlChannel(const std::string &args)
{
    DHLOGI("Open ctrl channel.");
    DHLOGI("Open ctrl channel success, notify open ctrl result.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskCloseCtrlChannel(const std::string &args)
{
    (void)args;
    DHLOGD("Close ctrl channel success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDSpeaker(const std::string &args)
{
    DHLOGI("Open speaker device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }

    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        cJSON_Delete(jParam);
        DHLOGE("Not found the keys.");
        return ERR_DH_AUDIO_FAILED;
    }
    spkDhId_ = std::string(cJSON_GetObjectItemCaseSensitive(jParam, KEY_DH_ID)->valuestring);
    cJSON *audioParamJson = cJSON_GetObjectItemCaseSensitive(jParam, KEY_AUDIO_PARAM);
    AudioParam audioParam;
    int32_t ret = from_json(audioParamJson, audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        cJSON_Delete(jParam);
        return ret;
    }

    if (speakerClient_ == nullptr) {
        DHLOGE("speaker client should be init by dev.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }

    ret = speakerClient_->SetUp(audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Setup speaker failed, ret: %d.", ret);
        NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, spkDhId_, ERR_DH_AUDIO_FAILED);
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, spkDhId_, ret);
    cJSON_Delete(jParam);

    DHLOGI("Open speaker device task end, notify source ret %d.", ret);
    isSpkInUse_.store(true);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDSpeaker(const std::string &args)
{
    (void)args;
    DHLOGI("Close speaker device.");
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client is null or already closed.");
        return DH_SUCCESS;
    }

    int32_t ret = speakerClient_->StopRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker client failed, ret: %d.", ret);
    }
    ret = speakerClient_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker client failed, ret: %d.", ret);
    }
    speakerClient_ = nullptr;
    isSpkInUse_.store(false);
    JudgeDeviceStatus();
    DHLOGI("Close speaker device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskStartRender()
{
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speakerClient_->StartRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start render failed. ret: %d.", ret);
        return ret;
    }
    DHLOGI("Start render success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Open mic device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }

    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    micDhId_ = std::string(cJSON_GetObjectItemCaseSensitive(jParam, KEY_DH_ID)->valuestring);
    cJSON *audioParamJson = cJSON_GetObjectItemCaseSensitive(jParam, KEY_AUDIO_PARAM);
    AudioParam audioParam;
    int32_t ret = from_json(audioParamJson, audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        cJSON_Delete(jParam);
        return ret;
    }

    if (micClient_ == nullptr) {
        DHLOGE("Mic client should be init by dev.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }

    do {
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
    cJSON_Delete(jParam);

    DHLOGI("Open mic device task end, notify source ret %d.", ret);
    isMicInUse_.store(true);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDMic(const std::string &args)
{
    (void)args;
    DHLOGI("Close mic device.");
    if (micClient_ == nullptr) {
        DHLOGE("Mic client is null or already closed.");
        return DH_SUCCESS;
    }

    int32_t ret = micClient_->StopCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop mic client failed, ret: %d.", ret);
    }
    ret = micClient_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release mic client failed, ret: %d.", ret);
    }
    micClient_ = nullptr;
    isMicInUse_.store(false);
    JudgeDeviceStatus();
    DHLOGI("Close mic device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskSetParameter(const std::string &args)
{
    DHLOGD("Set audio param.");
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, args);

    if (speakerClient_ == nullptr) {
        return ERR_DH_AUDIO_SA_SPEAKER_CLIENT_NOT_INIT;
    }
    return speakerClient_->SetAudioParameters(event);
}

int32_t DAudioSinkDev::TaskSetVolume(const std::string &args)
{
    DHLOGD("Set audio volume.");
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
    DHLOGD("Set audio volume success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskSetMute(const std::string &args)
{
    DHLOGD("Set audio mute.");
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
    DHLOGD("Set mute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskVolumeChange(const std::string &args)
{
    DHLOGD("Audio volume changed.");
    AudioEvent event(AudioEventType::VOLUME_CHANGE, args);
    return SendAudioEventToRemote(event);
}

int32_t DAudioSinkDev::TaskFocusChange(const std::string &args)
{
    DHLOGD("Audio focus changed.");
    AudioEvent event(AudioEventType::AUDIO_FOCUS_CHANGE, args);
    return SendAudioEventToRemote(event);
}

int32_t DAudioSinkDev::TaskRenderStateChange(const std::string &args)
{
    DHLOGD("Audio render state changed.");
    AudioEvent event(AudioEventType::AUDIO_RENDER_STATE_CHANGE, args);
    return SendAudioEventToRemote(event);
}

int32_t DAudioSinkDev::TaskPlayStatusChange(const std::string &args)
{
    DHLOGD("Play status change, content: %s.", args.c_str());
    if (speakerClient_ == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speakerClient_->PlayStatusChange(args);
    DHLOGD("Play status change success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::SendAudioEventToRemote(const AudioEvent &event)
{
    // because: type: VOLUME_CHANGE / AUDIO_FOCUS_CHANGE / AUDIO_RENDER_STATE_CHANGE
    // so speakerClient
    if (speakerClient_ == nullptr) {
        DHLOGE("Audio ctrl mgr not init.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speakerClient_->SendMessage(static_cast<uint32_t>(event.type),
        event.content, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task send message to remote failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return DH_SUCCESS;
}

void DAudioSinkDev::JudgeDeviceStatus()
{
    DHLOGI("Checking device's status.");
    if (isSpkInUse_.load() || isMicInUse_.load()) {
        DHLOGI("Device contain periperials in using, speaker status: %d, mic status: %d.",
            isSpkInUse_.load(), isMicInUse_.load());
        return;
    }
    DAudioSinkManager::GetInstance().OnSinkDevReleased(devId_);
}

void DAudioSinkDev::NotifySourceDev(const AudioEventType type, const std::string dhId, const int32_t result)
{
    std::random_device rd;
    const uint32_t randomTaskCode = rd();
    
    cJSON *jEvent = cJSON_CreateObject();
    if (jEvent == nullptr) {
        DHLOGE("Failed to create JSON data.");
        return;
    }
    cJSON_AddStringToObject(jEvent, KEY_DH_ID, dhId.c_str());
    cJSON_AddNumberToObject(jEvent, KEY_RESULT, result);
    cJSON_AddNumberToObject(jEvent, KEY_EVENT_TYPE, static_cast<int>(type));
    cJSON_AddNumberToObject(jEvent, KEY_RANDOM_TASK_CODE, randomTaskCode);
    
    DHLOGD("Notify source dev, new engine, random task code:%u", randomTaskCode);
    if (type == NOTIFY_OPEN_CTRL_RESULT || type == NOTIFY_CLOSE_CTRL_RESULT) {
        DHLOGE("In new engine mode, ctrl is not allowed.");
        cJSON_Delete(jEvent);
        return;
    }
    char *message = cJSON_PrintUnformatted(jEvent);
    if (message == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jEvent);
        return;
    }
    std::string messageStr(message);

    if (speakerClient_ != nullptr) {
        speakerClient_->SendMessage(static_cast<uint32_t>(type), messageStr, devId_);
    }
    if (micClient_ != nullptr) {
        micClient_->SendMessage(static_cast<uint32_t>(type), messageStr, devId_);
    }
    cJSON_Delete(jEvent);
    cJSON_free(message);
}

int32_t DAudioSinkDev::GetParamValue(const cJSON *jsonObj, const char* key, int32_t& value)
{
    cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (paramValue == nullptr || !cJSON_IsNumber(paramValue)) {
        return ERR_DH_AUDIO_FAILED;
    }
    value = paramValue->valueint;
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::GetCJsonObjectItems(const cJSON *jsonObj, AudioParam &audioParam)
{
    int32_t result = 0;
    result = GetParamValue(jsonObj, KEY_SAMPLING_RATE, reinterpret_cast<int32_t&>(audioParam.comParam.sampleRate));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_CHANNELS, reinterpret_cast<int32_t&>(audioParam.comParam.channelMask));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_FORMAT, reinterpret_cast<int32_t&>(audioParam.comParam.bitFormat));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_FRAMESIZE, reinterpret_cast<int32_t&>(audioParam.comParam.frameSize));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_SOURCE_TYPE, reinterpret_cast<int32_t&>(audioParam.captureOpts.sourceType));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_CONTENT_TYPE, reinterpret_cast<int32_t&>(audioParam.renderOpts.contentType));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_STREAM_USAGE, reinterpret_cast<int32_t&>(audioParam.renderOpts.streamUsage));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_RENDER_FLAGS, reinterpret_cast<int32_t&>(audioParam.renderOpts.renderFlags));
    if (result != DH_SUCCESS) {
        return result;
    }
    result = GetParamValue(jsonObj, KEY_CAPTURE_FLAGS,
                           reinterpret_cast<int32_t&>(audioParam.captureOpts.capturerFlags));
    if (result != DH_SUCCESS) {
        return result;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::from_json(const cJSON *jsonObj, AudioParam &audioParam)
{
    if (!JsonParamCheck(jsonObj,
        { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT, KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE,
            KEY_RENDER_FLAGS, KEY_CAPTURE_FLAGS, KEY_FRAMESIZE })) {
        DHLOGE("Not found the keys.");
        return ERR_DH_AUDIO_FAILED;
    }

    int ret = GetCJsonObjectItems(jsonObj, audioParam);
    if (ret != DH_SUCCESS) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::HandleEngineMessage(uint32_t type, std::string content, std::string devId)
{
    DHLOGI("HandleEngineMessage enter.");
    return DAudioSinkManager::GetInstance().HandleDAudioNotify(devId, devId, static_cast<int32_t>(type), content);
}

DAudioSinkDev::SinkEventHandler::SinkEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::shared_ptr<DAudioSinkDev> &dev) : AppExecFwk::EventHandler(runner), sinkDev_(dev)
{
    DHLOGD("Event handler is constructing.");
    mapEventFuncs_[static_cast<uint32_t>(OPEN_CTRL)] = &DAudioSinkDev::SinkEventHandler::NotifyOpenCtrlChannel;
    mapEventFuncs_[static_cast<uint32_t>(CLOSE_CTRL)] = &DAudioSinkDev::SinkEventHandler::NotifyCloseCtrlChannel;
    mapEventFuncs_[static_cast<uint32_t>(CTRL_OPENED)] = &DAudioSinkDev::SinkEventHandler::NotifyCtrlOpened;
    mapEventFuncs_[static_cast<uint32_t>(CTRL_CLOSED)] = &DAudioSinkDev::SinkEventHandler::NotifyCtrlClosed;
    mapEventFuncs_[static_cast<uint32_t>(OPEN_SPEAKER)] = &DAudioSinkDev::SinkEventHandler::NotifyOpenSpeaker;
    mapEventFuncs_[static_cast<uint32_t>(CLOSE_SPEAKER)] = &DAudioSinkDev::SinkEventHandler::NotifyCloseSpeaker;
    mapEventFuncs_[static_cast<uint32_t>(SPEAKER_OPENED)] = &DAudioSinkDev::SinkEventHandler::NotifySpeakerOpened;
    mapEventFuncs_[static_cast<uint32_t>(SPEAKER_CLOSED)] = &DAudioSinkDev::SinkEventHandler::NotifySpeakerClosed;
    mapEventFuncs_[static_cast<uint32_t>(OPEN_MIC)] = &DAudioSinkDev::SinkEventHandler::NotifyOpenMic;
    mapEventFuncs_[static_cast<uint32_t>(CLOSE_MIC)] = &DAudioSinkDev::SinkEventHandler::NotifyCloseMic;
    mapEventFuncs_[static_cast<uint32_t>(MIC_OPENED)] = &DAudioSinkDev::SinkEventHandler::NotifyMicOpened;
    mapEventFuncs_[static_cast<uint32_t>(MIC_CLOSED)] = &DAudioSinkDev::SinkEventHandler::NotifyMicClosed;
    mapEventFuncs_[static_cast<uint32_t>(VOLUME_SET)] = &DAudioSinkDev::SinkEventHandler::NotifySetVolume;
    mapEventFuncs_[static_cast<uint32_t>(VOLUME_CHANGE)] = &DAudioSinkDev::SinkEventHandler::NotifyVolumeChange;
    mapEventFuncs_[static_cast<uint32_t>(SET_PARAM)] = &DAudioSinkDev::SinkEventHandler::NotifySetParam;
    mapEventFuncs_[static_cast<uint32_t>(VOLUME_MUTE_SET)] = &DAudioSinkDev::SinkEventHandler::NotifySetMute;
    mapEventFuncs_[static_cast<uint32_t>(AUDIO_FOCUS_CHANGE)] = &DAudioSinkDev::SinkEventHandler::NotifyFocusChange;
    mapEventFuncs_[static_cast<uint32_t>(AUDIO_RENDER_STATE_CHANGE)] =
        &DAudioSinkDev::SinkEventHandler::NotifyRenderStateChange;
    mapEventFuncs_[static_cast<uint32_t>(CHANGE_PLAY_STATUS)] =
        &DAudioSinkDev::SinkEventHandler::NotifyPlayStatusChange;
}

DAudioSinkDev::SinkEventHandler::~SinkEventHandler() {}

void DAudioSinkDev::SinkEventHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto iter = mapEventFuncs_.find(event->GetInnerEventId());
    if (iter == mapEventFuncs_.end()) {
        DHLOGE("Event Id is invaild.", event->GetInnerEventId());
        return;
    }
    SinkEventFunc &func = iter->second;
    (this->*func)(event);
}

void DAudioSinkDev::SinkEventHandler::NotifyOpenCtrlChannel(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Notify open ctrl channel.");
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskOpenCtrlChannel(eventParam) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyCloseCtrlChannel(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Notify close ctrl channel.");
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskCloseCtrlChannel(eventParam) != DH_SUCCESS) {
        DHLOGE("Close ctrl channel falied.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyCtrlOpened(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Ctrl channel is opened.");
    (void)event;
}

void DAudioSinkDev::SinkEventHandler::NotifyCtrlClosed(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Notify ctrl closed.");
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskCloseCtrlChannel(eventParam) != DH_SUCCESS) {
        DHLOGE("Close ctrl channel failed.");
        return;
    }
    if (sinkDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Close speaker failed.");
        return;
    }
    if (sinkDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Close mic failed.");
        return;
    }
    sinkDevObj->JudgeDeviceStatus();
}

void DAudioSinkDev::SinkEventHandler::NotifyOpenSpeaker(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskOpenDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Open speaker failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyCloseSpeaker(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskOpenDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Open speaker failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifySpeakerOpened(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGD("Starting render.");
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskStartRender() != DH_SUCCESS) {
        DHLOGE("Speaker client start failed.");
        return;
    }
    if (sinkDevObj->TaskVolumeChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Notify pimary volume to source device failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifySpeakerClosed(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Close speaker failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyOpenMic(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskOpenDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Open mic failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyCloseMic(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Close mic failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyMicOpened(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Notify mic is opened.");
    (void)event;
}

void DAudioSinkDev::SinkEventHandler::NotifyMicClosed(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Close mic failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifySetVolume(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskSetVolume(eventParam) != DH_SUCCESS) {
        DHLOGE("Set volume failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyVolumeChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskVolumeChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Notify volume change status to source device failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifySetParam(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskSetParameter(eventParam) != DH_SUCCESS) {
        DHLOGE("Set parameters failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifySetMute(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskSetMute(eventParam) != DH_SUCCESS) {
        DHLOGE("Set mute failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyFocusChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskFocusChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Handle focus change event failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyRenderStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskRenderStateChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Handle render state change failed.");
        return;
    }
}

void DAudioSinkDev::SinkEventHandler::NotifyPlayStatusChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    if (sinkDevObj == nullptr) {
        DHLOGE("Sink dev is invalid.");
        return;
    }
    if (sinkDevObj->TaskPlayStatusChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Handle play status change event failed.");
        return;
    }
}

int32_t DAudioSinkDev::SinkEventHandler::GetEventParam(const AppExecFwk::InnerEvent::Pointer &event,
    std::string &eventParam)
{
    if (event == nullptr) {
        DHLOGE("The input event is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::shared_ptr<AudioEvent> paramObj = event->GetSharedObject<AudioEvent>();
    if (paramObj == nullptr) {
        DHLOGE("The event parameter object is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    eventParam = paramObj->content;
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
