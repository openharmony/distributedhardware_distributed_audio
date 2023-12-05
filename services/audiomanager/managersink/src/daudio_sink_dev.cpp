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


#include <random>

#include "cJSON.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_sink_manager.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkDev"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkDev::DAudioSinkDev(const std::string &devId, const sptr<IDAudioSinkIpcCallback> &sinkCallback)
    : devId_(devId), ipcSinkCallback_(sinkCallback)
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
    DHLOGD("Sleep audio dev.");
    if (handler_ == nullptr) {
        DHLOGI("Event handler is already stoped.");
        return;
    }
    while (!handler_->IsIdle()) {
        DHLOGD("handler is running, wait for idle.");
        usleep(WAIT_HANDLER_IDLE_TIME_US);
    }
    DHLOGI("Sleep audio dev over.");
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
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClientMap_[DEFAULT_CAPTURE_ID] = std::make_shared<DMicClient>(devId_, DEFAULT_CAPTURE_ID,
            shared_from_this());
        micClientMap_[DEFAULT_CAPTURE_ID]->InitSenderEngine(providerPtr);
    }

    if (channelState == ChannelState::SPK_CONTROL_OPENED) {
        spkClientMap_[DEFAULT_RENDER_ID] =
            std::make_shared<DSpeakerClient>(devId_, DEFAULT_RENDER_ID, shared_from_this());
        spkClientMap_[DEFAULT_RENDER_ID]->InitReceiverEngine(providerPtr);
        spkClientMap_[LOW_LATENCY_RENDER_ID] =
            std::make_shared<DSpeakerClient>(devId_, LOW_LATENCY_RENDER_ID, shared_from_this());
        spkClientMap_[LOW_LATENCY_RENDER_ID]->InitReceiverEngine(providerPtr);
    }
    return DH_SUCCESS;
}

void DAudioSinkDev::NotifyEvent(const AudioEvent &audioEvent)
{
    DHLOGD("Notify event, eventType: %d.", (int32_t)audioEvent.type);
    if ((int32_t)audioEvent.type == DISABLE_DEVICE) {
        TaskDisableDevice(audioEvent.content);
        return;
    }
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

int32_t DAudioSinkDev::TaskDisableDevice(const std::string &args)
{
    if (args.find(OWNER_NAME_D_SPEAKER) != args.npos) {
        isSpkInUse_.store(false);
    }
    if (args.find(OWNER_NAME_D_MIC) != args.npos) {
        isMicInUse_.store(false);
    }
    JudgeDeviceStatus();
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDSpeaker(const std::string &args)
{
    DHLOGI("Open speaker device, args = %s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(jParam[KEY_DH_ID]));
    if (dhId == -1) {
        DHLOGE("Parse dhId error.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    AudioParam audioParam;
    int32_t ret = from_json(jParam[KEY_AUDIO_PARAM], audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        return ret;
    }

    if (speakerClient == nullptr) {
        DHLOGE("speaker client should be init by dev.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    ret = speakerClient->SetUp(audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Setup speaker failed, ret: %d.", ret);
        NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, spkDhId_, ret);
        return ret;
    }
    NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, std::to_string(dhId), ret);
    DHLOGI("Open speaker device task end, notify source ret %d.", ret);
    isSpkInUse_.store(true);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDSpeaker(const std::string &args)
{
    DHLOGI("Close speaker device.");
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::lock_guard<std::mutex> devLck(spkClientMutex_);
    auto speakerClient = spkClientMap_[dhId];
    if (speakerClient == nullptr) {
        DHLOGE("Speaker client is null or already closed.");
        return DH_SUCCESS;
    }

    int32_t ret = speakerClient->StopRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker client failed, ret: %d.", ret);
    }
    ret = speakerClient->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker client failed, ret: %d.", ret);
    }
    spkClientMap_.erase(dhId);
    DHLOGI("Close speaker device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::ParseDhidFromEvent(std::string args)
{
    DHLOGI("ParseDhidFrom args : %s", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        return -1;
    }
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return -1;
    }
    cJSON *dhIdItem = cJSON_GetObjectItem(jParam, KEY_DH_ID);
    if (dhIdItem == NULL || !cJSON_IsString(dhIdItem)) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(dhIdItem->valuestring));
    cJSON_Delete(jParam);
    DHLOGI("Parsed dhId is: %d.", dhId);
    return dhId;
}

int32_t DAudioSinkDev::TaskStartRender(const std::string &args)
{
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        DHLOGE("Speaker client is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speakerClient->StartRender();
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
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        return ERR_DH_AUDIO_FAILED;
    }
    AudioParam audioParam;
    int32_t ret = from_json(jParam[KEY_AUDIO_PARAM], audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from json failed, error code %d.", ret);
        return ret;
    }
    micDhId_ = std::string(jParam[KEY_DH_ID]);
    int32_t dhId = ConvertString2Int(std::string(jParam[KEY_DH_ID]));
    if (dhId == -1) {
        DHLOGE("Parse dhId error.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhId];
    }
    if (micClient == nullptr) {
        DHLOGE("Mic client should be init by dev.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    ret = micClient->SetUp(audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set up mic failed, ret: %d.", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    ret = micClient->StartCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start capture failed, ret: %d.", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    PullUpPage();
    NotifySourceDev(NOTIFY_OPEN_MIC_RESULT, jParam[KEY_DH_ID], ret);
    DHLOGI("Open mic device task end, notify source ret %d.", ret);
    isMicInUse_.store(true);
    return ret;
}

int32_t DAudioSinkDev::TaskCloseDMic(const std::string &args)
{
    DHLOGI("Close mic device.");
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::lock_guard<std::mutex> devLck(micClientMutex_);
    std::shared_ptr<DMicClient> micClient = micClientMap_[dhId];
    if (micClient == nullptr) {
        DHLOGE("Mic client is null or already closed.");
        return DH_SUCCESS;
    }

    int32_t ret = micClient->StopCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop mic client failed, ret: %d.", ret);
    }
    ret = micClient->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release mic client failed, ret: %d.", ret);
    }
    micClientMap_.erase(dhId);
    if (isPageStatus_.load()) {
        bool isSensitive = false;
        bool isSameAccount = false;
        ipcSinkCallback_->OnNotifyResourceInfo(ResourceEventType::EVENT_TYPE_CLOSE_PAGE, SUBTYPE, devId_,
            isSensitive, isSameAccount);
    }
    isPageStatus_.store(false);
    DHLOGI("Close mic device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskSetParameter(const std::string &args)
{
    DHLOGD("Set audio param.");
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, args);
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    return speakerClient->SetAudioParameters(event);
}

int32_t DAudioSinkDev::TaskSetVolume(const std::string &args)
{
    DHLOGD("Set audio volume.");
    int32_t dhId = 0;
    if (GetAudioParamInt(args, "dhId", dhId) != DH_SUCCESS) {
        DHLOGE("Get key of dhId failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    AudioEvent event(AudioEventType::VOLUME_SET, args);
    int32_t ret = speakerClient->SetAudioParameters(event);
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
    int dhId = 0;
    if (GetAudioParamInt(args, "dhId", dhId) != DH_SUCCESS) {
        DHLOGE("Get key of dhId failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    AudioEvent event(AudioEventType::VOLUME_MUTE_SET, args);
    int32_t ret = speakerClient->SetMute(event);
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
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        DHLOGE("Speaker client already closed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speakerClient->PlayStatusChange(args);
    DHLOGD("Play status change success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::SendAudioEventToRemote(const AudioEvent &event)
{
    // because: type: VOLUME_CHANGE / AUDIO_FOCUS_CHANGE / AUDIO_RENDER_STATE_CHANGE
    // so speakerClient
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    if (speakerClient == nullptr) {
        DHLOGE("Audio ctrl mgr not init.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speakerClient->SendMessage(static_cast<uint32_t>(event.type),
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

int32_t DAudioSinkDev::ConvertString2Int(std::string val)
{
    if (!CheckIsNum(val)) {
        DHLOGE("String is not number. str:%s.", val.c_str());
        return -1;
    }
    return std::stoi(val);
}

void DAudioSinkDev::PullUpPage()
{
    bool isSensitive = false;
    bool isSameAccount = false;
    ipcSinkCallback_->OnNotifyResourceInfo(ResourceEventType::EVENT_TYPE_PULL_UP_PAGE, SUBTYPE, devId_,
        isSensitive, isSameAccount);
    isPageStatus_.store(true);
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

    DHLOGD("Notify source dev, new engine, random task code:%s", std::to_string(randomTaskCode).c_str());
    if (type == NOTIFY_OPEN_CTRL_RESULT || type == NOTIFY_CLOSE_CTRL_RESULT) {
        DHLOGE("In new engine mode, ctrl is not allowed.");
        return;
    }
    int32_t dhIdInt = ConvertString2Int(dhId);
    if (dhIdInt == -1) {
        DHLOGE("Parse dhId error.");
        return;
    }
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhIdInt];
    }
    if (speakerClient != nullptr) {
        speakerClient->SendMessage(static_cast<uint32_t>(type), jEvent.dump(), devId_);
    }
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhIdInt];
    }
    if (micClient != nullptr) {
        micClient->SendMessage(static_cast<uint32_t>(type), jEvent.dump(), devId_);
    }
}

int32_t DAudioSinkDev::from_json(const json &j, AudioParam &audioParam)
{
    if (!JsonParamCheck(j, { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT,
        KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE })) {
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

int32_t DAudioSinkDev::HandleEngineMessage(uint32_t type, std::string content, std::string devId)
{
    DHLOGI("HandleEngineMessage enter.");
    return DAudioSinkManager::GetInstance().HandleDAudioNotify(devId, devId, static_cast<int32_t>(type), content);
}

DAudioSinkDev::SinkEventHandler::SinkEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::shared_ptr<DAudioSinkDev> &dev) : AppExecFwk::EventHandler(runner), sinkDev_(dev)
{
    DHLOGD("Event handler is constructing.");
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
        DHLOGE("Event Id is invaild. %d", event->GetInnerEventId());
        return;
    }
    SinkEventFunc &func = iter->second;
    (this->*func)(event);
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
    if (sinkDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS) {
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
    if (sinkDevObj->TaskStartRender(eventParam) != DH_SUCCESS) {
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

int32_t DAudioSinkDev::PauseDistributedHardware(const std::string &networkId)
{
    DHLOGI("DAudioSinkDev PauseDistributedHardware.");
    int32_t dhId = ConvertString2Int(micDhId_);
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhId];
    }
    if (micClient == nullptr) {
        DHLOGE("Mic client should be init by dev.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = micClient->PauseCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Pause mic client failed, ret: %d.", ret);
    }
    return ret;
}

int32_t DAudioSinkDev::ResumeDistributedHardware(const std::string &networkId)
{
    DHLOGI("DAudioSinkDev ResumeDistributedHardware.");
    int32_t dhId = ConvertString2Int(micDhId_);
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhId];
    }
    if (micClient == nullptr) {
        DHLOGE("Mic client should be init by dev.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = micClient->ResumeCapture();
    if (ret != DH_SUCCESS) {
        DHLOGE("Resume mic client failed, ret: %d.", ret);
    }
    return ret;
}

int32_t DAudioSinkDev::StopDistributedHardware(const std::string &networkId)
{
    DHLOGI("DAudioSinkDev StopDistributedHardware.");
    isPageStatus_.store(false);
    NotifySourceDev(CLOSE_MIC, micDhId_, DH_SUCCESS);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
