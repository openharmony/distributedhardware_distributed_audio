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
    DHLOGD("Distributed audio sink device constructed, devId: %{public}s.", GetAnonyString(devId).c_str());
}

DAudioSinkDev::~DAudioSinkDev()
{
    SetDevLevelStatus(false);
    DHLOGD("Distributed audio sink device destructed, devId: %{public}s.", GetAnonyString(devId_).c_str());
}

int32_t DAudioSinkDev::AwakeAudioDev()
{
    auto runner = AppExecFwk::EventRunner::Create(true);
    CHECK_NULL_RETURN(runner, ERR_DH_AUDIO_NULLPTR);
    handler_ = std::make_shared<DAudioSinkDev::SinkEventHandler>(runner, shared_from_this());
    return DH_SUCCESS;
}

void DAudioSinkDev::SleepAudioDev()
{
    DHLOGD("Sleep audio dev.");
    CHECK_NULL_VOID(handler_);
    while (!handler_->IsIdle()) {
        DHLOGD("handler is running, wait for idle.");
        usleep(WAIT_HANDLER_IDLE_TIME_US);
    }
    DHLOGI("Sleep audio dev over.");
}

int32_t DAudioSinkDev::InitAVTransEngines(const ChannelState channelState, IAVEngineProvider *providerPtr)
{
    DHLOGI("Init InitAVTransEngines");
    CHECK_NULL_RETURN(providerPtr, ERR_DH_AUDIO_FAILED);

    if (channelState == ChannelState::UNKNOWN) {
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
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
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
    DHLOGD("Notify event, eventType: %{public}d.", (int32_t)audioEvent.type);
    if ((int32_t)audioEvent.type == DISABLE_DEVICE) {
        TaskDisableDevice(audioEvent.content);
        return;
    }
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    CHECK_NULL_VOID(handler_);
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
    DHLOGI("Open speaker device, args = %{public}s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        cJSON_Delete(jParam);
        DHLOGE("Not found the keys.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    CHECK_AND_FREE_RETURN_RET_LOG(dhId == -1, ERR_DH_AUDIO_NULLPTR, jParam,
        "%{public}s", "Parse dhId error.");
    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhId];
    }
    cJSON *audioParamJson = cJSON_GetObjectItem(jParam, KEY_AUDIO_PARAM);
    AudioParam audioParam;
    int32_t ret = from_json(audioParamJson, audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from cjson failed, error code %{public}d.", ret);
        cJSON_Delete(jParam);
        return ret;
    }
    CHECK_NULL_FREE_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR, jParam);
    ret = speakerClient->SetUp(audioParam);
    CHECK_AND_FREE_RETURN_RET_LOG(ret != DH_SUCCESS, ret, jParam,
        "Setup speaker failed, ret: %{public}d.", ret);
    isSpkInUse_.store(true);
    cJSON_Delete(jParam);
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
    CHECK_NULL_RETURN(speakerClient, DH_SUCCESS);

    int32_t ret = speakerClient->StopRender();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker client failed, ret: %{public}d.", ret);
    }
    ret = speakerClient->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker client failed, ret: %{public}d.", ret);
    }
    spkClientMap_.erase(dhId);
    DHLOGI("Close speaker device task excute success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::ParseDhidFromEvent(std::string args)
{
    DHLOGI("ParseDhidFrom args : %{public}s", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_FAILED);

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
    DHLOGI("Parsed dhId is: %{public}d.", dhId);
    return dhId;
}

int32_t DAudioSinkDev::ParseResultFromEvent(std::string args)
{
    DHLOGI("ParseResultFrom args : %{public}s", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_FAILED);

    if (!CJsonParamCheck(jParam, { KEY_RESULT })) {
        DHLOGE("Not found the keys of result.");
        cJSON_Delete(jParam);
        return -1;
    }
    cJSON *retItem = cJSON_GetObjectItem(jParam, KEY_RESULT);
    if (retItem == NULL || !cJSON_IsNumber(retItem)) {
        DHLOGE("Not found the keys of result.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = retItem->valueint;
    cJSON_Delete(jParam);
    DHLOGI("Parsed result is: %{public}d.", ret);
    return ret;
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);

    int32_t ret = speakerClient->StartRender();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret,
        "Start render failed. ret: %{public}d.", ret);
    DHLOGI("Start render success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Open mic device.");
    if (!isDevLevelStatus_) {
        DHLOGI("Dev security level status is false.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    AudioParam audioParam;
    cJSON *audioParamJson = cJSON_GetObjectItem(jParam, KEY_AUDIO_PARAM);
    int32_t ret = from_json(audioParamJson, audioParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param from cjson failed, error code %{public}d.", ret);
        cJSON_Delete(jParam);
        return ret;
    }
    CHECK_AND_FREE_RETURN_RET_LOG(ret != DH_SUCCESS, ret, jParam,
        "Get audio param from cjson failed, error code %{public}d.", ret);
    int32_t dhId = ParseDhidFromEvent(args);
    CHECK_AND_FREE_RETURN_RET_LOG(dhId == -1, ERR_DH_AUDIO_NULLPTR, jParam,
        "%{public}s", "Parse dhId error.");
    micDhId_ = std::to_string(dhId);
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhId];
    }
    CHECK_NULL_FREE_RETURN(micClient, ERR_DH_AUDIO_NULLPTR, jParam);
    ret = micClient->SetUp(audioParam);
    CHECK_AND_FREE_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED, jParam,
        "Set up mic failed, ret: %{public}d.", ret);
    ret = micClient->StartCapture();
    CHECK_AND_FREE_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED, jParam,
        "Start capture failed, ret: %{public}d.", ret);
    PullUpPage();
    isMicInUse_.store(true);
    cJSON_Delete(jParam);
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
    CHECK_NULL_RETURN(micClient, DH_SUCCESS);

    int32_t ret = micClient->StopCapture();
    CHECK_AND_LOG(ret != DH_SUCCESS, "Stop mic client failed, ret: %{public}d.", ret);
    ret = micClient->Release();
    CHECK_AND_LOG(ret != DH_SUCCESS, "Release mic client failed, ret: %{public}d.", ret);
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);

    AudioEvent event(AudioEventType::VOLUME_SET, args);
    int32_t ret = speakerClient->SetAudioParameters(event);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret,
        "Volume set failed, ret: %{public}d.", ret);
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);

    AudioEvent event(AudioEventType::VOLUME_MUTE_SET, args);
    int32_t ret = speakerClient->SetMute(event);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret,
        "Set mute failed, ret: %{public}d.", ret);
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
    DHLOGD("Play status change, content: %{public}s.", args.c_str());
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(speakerClient, ERR_DH_AUDIO_NULLPTR);

    int32_t ret = speakerClient->SendMessage(static_cast<uint32_t>(event.type),
        event.content, devId_);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_NULLPTR,
        "%{public}s", "Task send message to remote failed.");
    return DH_SUCCESS;
}

void DAudioSinkDev::JudgeDeviceStatus()
{
    DHLOGI("Checking device's status.");
    if (isSpkInUse_.load() || isMicInUse_.load()) {
        DHLOGI("Device contain periperials in using, speaker status: %{public}d, mic status: %{public}d.",
            isSpkInUse_.load(), isMicInUse_.load());
        return;
    }
    DAudioSinkManager::GetInstance().OnSinkDevReleased(devId_);
}

void DAudioSinkDev::SetDevLevelStatus(bool checkStatus)
{
    isDevLevelStatus_ = checkStatus;
}

int32_t DAudioSinkDev::ConvertString2Int(std::string val)
{
    if (!CheckIsNum(val)) {
        DHLOGE("String is not number. str:%{public}s.", val.c_str());
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
    cJSON *jEvent = cJSON_CreateObject();
    CHECK_NULL_VOID(jEvent);
    cJSON_AddStringToObject(jEvent, KEY_DH_ID, dhId.c_str());
    cJSON_AddNumberToObject(jEvent, KEY_RESULT, result);
    cJSON_AddNumberToObject(jEvent, KEY_EVENT_TYPE, static_cast<int32_t>(type));
    cJSON_AddStringToObject(jEvent, KEY_RANDOM_TASK_CODE, std::to_string(randomTaskCode).c_str());

    DHLOGI("Notify source dev, new engine, random task code:%{public}s", std::to_string(randomTaskCode).c_str());
    int32_t dhIdInt = ConvertString2Int(dhId);
    if (dhIdInt == -1) {
        DHLOGE("Parse dhId error.");
        cJSON_Delete(jEvent);
        return;
    }
    char *data = cJSON_PrintUnformatted(jEvent);
    if (data == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jEvent);
        return;
    }
    std::string message(data);

    std::shared_ptr<ISpkClient> speakerClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(spkClientMutex_);
        speakerClient = spkClientMap_[dhIdInt];
    }
    if (speakerClient != nullptr) {
        speakerClient->SendMessage(static_cast<uint32_t>(type), message, devId_);
    }
    std::shared_ptr<DMicClient> micClient = nullptr;
    {
        std::lock_guard<std::mutex> devLck(micClientMutex_);
        micClient = micClientMap_[dhIdInt];
    }
    if (micClient != nullptr) {
        micClient->SendMessage(static_cast<uint32_t>(type), message, devId_);
    }
    cJSON_Delete(jEvent);
    cJSON_free(data);
}

int32_t DAudioSinkDev::GetParamValue(const cJSON *j, const char* key, int32_t &value)
{
    cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(j, key);
    if (paramValue == nullptr || !cJSON_IsNumber(paramValue)) {
        return ERR_DH_AUDIO_FAILED;
    }
    value = paramValue->valueint;
    return DH_SUCCESS;
}

int32_t DAudioSinkDev::GetCJsonObjectItems(const cJSON *j, AudioParam &audioParam)
{
    int32_t ret = 0;
    ret = GetParamValue(j, KEY_SAMPLING_RATE, reinterpret_cast<int32_t&>(audioParam.comParam.sampleRate));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_CHANNELS, reinterpret_cast<int32_t&>(audioParam.comParam.channelMask));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_FORMAT, reinterpret_cast<int32_t&>(audioParam.comParam.bitFormat));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_FRAMESIZE, reinterpret_cast<int32_t&>(audioParam.comParam.frameSize));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_SOURCE_TYPE, reinterpret_cast<int32_t&>(audioParam.captureOpts.sourceType));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_CONTENT_TYPE, reinterpret_cast<int32_t&>(audioParam.renderOpts.contentType));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_STREAM_USAGE, reinterpret_cast<int32_t&>(audioParam.renderOpts.streamUsage));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_RENDER_FLAGS, reinterpret_cast<int32_t&>(audioParam.renderOpts.renderFlags));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    ret = GetParamValue(j, KEY_CAPTURE_FLAGS, reinterpret_cast<int32_t&>(audioParam.captureOpts.capturerFlags));
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "%{public}s", "Get param value error.");
    return ret;
}

int32_t DAudioSinkDev::from_json(const cJSON  *j, AudioParam &audioParam)
{
    if (!CJsonParamCheck(j, { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT,
        KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE })) {
        DHLOGE("Not found the keys of dhId");
        return ERR_DH_AUDIO_FAILED;
    }
    if (GetCJsonObjectItems(j, audioParam) != DH_SUCCESS) {
        DHLOGE("Get Cjson Object Items failed.");
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
        DHLOGE("Event Id is invaild. %{public}d", event->GetInnerEventId());
        return;
    }
    SinkEventFunc &func = iter->second;
    (this->*func)(event);
}

void DAudioSinkDev::SinkEventHandler::NotifyCtrlOpened(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Ctrl channel is opened. begin to init dev, then to notify source dev.");
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);

    int32_t dhId = sinkDevObj->ParseDhidFromEvent(eventParam);
    CHECK_AND_RETURN_LOG(dhId == -1, "%{public}s", "Parse dhId error.");
    int32_t ret = sinkDevObj->ParseResultFromEvent(eventParam);
    sinkDevObj->NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, std::to_string(dhId), ret);
    DHLOGI("Init sink device task end, notify source ret %{public}d.", ret);
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "%{public}s", "Init sink device failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyCtrlClosed(const AppExecFwk::InnerEvent::Pointer &event)
{
    DHLOGI("Notify ctrl closed.");
    (void)event;
}

void DAudioSinkDev::SinkEventHandler::NotifyOpenSpeaker(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);

    int32_t dhId = sinkDevObj->ParseDhidFromEvent(eventParam);
    CHECK_AND_RETURN_LOG(dhId == -1, "%{public}s", "Parse dhId error.");
    int32_t ret = sinkDevObj->TaskOpenDSpeaker(eventParam);
    sinkDevObj->NotifySourceDev(NOTIFY_OPEN_SPEAKER_RESULT, std::to_string(dhId), ret);
    DHLOGI("Open speaker device task end, notify source ret %{public}d.", ret);
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "%{public}s", "Open speaker failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyCloseSpeaker(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS,
        "%{public}s", "close speaker failed.");
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
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskStartRender(eventParam) != DH_SUCCESS,
        "%{public}s", "Speaker client start failed.");
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskVolumeChange(eventParam) != DH_SUCCESS,
        "%{public}s", "Notify pimary volume to source device failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifySpeakerClosed(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS,
        "%{public}s", "Close speaker failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyOpenMic(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);

    cJSON *jParam = cJSON_Parse(eventParam.c_str());
    CHECK_NULL_VOID(jParam);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID, KEY_AUDIO_PARAM })) {
        DHLOGE("Json param check failed.");
        cJSON_Delete(jParam);
        return;
    }
    int32_t ret = sinkDevObj->TaskOpenDMic(eventParam);
    sinkDevObj->NotifySourceDev(NOTIFY_OPEN_MIC_RESULT,
        std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring), ret);
    DHLOGI("Open mic device task end, notify source ret %{public}d.", ret);
    CHECK_AND_FREE_RETURN_LOG(ret != DH_SUCCESS, jParam, "%{public}s", "Open mic failed.");
    cJSON_Delete(jParam);
}

void DAudioSinkDev::SinkEventHandler::NotifyCloseMic(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS,
        "%{public}s", "Close mic failed.");
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
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS,
        "%{public}s", "Close mic failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifySetVolume(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskSetVolume(eventParam) != DH_SUCCESS,
        "%{public}s", "Set volume failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyVolumeChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskVolumeChange(eventParam) != DH_SUCCESS,
        "%{public}s", "Notify volume change status to source device failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifySetParam(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskSetParameter(eventParam) != DH_SUCCESS,
        "%{public}s", "Set parameters failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifySetMute(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskSetMute(eventParam) != DH_SUCCESS,
        "%{public}s", "Set mute failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyFocusChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskFocusChange(eventParam) != DH_SUCCESS,
        "%{public}s", "Handle focus change event failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyRenderStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskRenderStateChange(eventParam) != DH_SUCCESS,
        "%{public}s", "Handle render state change failed.");
}

void DAudioSinkDev::SinkEventHandler::NotifyPlayStatusChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sinkDevObj = sinkDev_.lock();
    CHECK_NULL_VOID(sinkDevObj);
    CHECK_AND_RETURN_LOG(sinkDevObj->TaskPlayStatusChange(eventParam) != DH_SUCCESS,
        "%{public}s", "Handle play status change event failed.");
}

int32_t DAudioSinkDev::SinkEventHandler::GetEventParam(const AppExecFwk::InnerEvent::Pointer &event,
    std::string &eventParam)
{
    CHECK_NULL_RETURN(event, ERR_DH_AUDIO_NULLPTR);
    std::shared_ptr<AudioEvent> paramObj = event->GetSharedObject<AudioEvent>();
    CHECK_NULL_RETURN(paramObj, ERR_DH_AUDIO_NULLPTR);
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

    CHECK_NULL_RETURN(micClient, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = micClient->PauseCapture();
    CHECK_AND_LOG(ret != DH_SUCCESS, "Pause mic client failed, ret: %{public}d.", ret);
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

    CHECK_NULL_RETURN(micClient, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = micClient->ResumeCapture();
    CHECK_AND_LOG(ret != DH_SUCCESS, "Resume mic client failed, ret: %{public}d.", ret);
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
