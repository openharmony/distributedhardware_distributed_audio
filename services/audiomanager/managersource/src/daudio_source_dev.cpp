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

#include "daudio_source_dev.h"

#include <cstring>
#include <random>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_source_manager.h"
#include "daudio_util.h"
#include "task_impl.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceDev"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint32_t EVENT_OPEN_CTRL = 1;
constexpr uint32_t EVENT_CLOSE_CTRL = 2;
constexpr uint32_t EVENT_OPEN_SPEAKER = 11;
constexpr uint32_t EVENT_CLOSE_SPEAKER = 12;
constexpr uint32_t EVENT_OPEN_MIC = 21;
constexpr uint32_t EVENT_CLOSE_MIC = 22;
constexpr uint32_t EVENT_VOLUME_SET = 31;
constexpr uint32_t EVENT_VOLUME_CHANGE = 33;
constexpr uint32_t EVENT_AUDIO_FOCUS_CHANGE = 41;
constexpr uint32_t EVENT_AUDIO_RENDER_STATE_CHANGE = 42;
constexpr uint32_t EVENT_CHANGE_PLAY_STATUS = 71;
constexpr uint32_t EVENT_MMAP_SPK_START = 81;
constexpr uint32_t EVENT_MMAP_SPK_STOP = 82;
constexpr uint32_t EVENT_MMAP_MIC_START = 83;
constexpr uint32_t EVENT_MMAP_MIC_STOP = 84;
constexpr uint32_t EVENT_DAUDIO_ENABLE = 88;
constexpr uint32_t EVENT_DAUDIO_DISABLE = 89;
}

DAudioSourceDev::DAudioSourceDev(const std::string &devId, const std::shared_ptr<DAudioSourceMgrCallback> &callback)
    : devId_(devId), mgrCallback_(callback)
{
    memberFuncMap_[OPEN_SPEAKER] = &DAudioSourceDev::HandleOpenDSpeaker;
    memberFuncMap_[CLOSE_SPEAKER] = &DAudioSourceDev::HandleCloseDSpeaker;
    memberFuncMap_[SPEAKER_OPENED] = &DAudioSourceDev::HandleDSpeakerOpened;
    memberFuncMap_[SPEAKER_CLOSED] = &DAudioSourceDev::HandleDSpeakerClosed;
    memberFuncMap_[NOTIFY_OPEN_SPEAKER_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[NOTIFY_CLOSE_SPEAKER_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[OPEN_MIC] = &DAudioSourceDev::HandleOpenDMic;
    memberFuncMap_[CLOSE_MIC] = &DAudioSourceDev::HandleCloseDMic;
    memberFuncMap_[MIC_OPENED] = &DAudioSourceDev::HandleDMicOpened;
    memberFuncMap_[MIC_CLOSED] = &DAudioSourceDev::HandleDMicClosed;
    memberFuncMap_[NOTIFY_OPEN_MIC_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[NOTIFY_CLOSE_MIC_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[NOTIFY_OPEN_CTRL_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[NOTIFY_CLOSE_CTRL_RESULT] = &DAudioSourceDev::HandleNotifyRPC;
    memberFuncMap_[CTRL_CLOSED] = &DAudioSourceDev::HandleCtrlTransClosed;
    memberFuncMap_[VOLUME_SET] = &DAudioSourceDev::HandleVolumeSet;
    memberFuncMap_[VOLUME_MUTE_SET] = &DAudioSourceDev::HandleVolumeSet;
    memberFuncMap_[VOLUME_CHANGE] = &DAudioSourceDev::HandleVolumeChange;
    memberFuncMap_[AUDIO_FOCUS_CHANGE] = &DAudioSourceDev::HandleFocusChange;
    memberFuncMap_[AUDIO_RENDER_STATE_CHANGE] = &DAudioSourceDev::HandleRenderStateChange;
    memberFuncMap_[CHANGE_PLAY_STATUS] = &DAudioSourceDev::HandlePlayStatusChange;
    memberFuncMap_[MMAP_SPK_START] = &DAudioSourceDev::HandleSpkMmapStart;
    memberFuncMap_[MMAP_SPK_STOP] = &DAudioSourceDev::HandleSpkMmapStop;
    memberFuncMap_[MMAP_MIC_START] = &DAudioSourceDev::HandleMicMmapStart;
    memberFuncMap_[MMAP_MIC_STOP] = &DAudioSourceDev::HandleMicMmapStop;

    eventNotifyMap_[NOTIFY_OPEN_SPEAKER_RESULT] = EVENT_NOTIFY_OPEN_SPK;
    eventNotifyMap_[NOTIFY_CLOSE_SPEAKER_RESULT] = EVENT_NOTIFY_CLOSE_SPK;
    eventNotifyMap_[NOTIFY_OPEN_MIC_RESULT] = EVENT_NOTIFY_OPEN_MIC;
    eventNotifyMap_[NOTIFY_CLOSE_MIC_RESULT] = EVENT_NOTIFY_CLOSE_MIC;
    eventNotifyMap_[NOTIFY_OPEN_CTRL_RESULT] = EVENT_NOTIFY_OPEN_CTRL;
    eventNotifyMap_[NOTIFY_CLOSE_CTRL_RESULT] = EVENT_NOTIFY_CLOSE_CTRL;
}

int32_t DAudioSourceDev::AwakeAudioDev()
{
    auto runner = AppExecFwk::EventRunner::Create(true);
    if (runner == nullptr) {
        DHLOGE("Create runner failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    handler_ = std::make_shared<DAudioSourceDev::SourceEventHandler>(runner, shared_from_this());
    return DH_SUCCESS;
}

void DAudioSourceDev::SleepAudioDev()
{
    if (handler_ == nullptr) {
        DHLOGI("Event handler is already stoped.");
        return;
    }
    while (!handler_->IsIdle()) {
        DHLOGD("Event handler is proccesing.");
    }
}

int32_t DAudioSourceDev::EnableDAudio(const std::string &dhId, const std::string &attrs)
{
    DHLOGI("Enable audio device, dhId: %s.", dhId.c_str());
    isRpcOpen_.store(true);
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId_.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddStringToObject(jParam, KEY_ATTRS, attrs.c_str());
    auto eventParam = std::shared_ptr<cJSON>(jParam, cJSON_Delete);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_ENABLE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Enable audio task generated successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::DisableDAudioInner(const std::string &dhId)
{
    cJSON *jParamClose = cJSON_CreateObject();
    if (jParamClose == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON_AddStringToObject(jParamClose, KEY_DH_ID, dhId.c_str());
    char *closeArg = cJSON_PrintUnformatted(jParamClose);
    if (closeArg == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParamClose);
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string closeStr(closeArg);
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, std::string(closeStr));

    int32_t dhIdNum = std::stoi(dhId);
    switch (GetDevTypeByDHId(dhIdNum)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            event.type = CLOSE_SPEAKER;
            HandleCloseDSpeaker(event);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            event.type = CLOSE_MIC;
            HandleCloseDMic(event);
            break;
        default:
            cJSON_Delete(jParamClose);
            cJSON_free(closeArg);
            DHLOGE("Unknown audio device.");
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }
    cJSON_Delete(jParamClose);
    cJSON_free(closeArg);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::DisableDAudio(const std::string &dhId)
{
    DHLOGI("Disable audio device, dhId: %s.", dhId.c_str());
    isRpcOpen_.store(false);
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!CheckIsNum(dhId)) {
        DHLOGE("Disable audio device dhId param error.");
        return ERR_DH_AUDIO_SA_DISABLE_PARAM_INVALID;
    }
    int32_t ret = DisableDAudioInner(dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to disable audio,result is: %d", ret);
        return ret;
    }

    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId_.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());

    auto eventParam = std::shared_ptr<cJSON>(jParam, cJSON_Delete);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_DISABLE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Disable audio task generated successfully.");
    return DH_SUCCESS;
}

void DAudioSourceDev::NotifyEvent(const AudioEvent &event)
{
    DHLOGD("Notify event, eventType: %d.", event.type);
    std::map<AudioEventType, DAudioSourceDevFunc>::iterator iter = memberFuncMap_.find(event.type);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid eventType.");
        return;
    }
    DAudioSourceDevFunc &func = iter->second;
    (this->*func)(event);
}

int32_t DAudioSourceDev::HandleOpenDSpeaker(const AudioEvent &event)
{
    DHLOGI("Open speaker device.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = OpenCtrlTrans(event);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_SPEAKER, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Opening DSpeaker event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCloseDSpeaker(const AudioEvent &event)
{
    DHLOGI("Close speaker device.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CLOSE_SPEAKER, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Closing DSpeaker event is sent successfully.");
    return CloseCtrlTrans(event, true);
}

int32_t DAudioSourceDev::HandleDSpeakerOpened(const AudioEvent &event)
{
    (void)event;
    DHLOGI("Speaker device opened.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDSpeakerClosed(const AudioEvent &event)
{
    DHLOGI("Speaker device closed.");
    if (speaker_ == nullptr) {
        DHLOGE("Speaker already closed.");
        return DH_SUCCESS;
    }
    return speaker_->NotifyHdfAudioEvent(event);
}

int32_t DAudioSourceDev::HandleOpenDMic(const AudioEvent &event)
{
    DHLOGI("Open mic device.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = OpenCtrlTrans(event);
    if (ret != DH_SUCCESS) {
        return ret;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_MIC, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Speaker Mmap Start event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCloseDMic(const AudioEvent &event)
{
    DHLOGI("Close mic device.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CLOSE_MIC, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Closing DSpeaker event is sent successfully.");
    return CloseCtrlTrans(event, false);
}

int32_t DAudioSourceDev::HandleDMicOpened(const AudioEvent &event)
{
    (void)event;
    DHLOGI("Mic device opened.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDMicClosed(const AudioEvent &event)
{
    DHLOGI("Mic device closed.");
    if (mic_ == nullptr) {
        DHLOGE("Mic already closed.");
        return DH_SUCCESS;
    }
    return mic_->NotifyHdfAudioEvent(event);
}

int32_t DAudioSourceDev::OpenCtrlTrans(const AudioEvent &event)
{
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseCtrlTrans(const AudioEvent &event, bool isSpk)
{
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleOpenCtrlTrans(const AudioEvent &event)
{
    DHLOGI("Open control trans.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_CTRL, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Opening ctrl trans channel event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCloseCtrlTrans(const AudioEvent &event)
{
    DHLOGI("Close control trans.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CLOSE_CTRL, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Close ctrl trans channel event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCtrlTransClosed(const AudioEvent &event)
{
    DHLOGI("Control trans closed.");
    AudioEvent audioEvent = event;
    HandleCloseCtrlTrans(audioEvent);
    if (speaker_ != nullptr && speaker_->IsOpened()) {
        audioEvent.type = SPEAKER_CLOSED;
        HandleDSpeakerClosed(audioEvent);
    }
    if (mic_ != nullptr && mic_->IsOpened()) {
        audioEvent.type = MIC_CLOSED;
        HandleDMicClosed(audioEvent);
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleNotifyRPC(const AudioEvent &event)
{
    std::lock_guard<std::mutex> dataLock(rpcWaitMutex_);
    if (event.content.length() > DAUDIO_MAX_JSON_LEN || event.content.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(event.content.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON data");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_RESULT })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }

    rpcResult_ = (cJSON_IsTrue(cJSON_GetObjectItem(jParam, KEY_RESULT)) == 1) ? true : false;
    DHLOGD("Notify RPC event: %d, result: %d.", event.type, rpcResult_);
    std::map<AudioEventType, uint8_t>::iterator iter = eventNotifyMap_.find(event.type);
    if (iter == eventNotifyMap_.end()) {
        cJSON_Delete(jParam);
        DHLOGE("Invalid eventType.");
        return ERR_DH_AUDIO_NOT_FOUND_KEY;
    }
    rpcNotify_ = iter->second;
    rpcWaitCond_.notify_all();
    cJSON_Delete(jParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleVolumeSet(const AudioEvent &event)
{
    DHLOGD("Start handle volume set.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_VOLUME_SET, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Volume setting event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleVolumeChange(const AudioEvent &event)
{
    DHLOGD("Start handle volume change.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_VOLUME_CHANGE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Volume change event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleFocusChange(const AudioEvent &event)
{
    DHLOGD("Start handle focus change.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_AUDIO_FOCUS_CHANGE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Focus change event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleRenderStateChange(const AudioEvent &event)
{
    DHLOGD("Start handle render state change.");
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_AUDIO_RENDER_STATE_CHANGE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Render state change event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandlePlayStatusChange(const AudioEvent &event)
{
    DHLOGD("Play status change, content: %s.", event.content.c_str());
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CHANGE_PLAY_STATUS, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Play state change event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleSpkMmapStart(const AudioEvent &event)
{
    DHLOGI("Spk mmap start, content: %s.", event.content.c_str());
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_START, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Speaker Mmap Start event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleSpkMmapStop(const AudioEvent &event)
{
    DHLOGI("Spk mmap stop, content: %s.", event.content.c_str());
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_STOP, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Speaker Mmap Stop event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleMicMmapStart(const AudioEvent &event)
{
    DHLOGI("Mic mmap start, content: %s.", event.content.c_str());
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_MIC_START, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Mic Mmap Start event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleMicMmapStop(const AudioEvent &event)
{
    DHLOGI("Mic mmap stop, content: %s.", event.content.c_str());
    if (handler_ == nullptr) {
        DHLOGE("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_MIC_STOP, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Mic Mmap Stop event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::WaitForRPC(const AudioEventType type)
{
    std::unique_lock<std::mutex> lck(rpcWaitMutex_);
    DHLOGI("Wait sink device notify type: %d.", type);
    auto status = rpcWaitCond_.wait_for(lck, std::chrono::seconds(RPC_WAIT_SECONDS), [this, type]() {
        switch (type) {
            case AudioEventType::NOTIFY_OPEN_SPEAKER_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_OPEN_SPK;
            case AudioEventType::NOTIFY_CLOSE_SPEAKER_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_CLOSE_SPK;
            case AudioEventType::NOTIFY_OPEN_MIC_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_OPEN_MIC;
            case AudioEventType::NOTIFY_CLOSE_MIC_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_CLOSE_MIC;
            case AudioEventType::NOTIFY_OPEN_CTRL_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_OPEN_CTRL;
            case AudioEventType::NOTIFY_CLOSE_CTRL_RESULT:
                return rpcNotify_ == EVENT_NOTIFY_CLOSE_CTRL;
            default:
                return false;
        }
    });
    if (!status) {
        DHLOGE("RPC notify wait timeout(%ds).", RPC_WAIT_SECONDS);
        return ERR_DH_AUDIO_SA_RPC_WAIT_TIMEOUT;
    }
    if (!rpcResult_) {
        DHLOGE("RPC notify Result Failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    rpcNotify_ = 0;
    rpcResult_ = false;
    DHLOGD("Receive sink device notify type: %d.", type);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskEnableDAudio(const std::string &args)
{
    DHLOGI("Enable audio device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }

    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_ATTRS }) ||
        !CheckIsNum(std::string(cJSON_GetObjectItemCaseSensitive(jParam, KEY_DH_ID)->valuestring))) {
        cJSON_Delete(jParam);
        DHLOGE("The keys or values is invalid.");
        return ERR_DH_AUDIO_SA_ENABLE_PARAM_INVALID;
    }
    cJSON *jsonDhId = cJSON_GetObjectItemCaseSensitive(jParam, KEY_DH_ID);
    if (jsonDhId == nullptr) {
        DHLOGE("Failed to get object item.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t dhId = std::atoi(jsonDhId->valuestring);
    char *attrs = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_ATTRS));
    std::string attrsStr(attrs);
    int32_t result = 0;
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            result =  EnableDSpeaker(dhId, attrsStr);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            result = EnableDMic(dhId, attrsStr);
            break;
        default:
            DHLOGE("Unknown audio device.");
            result = ERR_DH_AUDIO_NOT_SUPPORT;
            break;
    }
    cJSON_Delete(jParam);
    cJSON_free(attrs);
    return result;
}

int32_t DAudioSourceDev::EnableDSpeaker(const int32_t dhId, const std::string &attrs)
{
    if (speaker_ == nullptr) {
        DHLOGI("Create new speaker device.");
        speaker_ = std::make_shared<DSpeakerDev>(devId_, shared_from_this());
    }
    DAUDIO_SYNC_TRACE(DAUDIO_ENABLE_SPK);
    return speaker_->EnableDSpeaker(dhId, attrs);
}

int32_t DAudioSourceDev::EnableDMic(const int32_t dhId, const std::string &attrs)
{
    if (mic_ == nullptr) {
        DHLOGI("Create new mic device.");
        mic_ = std::make_shared<DMicDev>(devId_, shared_from_this());
    }
    DAUDIO_SYNC_TRACE(DAUDIO_ENABLE_MIC);
    return mic_->EnableDMic(dhId, attrs);
}

void DAudioSourceDev::OnEnableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)funcName;
    DHLOGI("On enable task result.");
    if (mgrCallback_ == nullptr) {
        DHLOGE("DAudio source manager callback is null.");
        return;
    }

    if (result.length() > DAUDIO_MAX_JSON_LEN || result.empty()) {
        return;
    }
    cJSON *jParam = cJSON_Parse(result.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return;
    }
    if (!JsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return;
    }
    char *devId = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_DEV_ID));
    std::string devIdStr(devId);
    char *dhId = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_DH_ID));
    std::string dhIdStr(dhId);
    mgrCallback_->OnEnableAudioResult(devIdStr, dhIdStr, resultCode);
    cJSON_Delete(jParam);
    if (devId != nullptr) {
        cJSON_free(devId);
    }
    if (dhId != nullptr) {
        cJSON_free(dhId);
    }
}

int32_t DAudioSourceDev::TaskDisableDAudio(const std::string &args)
{
    DHLOGI("Task disable daudio.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID }) ||
        !CheckIsNum(std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring))) {
        cJSON_Delete(jParam);
        DHLOGE("Not found the keys.");
        return ERR_DH_AUDIO_SA_DISABLE_PARAM_INVALID;
    }
    cJSON *jsonDhId = cJSON_GetObjectItemCaseSensitive(jParam, KEY_DH_ID);
    if (jsonDhId == nullptr) {
        DHLOGE("Failed to get object item.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t dhId = std::atoi(jsonDhId->valuestring);
    int32_t result = 0;
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            result = DisableDSpeaker(dhId);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            result = DisableDMic(dhId);
            break;
        default:
            DHLOGE("Unknown audio device.");
            result =  ERR_DH_AUDIO_NOT_SUPPORT;
            break;
    }
    cJSON_Delete(jParam);
    return result;
}

int32_t DAudioSourceDev::DisableDSpeaker(const int32_t dhId)
{
    if (speaker_ == nullptr) {
        DHLOGE("Speaker device is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_DISABLE_SPK);
    return speaker_->DisableDSpeaker(dhId);
}

int32_t DAudioSourceDev::DisableDMic(const int32_t dhId)
{
    if (mic_ == nullptr) {
        DHLOGE("Mic device is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_DISABLE_MIC);
    return mic_->DisableDMic(dhId);
}

void DAudioSourceDev::OnDisableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)funcName;
    DHLOGI("On disable task result.");
    if (mgrCallback_ == nullptr) {
        DHLOGE("DAudio source manager callback is null.");
        return;
    }

    if (result.length() > DAUDIO_MAX_JSON_LEN || result.empty()) {
        return;
    }
    cJSON *jParam = cJSON_Parse(result.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return;
    }
    if (!JsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return;
    }
    char *devId = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_DEV_ID));
    std::string devIdStr(devId);
    char *dhId = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_DH_ID));
    std::string dhIdStr(dhId);
    mgrCallback_->OnDisableAudioResult(devIdStr, dhIdStr, resultCode);
    cJSON_Delete(jParam);
    if (devId != nullptr) {
        cJSON_free(devId);
    }
    if (dhId != nullptr) {
        cJSON_free(dhId);
    }
}

int32_t DAudioSourceDev::TaskOpenDSpeaker(const std::string &args)
{
    DHLOGI("Task open speaker args: %s.", args.c_str());
    if (speaker_ == nullptr) {
        DHLOGE("Speaker device not init");
        return ERR_DH_AUDIO_SA_SPEAKER_DEVICE_NOT_INIT;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = speaker_->InitSenderEngine(DAudioSourceManager::GetInstance().getSenderProvider());
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker init sender Engine, error code %d.", ret);
        cJSON_Delete(jParam);
        return ret;
    }
    cJSON *jAudioParam = cJSON_CreateObject();
    if (jAudioParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        return ERR_DH_AUDIO_NULLPTR;
    }
    to_json(&jAudioParam, speaker_->GetAudioParam());
    ret = NotifySinkDev(OPEN_SPEAKER, jAudioParam, std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open speaker failed, error code %d.", ret);
        cJSON_Delete(jParam);
        cJSON_Delete(jAudioParam);
        return ret;
    }
    ret = OpenDSpeakerInner();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task Open DSpeaker Execute failed, error code %d.", ret);
        cJSON_Delete(jParam);
        cJSON_Delete(jAudioParam);
        return ret;
    }
    cJSON_Delete(jParam);
    cJSON_Delete(jAudioParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::OpenDSpeakerInner()
{
    int32_t ret = speaker_->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker setup failed, error code %d.", ret);
        return ret;
    }
    ret = speaker_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker start failed, error code %d.", ret);
        speaker_->Stop();
        speaker_->Release();
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseSpkOld(const std::string &args)
{
    DHLOGI("Close speaker old");
    bool closeStatus = true;
    int32_t ret = speaker_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker stop failed.");
        closeStatus = false;
    }
    ret = speaker_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker release failed.");
        closeStatus = false;
    }
    if (!speaker_->IsOpened()) {
        cJSON *jAudioParam = cJSON_CreateObject();
        if (jAudioParam == nullptr) {
            DHLOGE("Failed to create JSON object.");
            return ERR_DH_AUDIO_NULLPTR;
        }
        cJSON *jParam = cJSON_Parse(args.c_str());
        if (jParam == nullptr) {
            DHLOGE("Failed to parse JSON parameter.");
            cJSON_Delete(jParam);
            return ERR_DH_AUDIO_NULLPTR;
        }
        if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
            DHLOGE("Not found the keys.");
            cJSON_Delete(jParam);
            cJSON_Delete(jAudioParam);
            return ERR_DH_AUDIO_FAILED;
        }
        NotifySinkDev(CLOSE_SPEAKER, jAudioParam, std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
        cJSON_Delete(jParam);
        cJSON_Delete(jAudioParam);
    }
    if (!closeStatus) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseSpkNew(const std::string &args)
{
    DHLOGI("Close speaker new");
    cJSON *jAudioParam = cJSON_CreateObject();
    if (jAudioParam == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Task close speaker new, json param check failed.");
        cJSON_Delete(jParam);
        cJSON_Delete(jAudioParam);
        return ERR_DH_AUDIO_FAILED;
    }
    NotifySinkDev(CLOSE_SPEAKER, jAudioParam, std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    bool closeStatus = true;
    int32_t ret = speaker_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker stop failed.");
        closeStatus = false;
    }
    ret = speaker_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker release failed.");
        closeStatus = false;
    }
    if (!closeStatus) {
        cJSON_Delete(jParam);
        cJSON_Delete(jAudioParam);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON_Delete(jParam);
    cJSON_Delete(jAudioParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskCloseDSpeaker(const std::string &args)
{
    DHLOGI("Task close speaker, args: %s.", args.c_str());
    if (speaker_ == nullptr) {
        DHLOGD("Speaker already closed.");
        NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS);
        return DH_SUCCESS;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        DHLOGD("args length error.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t ret = CloseSpkNew(args);
    if (ret != DH_SUCCESS) {
        DHLOGE("Close spk in old mode failed.");
        return ret;
    }
    NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Task open mic, args: %s.", args.c_str());
    if (mic_ == nullptr) {
        DHLOGE("Mic device not init");
        return ERR_DH_AUDIO_SA_MIC_DEVICE_NOT_INIT;
    }
    int32_t ret = mic_->InitReceiverEngine(DAudioSourceManager::GetInstance().getReceiverProvider());
    if (ret != DH_SUCCESS) {
        DHLOGE("Init receiver engine failed.");
        return ret;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    ret = mic_->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic setup failed.");
        return ret;
    }

    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        cJSON_Delete(jParam);
        mic_->Release();
        return ERR_DH_AUDIO_FAILED;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }

    ret = NotifySinkDevOpenMic(jParam);
    if (ret != DH_SUCCESS) {
        cJSON_Delete(jParam);
        return ret;
    }

    ret = OpenDMicInner();
    if (ret != DH_SUCCESS) {
        cJSON_Delete(jParam);
        return ret;
    }
    cJSON_Delete(jParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::NotifySinkDevOpenMic(cJSON *jParam)
{
    cJSON *jAudioParam = cJSON_CreateObject();
    if (jAudioParam == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    to_json(&jAudioParam, mic_->GetAudioParam());
    int32_t ret = NotifySinkDev(OPEN_MIC, jAudioParam, cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open mic failed, error code %d.", ret);
        mic_->Release();
        cJSON_Delete(jAudioParam);
        return ret;
    }
    cJSON_Delete(jAudioParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::OpenDMicInner()
{
    int32_t ret = mic_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic start failed, error code %d.", ret);
        mic_->Stop();
        mic_->Release();
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseMicOld(const std::string &args)
{
    DHLOGI("Close mic old.");
    bool closeStatus = true;
    int32_t ret = mic_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic stop failed, error code %d", ret);
        closeStatus = false;
    }
    ret = mic_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic release failed, error code %d", ret);
        closeStatus = false;
    }
    if (!mic_->IsOpened()) {
        cJSON *jAudioParam = cJSON_CreateObject();
        if (jAudioParam == nullptr) {
            DHLOGE("Failed to create JSON object.");
            return ERR_DH_AUDIO_NULLPTR;
        }
        cJSON *jParam = cJSON_Parse(args.c_str());
        if (jParam == nullptr) {
            DHLOGE("Failed to parse JSON parameter.");
            cJSON_Delete(jParam);
            return ERR_DH_AUDIO_NULLPTR;
        }
        if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
            DHLOGE("Task close mic, json param check failed.");
            cJSON_Delete(jAudioParam);
            cJSON_Delete(jParam);
            return ERR_DH_AUDIO_FAILED;
        }
        NotifySinkDev(CLOSE_MIC, jAudioParam, std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
        cJSON_Delete(jAudioParam);
        cJSON_Delete(jParam);
    }
    if (!closeStatus) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseMicNew(const std::string &args)
{
    DHLOGI("Close mic new.");
    cJSON *jAudioParam = cJSON_CreateObject();
    if (jAudioParam == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON parameter.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Task close mic, json param check failed.");
        cJSON_Delete(jAudioParam);
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    NotifySinkDev(CLOSE_MIC, jAudioParam, std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));

    bool closeStatus = true;
    int32_t ret = mic_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic stop failed, error code %d", ret);
        closeStatus = false;
    }
    ret = mic_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic release failed, error code %d", ret);
        closeStatus = false;
    }
    if (!closeStatus) {
        cJSON_Delete(jAudioParam);
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON_Delete(jAudioParam);
    cJSON_Delete(jParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskCloseDMic(const std::string &args)
{
    DHLOGI("Task close mic, args: %s.", args.c_str());
    if (mic_ == nullptr) {
        DHLOGE("Mic device already closed.");
        NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS);
        return DH_SUCCESS;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t ret = CloseMicNew(args);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task close mic error.");
        return ret;
    }
    NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskOpenCtrlChannel(const std::string &args)
{
    DHLOGI("Task open ctrl channel, args: %s.", args.c_str());
    DHLOGI("Task open ctrl channel success.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskCloseCtrlChannel(const std::string &args)
{
    DHLOGI("Task close ctrl channel, args: %s.", args.c_str());
    DHLOGI("Close audio ctrl channel success.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskSetVolume(const std::string &args)
{
    DHLOGD("Task set volume, args: %s.", args.c_str());
    AudioEvent event(getEventTypeFromArgs(args), args);
    return SendAudioEventToRemote(event);
}

int32_t DAudioSourceDev::TaskChangeVolume(const std::string &args)
{
    DHLOGD("Task change volume, args: %s.", args.c_str());
    return NotifyHDF(AudioEventType::VOLUME_CHANGE, args);
}

int32_t DAudioSourceDev::TaskChangeFocus(const std::string &args)
{
    DHLOGD("Task change focus, args: %s.", args.c_str());
    return NotifyHDF(AudioEventType::AUDIO_FOCUS_CHANGE, args);
}

int32_t DAudioSourceDev::TaskChangeRenderState(const std::string &args)
{
    DHLOGD("Task change render state, args: %s.", args.c_str());
    return NotifyHDF(AudioEventType::AUDIO_RENDER_STATE_CHANGE, args);
}

int32_t DAudioSourceDev::TaskPlayStatusChange(const std::string &args)
{
    DHLOGD("Task play status change, content: %s.", args.c_str());
    AudioEvent audioEvent(CHANGE_PLAY_STATUS, args);
    int32_t ret = SendAudioEventToRemote(audioEvent);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task Play status change failed.");
        return ERR_DH_AUDIO_FAILED;
    }

    if (args == AUDIO_EVENT_RESTART) {
        ret = speaker_->Restart();
        if (ret != DH_SUCCESS) {
            DHLOGE("Speaker restart failed.");
        }
        return ret;
    } else if (args == AUDIO_EVENT_PAUSE) {
        ret = speaker_->Pause();
        if (ret != DH_SUCCESS) {
            DHLOGE("Speaker Pause failed.");
        }
        return ret;
    } else {
        DHLOGE("Play status error.");
        return ERR_DH_AUDIO_FAILED;
    }
}

int32_t DAudioSourceDev::SendAudioEventToRemote(const AudioEvent &event)
{
    // because: type: CHANGE_PLAY_STATUS / VOLUME_MUTE_SET / VOLUME_SET, so speaker
    if (speaker_ == nullptr) {
        DHLOGE("Audio ctrl mgr not init.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker_->SendMessage(static_cast<uint32_t>(event.type),
        event.content, devId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task send message to remote failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskSpkMmapStart(const std::string &args)
{
    DHLOGI("Task spk mmap start, content: %s.", args.c_str());
    if (speaker_ == nullptr) {
        DHLOGE("Task spk mmap start, speaker is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker_->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task spk mmap start fail, error code: %d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskSpkMmapStop(const std::string &args)
{
    DHLOGI("Task spk mmap stop, content: %s.", args.c_str());
    if (speaker_ == nullptr) {
        DHLOGE("Task spk mmap stop, speaker is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speaker_->MmapStop();
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskMicMmapStart(const std::string &args)
{
    DHLOGI("Task mic mmap start, content: %s.", args.c_str());
    if (mic_ == nullptr) {
        DHLOGE("Task mic mmap start, mic is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = mic_->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task mic mmap start fail, error code: %d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskMicMmapStop(const std::string &args)
{
    DHLOGI("Task mic mmap stop, content: %s.", args.c_str());
    if (mic_ == nullptr) {
        DHLOGE("Task mic mmap stop, mic is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    mic_->MmapStop();
    return DH_SUCCESS;
}

void DAudioSourceDev::OnTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)resultCode;
    (void)result;
    (void)funcName;
    DHLOGD("OnTaskResult. resultcode: %d, result: %s, funcName: %s", resultCode, result.c_str(),
        funcName.c_str());
}

void DAudioSourceDev::CleanupJson(cJSON *jParamCopy, char *content)
{
    cJSON_Delete(jParamCopy);
    cJSON_free(content);
}

int32_t DAudioSourceDev::NotifySinkDev(const AudioEventType type, const cJSON *param, const std::string dhId)
{
    if (!isRpcOpen_.load()) {
        DHLOGE("Network connection failure, rpc is not open!");
        return ERR_DH_AUDIO_FAILED;
    }

    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddNumberToObject(jParam, KEY_EVENT_TYPE, static_cast<int32_t>(type));
    cJSON *jParamCopy = cJSON_Duplicate(param, 1);
    cJSON_AddItemToObject(jParam, KEY_AUDIO_PARAM, jParamCopy);
    std::random_device rd;
    const uint32_t randomTaskCode = rd();
    constexpr uint32_t eventOffset = 4;
    cJSON_AddStringToObject(jParam, KEY_RANDOM_TASK_CODE, std::to_string(randomTaskCode).c_str());
    DHLOGD("Notify sink dev, new engine, random task code:%s", std::to_string(randomTaskCode).c_str());

    if (speaker_ == nullptr || mic_ == nullptr) {
        cJSON_Delete(jParamCopy);
        DHLOGE("speaker or mic dev is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    if (type == OPEN_CTRL || type == CLOSE_CTRL) {
        cJSON_Delete(jParamCopy);
        DHLOGE("In new engine mode, ctrl is not allowed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    char *content = cJSON_PrintUnformatted(jParam);
    std::string contentStr(content);
    speaker_->SendMessage(static_cast<uint32_t>(type), contentStr, devId_);
    mic_->SendMessage(static_cast<uint32_t>(type), contentStr, devId_);

    if (type == CLOSE_SPEAKER || type == CLOSE_MIC) {
        // Close spk || Close mic  do not need to wait RPC
        CleanupJson(jParamCopy, content);
        return DH_SUCCESS;
    }
    CleanupJson(jParamCopy, content);
    return WaitForRPC(static_cast<AudioEventType>(static_cast<int32_t>(type) + eventOffset));
}

int32_t DAudioSourceDev::NotifyHDF(const AudioEventType type, const std::string result)
{
    AudioEvent event(type, result);
    switch (type) {
        case NOTIFY_OPEN_SPEAKER_RESULT:
        case NOTIFY_CLOSE_SPEAKER_RESULT:
        case VOLUME_CHANGE:
        case AUDIO_FOCUS_CHANGE:
        case AUDIO_RENDER_STATE_CHANGE:
            if (speaker_ == nullptr) {
                DHLOGE("Speaker device not init");
                return ERR_DH_AUDIO_NULLPTR;
            }
            return speaker_->NotifyHdfAudioEvent(event);
        case NOTIFY_OPEN_MIC_RESULT:
        case NOTIFY_CLOSE_MIC_RESULT:
            if (mic_ == nullptr) {
                DHLOGE("Mic device not init");
                return ERR_DH_AUDIO_NULLPTR;
            }
            return mic_->NotifyHdfAudioEvent(event);
        default:
            DHLOGE("NotifyHDF unknown type.");
            return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

AudioEventType DAudioSourceDev::getEventTypeFromArgs(const std::string &args)
{
    std::string::size_type volume_mute_set = args.find(STREAM_MUTE_STATUS);
    if (volume_mute_set != std::string::npos) {
        return AudioEventType::VOLUME_MUTE_SET;
    }
    return AudioEventType::VOLUME_SET;
}

void DAudioSourceDev::to_json(cJSON **j, const AudioParam &param)
{
    *j = cJSON_CreateObject();
    if (*j == nullptr) {
        DHLOGE("Failed to create JSON object.");
        return;
    }
    cJSON_AddNumberToObject(*j, KEY_SAMPLING_RATE, param.comParam.sampleRate);
    cJSON_AddNumberToObject(*j, KEY_FORMAT, param.comParam.bitFormat);
    cJSON_AddNumberToObject(*j, KEY_CHANNELS, param.comParam.channelMask);
    cJSON_AddNumberToObject(*j, KEY_FRAMESIZE, param.comParam.frameSize);
    cJSON_AddNumberToObject(*j, KEY_CONTENT_TYPE, param.renderOpts.contentType);
    cJSON_AddNumberToObject(*j, KEY_STREAM_USAGE, param.renderOpts.streamUsage);
    cJSON_AddNumberToObject(*j, KEY_RENDER_FLAGS, param.renderOpts.renderFlags);
    cJSON_AddNumberToObject(*j, KEY_CAPTURE_FLAGS, param.captureOpts.capturerFlags);
    cJSON_AddNumberToObject(*j, KEY_SOURCE_TYPE, param.captureOpts.sourceType);
}

DAudioSourceDev::SourceEventHandler::SourceEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::shared_ptr<DAudioSourceDev> &dev) : AppExecFwk::EventHandler(runner), sourceDev_(dev)
{
    DHLOGD("Event handler is constructing.");
    mapEventFuncs_[EVENT_DAUDIO_ENABLE] = &DAudioSourceDev::SourceEventHandler::EnableDAudioCallback;
    mapEventFuncs_[EVENT_DAUDIO_DISABLE] = &DAudioSourceDev::SourceEventHandler::DisableDAudioCallback;
    mapEventFuncs_[EVENT_OPEN_SPEAKER] = &DAudioSourceDev::SourceEventHandler::OpenDSpeakerCallback;
    mapEventFuncs_[EVENT_CLOSE_SPEAKER] = &DAudioSourceDev::SourceEventHandler::CloseDSpeakerCallback;
    mapEventFuncs_[EVENT_OPEN_MIC] = &DAudioSourceDev::SourceEventHandler::OpenDMicCallback;
    mapEventFuncs_[EVENT_CLOSE_MIC] = &DAudioSourceDev::SourceEventHandler::CloseDMicCallback;
    mapEventFuncs_[EVENT_OPEN_CTRL] = &DAudioSourceDev::SourceEventHandler::OpenCtrlCallback;
    mapEventFuncs_[EVENT_CLOSE_CTRL] = &DAudioSourceDev::SourceEventHandler::CloseCtrlCallback;
    mapEventFuncs_[EVENT_VOLUME_SET] = &DAudioSourceDev::SourceEventHandler::SetVolumeCallback;
    mapEventFuncs_[EVENT_VOLUME_CHANGE] = &DAudioSourceDev::SourceEventHandler::ChangeVolumeCallback;
    mapEventFuncs_[EVENT_AUDIO_FOCUS_CHANGE] = &DAudioSourceDev::SourceEventHandler::ChangeFocusCallback;
    mapEventFuncs_[EVENT_AUDIO_RENDER_STATE_CHANGE] = &DAudioSourceDev::SourceEventHandler::ChangeRenderStateCallback;
    mapEventFuncs_[EVENT_CHANGE_PLAY_STATUS] = &DAudioSourceDev::SourceEventHandler::PlayStatusChangeCallback;
    mapEventFuncs_[EVENT_MMAP_SPK_START] = &DAudioSourceDev::SourceEventHandler::SpkMmapStartCallback;
    mapEventFuncs_[EVENT_MMAP_SPK_STOP] = &DAudioSourceDev::SourceEventHandler::SpkMmapStopCallback;
    mapEventFuncs_[EVENT_MMAP_MIC_START] = &DAudioSourceDev::SourceEventHandler::MicMmapStartCallback;
    mapEventFuncs_[EVENT_MMAP_MIC_STOP] = &DAudioSourceDev::SourceEventHandler::MicMmapStopCallback;
}

DAudioSourceDev::SourceEventHandler::~SourceEventHandler() {}

void DAudioSourceDev::SourceEventHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto iter = mapEventFuncs_.find(event->GetInnerEventId());
    if (iter == mapEventFuncs_.end()) {
        DHLOGE("Event Id is invaild.", event->GetInnerEventId());
        return;
    }
    SourceEventFunc &func = iter->second;
    (this->*func)(event);
}

void DAudioSourceDev::SourceEventHandler::EnableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        DHLOGE("The input event is null.");
        return;
    }
    cJSON *jParam = event->GetSharedObject<cJSON>().get();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    char* jsonString = cJSON_PrintUnformatted(jParam);
    std::string jParamStr(jsonString, jsonString + strlen(jsonString));
    if (jsonString != nullptr) {
        cJSON_free(jsonString);
    }
    DHLOGI("EnableDAudioCallback jParamStr is: %s", jParamStr.c_str());
    int32_t ret = sourceDevObj->TaskEnableDAudio(jParamStr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
    }
    sourceDevObj->OnEnableTaskResult(ret, jParamStr, "");
}

void DAudioSourceDev::SourceEventHandler::DisableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        DHLOGE("The input event is null.");
        return;
    }
    cJSON *jParam = event->GetSharedObject<cJSON>().get();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    char* jsonString = cJSON_PrintUnformatted(jParam);
    std::string jParamStr(jsonString, jsonString + strlen(jsonString));
    if (jsonString != nullptr) {
        cJSON_free(jsonString);
    }
    DHLOGI("DisableDAudioCallback jParamStr is: %s", jParamStr.c_str());
    int32_t ret = sourceDevObj->TaskDisableDAudio(jParamStr);
    if (ret != DH_SUCCESS) {
        DHLOGE("Disable distributed audio failed.");
    }
    sourceDevObj->OnDisableTaskResult(ret, jParamStr, "");
}

void DAudioSourceDev::SourceEventHandler::OpenDSpeakerCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskOpenDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Open speaker failed.");
        return;
    }
    DHLOGI("Open speaker successfully.");
}

void DAudioSourceDev::SourceEventHandler::CloseDSpeakerCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskCloseDSpeaker(eventParam) != DH_SUCCESS) {
        DHLOGE("Close speaker failed.");
        return;
    }
    DHLOGI("Close speaker successfully.");
}

void DAudioSourceDev::SourceEventHandler::OpenDMicCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskOpenDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Open mic failed.");
        return;
    }
    DHLOGI("Open mic successfully.");
}

void DAudioSourceDev::SourceEventHandler::CloseDMicCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Close mic failed.");
        return;
    }
    DHLOGI("Close mic successfully.");
}

void DAudioSourceDev::SourceEventHandler::OpenCtrlCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskOpenCtrlChannel(eventParam) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
        return;
    }
    DHLOGI("Open ctrl channel successfully.");
}

void DAudioSourceDev::SourceEventHandler::CloseCtrlCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskCloseCtrlChannel(eventParam) != DH_SUCCESS) {
        DHLOGE("Close ctrl channel failed.");
        return;
    }
    DHLOGI("Close ctrl channel successfully.");
}

void DAudioSourceDev::SourceEventHandler::SetVolumeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskSetVolume(eventParam) != DH_SUCCESS) {
        DHLOGE("Set volume failed.");
        return;
    }
    DHLOGI("Set audio volume successfully.");
}

void DAudioSourceDev::SourceEventHandler::ChangeVolumeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskChangeVolume(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process volume change event.");
        return;
    }
    DHLOGI("Processing volume change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::ChangeFocusCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskChangeFocus(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process focus change event.");
        return;
    }
    DHLOGI("Processing volume change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::ChangeRenderStateCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskChangeRenderState(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process render state change event.");
        return;
    }
    DHLOGI("Processing render state change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::PlayStatusChangeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskPlayStatusChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process playing status change event.");
        return;
    }
    DHLOGI("Processing playing status change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskSpkMmapStart(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to start speaker with mmap mode.");
        return;
    }
    DHLOGI("Start speaker with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskSpkMmapStop(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to stop speaker with mmap mode.");
        return;
    }
    DHLOGI("Stop speaker with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::MicMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskMicMmapStart(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to start mic with mmap mode.");
        return;
    }
    DHLOGI("Start mic with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::MicMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    if (sourceDevObj->TaskMicMmapStop(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to stop mic with mmap mode.");
        return;
    }
    DHLOGI("Stop mic with mmap mode successfully.");
}

int32_t DAudioSourceDev::SourceEventHandler::GetEventParam(const AppExecFwk::InnerEvent::Pointer &event,
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
