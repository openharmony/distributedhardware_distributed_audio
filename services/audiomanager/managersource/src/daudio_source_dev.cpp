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
uint32_t EVENT_OPEN_CTRL = 1;
uint32_t EVENT_CLOSE_CTRL = 2;
uint32_t EVENT_OPEN_SPEAKER = 11;
uint32_t EVENT_CLOSE_SPEAKER = 12;
uint32_t EVENT_OPEN_MIC = 21;
uint32_t EVENT_CLOSE_MIC = 22;
uint32_t EVENT_VOLUME_SET = 31;
uint32_t EVENT_VOLUME_CHANGE = 33;
uint32_t EVENT_AUDIO_FOCUS_CHANGE = 41;
uint32_t EVENT_AUDIO_RENDER_STATE_CHANGE = 42;
uint32_t EVENT_CHANGE_PLAY_STATUS = 71;
uint32_t EVENT_MMAP_SPK_START = 81;
uint32_t EVENT_MMAP_SPK_STOP = 82;
uint32_t EVENT_MMAP_MIC_START = 83;
uint32_t EVENT_MMAP_MIC_STOP = 84;
uint32_t EVENT_DAUDIO_ENABLE = 88;
uint32_t EVENT_DAUDIO_DISABLE = 89;


// reserve
// uint32_t EVENT_CTRL_OPENED = 3;
// uint32_t EVENT_CTRL_CLOSED = 4;
// uint32_t EVENT_NOTIFY_OPEN_CTRL_RESULT = 5;
// uint32_t EVENT_NOTIFY_CLOSE_CTRL_RESULT = 6;
// uint32_t EVENT_DATA_OPENED = 7;
// uint32_t EVENT_DATA_CLOSED = 8;
// uint32_t EVENT_SPEAKER_OPENED = 13;
// uint32_t EVENT_SPEAKER_CLOSED = 14;
// uint32_t EVENT_NOTIFY_OPEN_SPEAKER_RESULT = 15;
// uint32_t EVENT_NOTIFY_CLOSE_SPEAKER_RESULT = 16;
// uint32_t EVENT_MIC_OPENED = 23;
// uint32_t EVENT_MIC_CLOSED = 24;
// uint32_t EVENT_NOTIFY_OPEN_MIC_RESULT = 25;
// uint32_t EVENT_NOTIFY_CLOSE_MIC_RESULT = 26;
// uint32_t EVENT_VOLUME_GET = 32;
// uint32_t EVENT_VOLUME_MIN_GET = 34;
// uint32_t EVENT_VOLUME_MAX_GET = 35;
// uint32_t EVENT_VOLUME_MUTE_SET = 36;
// uint32_t EVENT_SET_PARAM = 51;
// uint32_t EVENT_SEND_PARAM = 52;
// uint32_t EVENT_AUDIO_ENCODER_ERR = 61;
// uint32_t EVENT_AUDIO_DECODER_ERR = 62;
// uint32_t EVENT_AUDIO_START = 85;
// uint32_t EVENT_AUDIO_STOP = 86;
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
    constexpr size_t capacity = 20;
    taskQueue_ = std::make_shared<TaskQueue>(capacity);
    taskQueue_->Start();

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
    if (taskQueue_ == nullptr) {
        DHLOGI("Task queue already stop.");
        return;
    }
    taskQueue_->Stop();
    taskQueue_ = nullptr;

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
    json jParam = { { KEY_DEV_ID, devId_ }, { KEY_DH_ID, dhId }, { KEY_ATTRS, attrs } };
    auto eventParam = std::make_shared<json>(jParam);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_ENABLE, eventParam, 0);
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Send event success.");
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
    json jParamClose = { { KEY_DH_ID, dhId } };
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, jParamClose.dump());
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
            DHLOGE("Unknown audio device.");
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }

    json jParam = { { KEY_DEV_ID, devId_ }, { KEY_DH_ID, dhId } };
    auto eventParam = std::make_shared<json>(jParam);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_DISABLE, eventParam, 0);
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Disable audio task generate success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Opening DSpeakerevent is sent success.");
    return DH_SUCCESS;;
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Closing DSpeaker event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Speaker Mmap Start event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Closing DSpeaker event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Opening ctrl trans channel event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Close ctrl trans channel event is sent success.");
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
    json jParam = json::parse(event.content, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_RESULT })) {
        return ERR_DH_AUDIO_FAILED;
    }

    rpcResult_ = (jParam[KEY_RESULT] == DH_SUCCESS) ? true : false;
    DHLOGD("Notify RPC event: %d, result: %d.", event.type, rpcResult_);
    std::map<AudioEventType, uint8_t>::iterator iter = eventNotifyMap_.find(event.type);
    if (iter == eventNotifyMap_.end()) {
        DHLOGE("Invalid eventType.");
        return ERR_DH_AUDIO_NOT_FOUND_KEY;
    }
    rpcNotify_ = iter->second;
    rpcWaitCond_.notify_all();
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Volume setting event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Volume change event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Focus change event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Render state change event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Play state change event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Speaker Mmap Start event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Speaker Mmap Stop event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Mic Mmap Start event is sent success.");
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
    handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    DHLOGD("Mic Mmap Stop event is sent success.");
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
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID, KEY_ATTRS }) || !CheckIsNum((std::string)jParam[KEY_DH_ID])) {
        DHLOGE("The keys or values is invalid.");
        return ERR_DH_AUDIO_SA_ENABLE_PARAM_INVALID;
    }
    int32_t dhId = std::stoi((std::string)jParam[KEY_DH_ID]);

    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            return EnableDSpeaker(dhId, jParam[KEY_ATTRS]);
        case AUDIO_DEVICE_TYPE_MIC:
            return EnableDMic(dhId, jParam[KEY_ATTRS]);
        default:
            DHLOGE("Unknown audio device.");
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }
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
    json jParam = json::parse(result, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        return;
    }
    mgrCallback_->OnEnableAudioResult(jParam[KEY_DEV_ID], jParam[KEY_DH_ID], resultCode);
}

int32_t DAudioSourceDev::TaskDisableDAudio(const std::string &args)
{
    DHLOGI("Task disable daudio.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID }) || !CheckIsNum((std::string)jParam[KEY_DH_ID])) {
        return ERR_DH_AUDIO_SA_DISABLE_PARAM_INVALID;
    }
    int32_t dhId = std::stoi((std::string)jParam[KEY_DH_ID]);
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            return DisableDSpeaker(dhId);
        case AUDIO_DEVICE_TYPE_MIC:
            return DisableDMic(dhId);
        default:
            DHLOGE("Unknown audio device.");
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }
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
    json jParam = json::parse(result, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        return;
    }
    mgrCallback_->OnDisableAudioResult(jParam[KEY_DEV_ID], jParam[KEY_DH_ID], resultCode);
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
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        return ERR_DH_AUDIO_FAILED;
    }

    int32_t ret = speaker_->InitSenderEngine(DAudioSourceManager::GetInstance().getSenderProvider());
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker init sender Engine, error code %d.", ret);
        return ret;
    }

    json jAudioParam;
    to_json(jAudioParam, speaker_->GetAudioParam());
    ret = NotifySinkDev(OPEN_SPEAKER, jAudioParam, jParam[KEY_DH_ID]);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open speaker failed, error code %d.", ret);
        return ret;
    }

    ret = speaker_->SetUp();
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
        json jAudioParam;
        json jParam = json::parse(args, nullptr, false);
        if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
            return ERR_DH_AUDIO_FAILED;
        }
        NotifySinkDev(CLOSE_SPEAKER, jAudioParam, jParam[KEY_DH_ID]);
    }
    if (!closeStatus) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseSpkNew(const std::string &args)
{
    DHLOGI("Close speaker new");
    json jAudioParam;
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Task close speaker, json param check failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    NotifySinkDev(CLOSE_SPEAKER, jAudioParam, jParam[KEY_DH_ID]);
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
        return ERR_DH_AUDIO_FAILED;
    }
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

    json jAudioParam;
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        return ERR_DH_AUDIO_FAILED;
    }
    to_json(jAudioParam, mic_->GetAudioParam());
    ret = NotifySinkDev(OPEN_MIC, jAudioParam, jParam[KEY_DH_ID]);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open mic failed, error code %d.", ret);
        mic_->Release();
        return ret;
    }

    ret = mic_->Start();
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
        json jAudioParam;
        json jParam = json::parse(args, nullptr, false);
        if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
            DHLOGE("Task close mic, json param check failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        NotifySinkDev(CLOSE_MIC, jAudioParam, jParam[KEY_DH_ID]);
    }
    if (!closeStatus) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseMicNew(const std::string &args)
{
    DHLOGI("Close mic new.");
    json jAudioParam;
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Task close mic, json param check failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    NotifySinkDev(CLOSE_MIC, jAudioParam, jParam[KEY_DH_ID]);

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
        return ERR_DH_AUDIO_FAILED;
    }
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

int32_t DAudioSourceDev::NotifySinkDev(const AudioEventType type, const json Param, const std::string dhId)
{
    if (!isRpcOpen_.load()) {
        DHLOGE("Network connection failure, rpc is not open!");
        return ERR_DH_AUDIO_FAILED;
    }

    std::random_device rd;
    const uint32_t randomTaskCode = rd();
    constexpr uint32_t eventOffset = 4;
    json jParam = { { KEY_DH_ID, dhId },
                    { KEY_EVENT_TYPE, type },
                    { KEY_AUDIO_PARAM, Param },
                    { KEY_RANDOM_TASK_CODE, std::to_string(randomTaskCode) } };
    DHLOGD("Notify sink dev, new engine, random task code:%s", std::to_string(randomTaskCode).c_str());
    if (speaker_ == nullptr || mic_ == nullptr) {
        DHLOGE("speaker or mic dev is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (type == OPEN_CTRL || type == CLOSE_CTRL) {
        DHLOGE("In new engine mode, ctrl is not allowed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speaker_->SendMessage(static_cast<uint32_t>(type), jParam.dump(), devId_);
    mic_->SendMessage(static_cast<uint32_t>(type), jParam.dump(), devId_);
    if (type == CLOSE_SPEAKER || type == CLOSE_MIC) {
        // Close spk || Close mic  do not need to wait RPC
        return DH_SUCCESS;
    }
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

void DAudioSourceDev::to_json(json &j, const AudioParam &param)
{
    j = json {
        { KEY_SAMPLING_RATE, param.comParam.sampleRate },   { KEY_FORMAT, param.comParam.bitFormat },
        { KEY_CHANNELS, param.comParam.channelMask },       { KEY_FRAMESIZE, param.comParam.frameSize },
        { KEY_CONTENT_TYPE, param.renderOpts.contentType }, { KEY_STREAM_USAGE, param.renderOpts.streamUsage },
        { KEY_RENDER_FLAGS, param.renderOpts.renderFlags }, { KEY_CAPTURE_FLAGS, param.captureOpts.capturerFlags },
        { KEY_SOURCE_TYPE, param.captureOpts.sourceType },
    };
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

DAudioSourceDev::SourceEventHandler::~SourceEventHandler(){}

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
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<json> jParam = event->GetSharedObject<json>();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    int32_t ret = sourceDev_.lock()->TaskEnableDAudio(jParam->dump());
    sourceDev_.lock()->OnEnableTaskResult(DH_SUCCESS, jParam->dump(), "");
    if (ret != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
        return;
    }
}

void DAudioSourceDev::SourceEventHandler::DisableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<json> jParam = event->GetSharedObject<json>();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    int32_t ret = sourceDev_.lock()->TaskDisableDAudio(jParam->dump());
    sourceDev_.lock()->OnDisableTaskResult(ret, jParam->dump(), "");
    if (ret != DH_SUCCESS) {
        DHLOGE("Disable distributed audio failed.");
        return;
    }
}

void DAudioSourceDev::SourceEventHandler::OpenDSpeakerCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskOpenDSpeaker(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::CloseDSpeakerCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskCloseDSpeaker(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::OpenDMicCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskOpenDMic(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::CloseDMicCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskCloseDMic(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::OpenCtrlCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskOpenCtrlChannel(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::CloseCtrlCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskCloseCtrlChannel(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::SetVolumeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskSetVolume(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::ChangeVolumeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskChangeVolume(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::ChangeFocusCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskChangeFocus(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::ChangeRenderStateCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskChangeRenderState(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::PlayStatusChangeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskPlayStatusChange(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskSpkMmapStart(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskSpkMmapStop(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::MicMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskMicMmapStart(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}

void DAudioSourceDev::SourceEventHandler::MicMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || sourceDev_.expired()) {
        DHLOGE("The input event or sink dev is null.");
        return;
    }
    std::shared_ptr<AudioEvent> eventParam = event->GetSharedObject<AudioEvent>();
    if (eventParam == nullptr) {
        DHLOGE("The event parameter is null.");
        return;
    }
    if (sourceDev_.lock()->TaskSpkMmapStop(eventParam->content) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed."); // TODO:
        return;
    }
    // TODO: callback
}
} // namespace DistributedHardware
} // namespace OHOS
