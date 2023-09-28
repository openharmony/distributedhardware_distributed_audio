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

#include "cJSON.h"

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
constexpr uint32_t EVENT_SET_THREAD_STATUS = 90;
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
    json jParam = { { KEY_DEV_ID, devId_ }, { KEY_DH_ID, dhId }, { KEY_ATTRS, attrs } };
    auto eventParam = std::make_shared<json>(jParam);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_ENABLE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Enable audio task generate successfully.");
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
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Disable audio task generate successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::RestoreThreadStatus()
{
    if (handler_ == nullptr) {
        DHLOGI("Event handler is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    json jParam;
    auto eventParam = std::make_shared<json>(jParam);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_SET_THREAD_STATUS, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Enable audio task generate successfully.");
    return DH_SUCCESS;
}

bool DAudioSourceDev::GetThreadStatusFlag()
{
    return threadStatusFlag_;
}

void DAudioSourceDev::SetThreadStatusFlag()
{
    threadStatusFlag_ = false;
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
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(event.content);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return speaker->NotifyHdfAudioEvent(event, dhId);
}

std::shared_ptr<DAudioIoDev> DAudioSourceDev::FindIoDevImpl(std::string args)
{
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return nullptr;
    }
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGE("Not find IO device instance.");
        return nullptr;
    }
    return deviceMap_[dhId];
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
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto mic = FindIoDevImpl(event.content);
    if (mic == nullptr) {
        DHLOGE("Mic already closed.");
        return DH_SUCCESS;
    }
    return mic->NotifyHdfAudioEvent(event, dhId);
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
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) != deviceMap_.end()) {
        DHLOGI("The speaker device is already enabled.");
        return DH_SUCCESS;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_ENABLE_SPK);
    auto speaker = std::make_shared<DSpeakerDev>(devId_, shared_from_this());
    if (speaker->EnableDevice(dhId, attrs) != DH_SUCCESS) {
        DHLOGI("Failed to enable speaker device.");
        return ERR_DH_AUDIO_FAILED;
    }
    deviceMap_[dhId] = speaker;
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::EnableDMic(const int32_t dhId, const std::string &attrs)
{
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) != deviceMap_.end()) {
        DHLOGI("The mic device is already enabled.");
        return DH_SUCCESS;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_ENABLE_MIC);
    auto mic = std::make_shared<DMicDev>(devId_, shared_from_this());
    if (mic->EnableDevice(dhId, attrs) != DH_SUCCESS) {
        DHLOGI("Failed to enable mic device.");
        return ERR_DH_AUDIO_FAILED;
    }
    deviceMap_[dhId] = mic;
    return DH_SUCCESS;
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
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGI("The speaker device is already disabled.");
        return DH_SUCCESS;
    }
    auto ioDev = deviceMap_[dhId];
    if (ioDev == nullptr) {
        DHLOGE("Speaker device is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_DISABLE_SPK);
    return ioDev->DisableDevice(dhId);
}

int32_t DAudioSourceDev::DisableDMic(const int32_t dhId)
{
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGI("The mic device is already disabled.");
        return DH_SUCCESS;
    }
    auto ioDev = deviceMap_[dhId];
    if (ioDev == nullptr) {
        DHLOGE("Mic device is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    DAUDIO_SYNC_TRACE(DAUDIO_DISABLE_MIC);
    return ioDev->DisableDevice(dhId);
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
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = speaker->InitSenderEngine(DAudioSourceManager::GetInstance().getSenderProvider());
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker init sender Engine, error code %d.", ret);
        return ret;
    }

    json jAudioParam;
    to_json(jAudioParam, speaker->GetAudioParam());
    ret = NotifySinkDev(OPEN_SPEAKER, jAudioParam, jParam[KEY_DH_ID]);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open speaker failed, error code %d.", ret);
        return ret;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    ret = OpenDSpeakerInner(speaker, dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task Open DSpeaker Execute failed, error code %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::ParseDhidFromEvent(std::string args)
{
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        cJSON_Delete(jParam);
        return -1;
    }
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return -1;
    }
    int32_t dhId = std::stoi(std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    cJSON_Delete(jParam);
    DHLOGI("Parsed dhId is: %d.", dhId);
    return dhId;
}

int32_t DAudioSourceDev::OpenDSpeakerInner(std::shared_ptr<DAudioIoDev> &speaker, const int32_t dhId)
{
    int32_t ret = speaker->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker setup failed, error code %d.", ret);
        return ret;
    }
    ret = speaker->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker start failed, error code %d.", ret);
        speaker->Stop();
        speaker->Release();
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseSpkOld(const std::string &args)
{
    DHLOGI("Close speaker old");
    bool closeStatus = true;
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker stop failed.");
        closeStatus = false;
    }
    ret = speaker->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker release failed.");
        closeStatus = false;
    }
    if (!speaker->IsOpened()) {
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
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker stop failed.");
        closeStatus = false;
    }
    ret = speaker->Release();
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
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGD("Speaker already closed.");
        NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
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
    NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Task open mic, args: %s.", args.c_str());
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device not init");
        return ERR_DH_AUDIO_SA_MIC_DEVICE_NOT_INIT;
    }
    int32_t ret = mic->InitReceiverEngine(DAudioSourceManager::GetInstance().getReceiverProvider());
    if (ret != DH_SUCCESS) {
        DHLOGE("Init receiver engine failed.");
        return ret;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    ret = mic->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic setup failed.");
        return ret;
    }

    json jAudioParam;
    json jParam = json::parse(args, nullptr, false);
    if (!JsonParamCheck(jParam, { KEY_DH_ID })) {
        return ERR_DH_AUDIO_FAILED;
    }
    to_json(jAudioParam, mic->GetAudioParam());
    ret = NotifySinkDev(OPEN_MIC, jAudioParam, jParam[KEY_DH_ID]);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open mic failed, error code %d.", ret);
        mic->Release();
        return ret;
    }

    ret = mic->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic start failed, error code %d.", ret);
        mic->Stop();
        mic->Release();
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, std::stoi(std::string(jParam[KEY_DH_ID])));
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseMicOld(const std::string &args)
{
    DHLOGI("Close mic old.");
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device not init");
        return DH_SUCCESS;
    }
    bool closeStatus = true;
    int32_t ret = mic->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic stop failed, error code %d", ret);
        closeStatus = false;
    }
    ret = mic->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic release failed, error code %d", ret);
        closeStatus = false;
    }
    if (!mic->IsOpened()) {
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

    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device not init");
        return DH_SUCCESS;
    }
    bool closeStatus = true;
    int32_t ret = mic->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic stop failed, error code %d", ret);
        closeStatus = false;
    }
    ret = mic->Release();
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
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device already closed.");
        NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
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
    NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
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
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = std::stoi(std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    cJSON_Delete(jParam);
    return NotifyHDF(AudioEventType::VOLUME_CHANGE, args, dhId);
}

int32_t DAudioSourceDev::TaskChangeFocus(const std::string &args)
{
    DHLOGD("Task change focus, args: %s.", args.c_str());
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId < 0) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    return NotifyHDF(AudioEventType::AUDIO_FOCUS_CHANGE, args, dhId);
}

int32_t DAudioSourceDev::TaskChangeRenderState(const std::string &args)
{
    DHLOGD("Task change render state, args: %s.", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %s", cJSON_GetErrorPtr());
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = std::stoi(std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring));
    cJSON_Delete(jParam);
    return NotifyHDF(AudioEventType::AUDIO_RENDER_STATE_CHANGE, args, dhId);
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
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (args == AUDIO_EVENT_RESTART) {
        ret = speaker->Restart();
        if (ret != DH_SUCCESS) {
            DHLOGE("Speaker restart failed.");
        }
        return ret;
    } else if (args == AUDIO_EVENT_PAUSE) {
        ret = speaker->Pause();
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
    std::shared_ptr<DAudioIoDev> speaker = nullptr;
    if (event.type == VOLUME_SET) {
        int32_t dhId = 0;
        if (GetAudioParamInt(event.content, "dhId", dhId) != DH_SUCCESS) {
            DHLOGE("Get key of dhId failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        std::lock_guard<std::mutex> devLck(ioDevMtx_);
        speaker = deviceMap_[dhId];
    } else {
        speaker = FindIoDevImpl(event.content);
    }
    if (speaker == nullptr) {
        DHLOGE("Audio ctrl mgr not init.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker->SendMessage(static_cast<uint32_t>(event.type),
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
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("Task spk mmap start, speaker is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = speaker->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task spk mmap start fail, error code: %d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskSpkMmapStop(const std::string &args)
{
    DHLOGI("Task spk mmap stop, content: %s.", args.c_str());
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("Task spk mmap start, speaker is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    speaker->MmapStop();
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskMicMmapStart(const std::string &args)
{
    DHLOGI("Task mic mmap start, content: %s.", args.c_str());
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Task mic mmap start, mic is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = mic->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task mic mmap start fail, error code: %d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskMicMmapStop(const std::string &args)
{
    DHLOGI("Task mic mmap stop, content: %s.", args.c_str());
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Task mic mmap stop, mic is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    mic->MmapStop();
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

    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(std::stoi(dhId)) == deviceMap_.end()) {
        DHLOGE("speaker or mic dev is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto ioDev = deviceMap_[std::stoi(dhId)];
    if (type == OPEN_CTRL || type == CLOSE_CTRL) {
        DHLOGE("In new engine mode, ctrl is not allowed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    ioDev->SendMessage(static_cast<uint32_t>(type), jParam.dump(), devId_);
    if (type == CLOSE_SPEAKER || type == CLOSE_MIC) {
        // Close spk || Close mic  do not need to wait RPC
        return DH_SUCCESS;
    }
    return WaitForRPC(static_cast<AudioEventType>(static_cast<int32_t>(type) + eventOffset));
}

int32_t DAudioSourceDev::NotifyHDF(const AudioEventType type, const std::string result, const int32_t dhId)
{
    DHLOGI("Notify HDF framework the result, event type: %d; result: %s.", type, result.c_str());
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGE("Speaker or mic dev is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto ioDev = deviceMap_[dhId];
    AudioEvent event(type, result);
    switch (type) {
        case NOTIFY_OPEN_SPEAKER_RESULT:
        case NOTIFY_CLOSE_SPEAKER_RESULT:
        case VOLUME_CHANGE:
        case AUDIO_FOCUS_CHANGE:
        case AUDIO_RENDER_STATE_CHANGE:
            return ioDev->NotifyHdfAudioEvent(event, dhId);
        case NOTIFY_OPEN_MIC_RESULT:
        case NOTIFY_CLOSE_MIC_RESULT:
            return ioDev->NotifyHdfAudioEvent(event, dhId);
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
    mapEventFuncs_[EVENT_SET_THREAD_STATUS] = &DAudioSourceDev::SourceEventHandler::SetThreadStatusFlagTrue;
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
    std::shared_ptr<json> jParam = event->GetSharedObject<json>();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    int32_t ret = sourceDevObj->TaskEnableDAudio(jParam->dump());
    if (ret != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
    }
    sourceDevObj->OnEnableTaskResult(ret, jParam->dump(), "");
}

void DAudioSourceDev::SourceEventHandler::DisableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        DHLOGE("The input event is null.");
        return;
    }
    std::shared_ptr<json> jParam = event->GetSharedObject<json>();
    if (jParam == nullptr) {
        DHLOGE("The json parameter is null.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    if (sourceDevObj == nullptr) {
        DHLOGE("Source dev is invalid.");
        return;
    }
    int32_t ret = sourceDevObj->TaskDisableDAudio(jParam->dump());
    if (ret != DH_SUCCESS) {
        DHLOGE("Disable distributed audio failed.");
    }
    sourceDevObj->OnDisableTaskResult(ret, jParam->dump(), "");
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

void DAudioSourceDev::SourceEventHandler::SetThreadStatusFlagTrue(const AppExecFwk::InnerEvent::Pointer &event)
{
    (void) event;
    auto sourceDevobj = sourceDev_.lock();
    if (sourceDevobj == nullptr) {
        DHLOGE("Source dev is invaild.");
        return;
    }
    sourceDevobj->threadStatusFlag_ = true;
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
