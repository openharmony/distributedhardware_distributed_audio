/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "daudio_radar.h"
#include "daudio_source_manager.h"
#include "daudio_util.h"

#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "ipc_skeleton.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceDev"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint32_t EVENT_OPEN_SPEAKER = 11;
constexpr uint32_t EVENT_CLOSE_SPEAKER = 12;
constexpr uint32_t EVENT_OPEN_MIC = 21;
constexpr uint32_t EVENT_CLOSE_MIC = 22;
constexpr uint32_t EVENT_DMIC_CLOSED = 24;
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
    CHECK_NULL_RETURN(runner, ERR_DH_AUDIO_NULLPTR);
    handler_ = std::make_shared<DAudioSourceDev::SourceEventHandler>(runner, shared_from_this());
    return DH_SUCCESS;
}

void DAudioSourceDev::SleepAudioDev()
{
    DHLOGD("Sleep audio dev.");
    CHECK_NULL_VOID(handler_);
    while (!handler_->IsIdle()) {
        DHLOGD("handler is running, wait for idle.");
        usleep(WAIT_HANDLER_IDLE_TIME_US);
    }
    DHLOGI("Sleep audio dev over.");
}

void DAudioSourceDev::SetRegDataType(const std::string &capability)
{
    DHLOGI("SetRegDataType enter.");
    cJSON *jParam = cJSON_Parse(capability.c_str());
    CHECK_NULL_VOID(jParam);
    if (!CJsonParamCheck(jParam, { KEY_DATATYPE })) {
        DHLOGE("The key dataType is not found.");
        cJSON_Delete(jParam);
        return;
    }
    cJSON *dataType = cJSON_GetObjectItem(jParam, KEY_DATATYPE);
    if (dataType == nullptr || !cJSON_IsString(dataType)) {
        DHLOGE("The key dataType is null.");
        cJSON_Delete(jParam);
        return;
    }
    DHLOGI("RegData type is : %{public}s.", dataType->valuestring);
    std::string typeStr(dataType->valuestring);
    if (typeStr == KEY_TYPE_FULL) {
        isFull_.store(true);
    } else {
        isFull_.store(false);
    }
    cJSON_Delete(jParam);
}

int32_t DAudioSourceDev::EnableDAudio(const std::string &dhId, const std::string &attrs)
{
    DHLOGI("Enable audio device, dhId: %{public}s.", dhId.c_str());
    isRpcOpen_.store(true);
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId_.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddStringToObject(jParam, KEY_ATTRS, attrs.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_FREE_RETURN(jsonString, ERR_DH_AUDIO_NULLPTR, jParam);
    auto eventParam = std::make_shared<std::string>(jsonString);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_ENABLE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        cJSON_Delete(jParam);
        cJSON_free(jsonString);
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Enable audio task generate successfully.");
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
    if (!isFull_.load()) {
        SetRegDataType(attrs);
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::DisableDAudioInner(const std::string &dhId)
{
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId_.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_FREE_RETURN(jsonString, ERR_DH_AUDIO_NULLPTR, jParam);
    auto eventParam = std::make_shared<std::string>(jsonString);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DAUDIO_DISABLE, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        cJSON_Delete(jParam);
        cJSON_free(jsonString);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::DisableDAudio(const std::string &dhId)
{
    DHLOGI("Disable audio device, dhId: %{public}s.", dhId.c_str());
    isRpcOpen_.store(false);

    cJSON *jParamClose = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParamClose, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParamClose, KEY_DH_ID, dhId.c_str());
    char *data = cJSON_PrintUnformatted(jParamClose);
    CHECK_NULL_FREE_RETURN(data, ERR_DH_AUDIO_NULLPTR, jParamClose);
    AudioEvent event(AudioEventType::EVENT_UNKNOWN, std::string(data));
    int32_t dhIdNum = ConvertString2Int(dhId);
    if (dhIdNum == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Parse dhId error.");
        cJSON_Delete(jParamClose);
        cJSON_free(data);
        return ERR_DH_AUDIO_NOT_SUPPORT;
    }
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
            cJSON_free(data);
            DHLOGE("Unknown audio device. dhId: %{public}d.", dhIdNum);
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }
    cJSON_Delete(jParamClose);
    cJSON_free(data);
    int32_t ret = DisableDAudioInner(dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to disable audio device, result is: %{public}d.", ret);
        return ret;
    }
    DHLOGI("Disable audio task generate successfully.");
    return DH_SUCCESS;
}

bool DAudioSourceDev::GetThreadStatusFlag()
{
    return threadStatusFlag_;
}

void DAudioSourceDev::SetThreadStatusFlag(bool flag)
{
    threadStatusFlag_ = flag;
}

void DAudioSourceDev::NotifyEventInner(const AudioEvent &event)
{
    switch (event.type) {
        case OPEN_MIC:
            HandleOpenDMic(event);
            break;
        case CLOSE_MIC:
            HandleCloseDMic(event);
            break;
        case MIC_OPENED:
            HandleDMicOpened(event);
            break;
        case MIC_CLOSED:
            HandleDMicClosed(event);
            break;
        case CTRL_CLOSED:
            HandleCtrlTransClosed(event);
            break;
        case VOLUME_SET:
        case VOLUME_MUTE_SET:
            HandleVolumeSet(event);
            break;
        case VOLUME_CHANGE:
            HandleVolumeChange(event);
            break;
        case AUDIO_FOCUS_CHANGE:
            HandleFocusChange(event);
            break;
        case AUDIO_RENDER_STATE_CHANGE:
            HandleRenderStateChange(event);
            break;
        case CHANGE_PLAY_STATUS:
            HandlePlayStatusChange(event);
            break;
        case MMAP_SPK_START:
            HandleSpkMmapStart(event);
            break;
        case MMAP_SPK_STOP:
            HandleSpkMmapStop(event);
            break;
        case MMAP_MIC_START:
            HandleMicMmapStart(event);
            break;
        case MMAP_MIC_STOP:
            HandleMicMmapStop(event);
            break;
        default:
            break;
    }
}

void DAudioSourceDev::NotifyEvent(const AudioEvent &event)
{
    switch (event.type) {
        case OPEN_SPEAKER:
            HandleOpenDSpeaker(event);
            break;
        case CLOSE_SPEAKER:
            HandleCloseDSpeaker(event);
            break;
        case SPEAKER_OPENED:
            HandleDSpeakerOpened(event);
            break;
        case SPEAKER_CLOSED:
            HandleDSpeakerClosed(event);
            break;
        case NOTIFY_OPEN_SPEAKER_RESULT:
        case NOTIFY_CLOSE_SPEAKER_RESULT:
        case NOTIFY_OPEN_MIC_RESULT:
        case NOTIFY_CLOSE_MIC_RESULT:
        case NOTIFY_OPEN_CTRL_RESULT:
        case NOTIFY_CLOSE_CTRL_RESULT:
            HandleNotifyRPC(event);
            break;
#ifdef AUDIO_SUPPORT_SHARED_BUFFER
        case AUDIO_START:
        case AUDIO_STOP:
            HandleAudioStatus(event);
            break;
#endif
        case OPEN_MIC:
        case CLOSE_MIC:
        case MIC_OPENED:
        case MIC_CLOSED:
        case CTRL_CLOSED:
        case VOLUME_SET:
        case VOLUME_MUTE_SET:
        case VOLUME_CHANGE:
        case AUDIO_FOCUS_CHANGE:
        case AUDIO_RENDER_STATE_CHANGE:
        case CHANGE_PLAY_STATUS:
        case MMAP_SPK_START:
        case MMAP_SPK_STOP:
        case MMAP_MIC_START:
        case MMAP_MIC_STOP:
            NotifyEventInner(event);
            break;
        default:
            DHLOGE("Invalid eventType: %{public}d.", event.type);
            break;
    }
}

#ifdef AUDIO_SUPPORT_SHARED_BUFFER
void DAudioSourceDev::HandleAudioStatus(const AudioEvent &event)
{
    switch (event.type) {
        case AUDIO_START:
            HandleAudioStart(event);
            break;
        case AUDIO_STOP:
            HandleAudioStop(event);
            break;
        default:
            break;
    }
}

int32_t DAudioSourceDev::HandleAudioStart(const AudioEvent &event)
{
    DHLOGI("Audio start, content: %{public}s.", event.content.c_str());
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    if (dhId == PIN_IN_MIC) {
        DHLOGI("MIC start");
        return DH_SUCCESS;
    }
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_START, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Mmap Start event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleAudioStop(const AudioEvent &event)
{
    DHLOGI("Audio mmap stop, content: %{public}s.", event.content.c_str());
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    if (dhId == PIN_IN_MIC) {
        DHLOGI("MIC stop");
        return DH_SUCCESS;
    }
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_STOP, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Speaker Mmap Stop event is sent successfully.");
    return DH_SUCCESS;
}
#endif

int32_t DAudioSourceDev::HandleOpenDSpeaker(const AudioEvent &event)
{
    DHLOGI("Open speaker device.");
    CHECK_AND_RETURN_RET_LOG(!CheckAclRight(), ERR_DH_AUDIO_FAILED, "ACL check failed.");

    bool isInvalid = false;
    CHECK_AND_RETURN_RET_LOG(CheckOsType(devId_, isInvalid) && isInvalid, ERR_DH_AUDIO_FAILED,
        "GetOsType failed or invalid osType");
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_SPEAKER, eventParam, 0);
    CHECK_AND_RETURN_RET_LOG(!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE),
        ERR_DH_AUDIO_FAILED, "Send event failed.");
    DHLOGD("Opening DSpeaker event is sent successfully.");
    return DH_SUCCESS;
}

bool DAudioSourceDev::CheckAclRight()
{
    CHECK_AND_RETURN_RET_LOG(!GetOsAccountInfo(), false, "GetOsAccountInfo failed.");
    std::shared_ptr<DmInitCallback> initCallback = std::make_shared<DeviceInitCallback>();
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, initCallback);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, false, "InitDeviceManager failed ret = %{public}d", ret);
    GetLocalDeviceNetworkId(srcDevId_);
    DmAccessCaller dmSrcCaller;
    dmSrcCaller.accountId = accountId_;
    dmSrcCaller.pkgName = PKG_NAME;
    dmSrcCaller.networkId = srcDevId_;
    dmSrcCaller.userId = userId_;
    dmSrcCaller.tokenId = tokenId_;

    DmAccessCallee dmDstCallee;
    dmDstCallee.networkId = devId_;
    DHLOGI("CheckAclRight dmSrcCaller networkId: %{public}s, accountId: %{public}s, devId: %{public}s",
        GetAnonyString(srcDevId_).c_str(), GetAnonyString(accountId_).c_str(), GetAnonyString(devId_).c_str());
    CHECK_AND_RETURN_RET_LOG(DeviceManager::GetInstance().CheckSrcAccessControl(dmSrcCaller, dmDstCallee),
        true, "ACL pass");
    return false;
}

bool DAudioSourceDev::GetOsAccountInfo()
{
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    int32_t ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, false,
        "Get userId from active os accountIds fail, ret: %{public}d", ret);
    if (ids.empty()) {
        userId_ = 0;
    } else {
        userId_ = ids[0];
    }

    AccountSA::OhosAccountInfo osAccountInfo;
    ret = AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(osAccountInfo);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, false,
        "Get accountId from ohos account info fail, ret: %{public}d", ret);
    accountId_ = osAccountInfo.uid_;
#endif
    return true;
}

void DeviceInitCallback::OnRemoteDied()
{
    DHLOGI("DeviceInitCallback OnRemoteDied");
}

int32_t DAudioSourceDev::HandleCloseDSpeaker(const AudioEvent &event)
{
    DHLOGI("Close speaker device.");
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CLOSE_SPEAKER, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Closing DSpeaker event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDSpeakerOpened(const AudioEvent &event)
{
    (void)event;
    DHLOGI("Speaker device opened.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDSpeakerClosed(const AudioEvent &event)
{
    DHLOGI("Speaker device closed, event.content = %{public}s.", event.content.c_str());
    int32_t dhId = ParseDhidFromEvent(event.content);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(event.content);
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    return speaker->NotifyHdfAudioEvent(event, dhId);
}

std::shared_ptr<DAudioIoDev> DAudioSourceDev::FindIoDevImpl(std::string args)
{
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
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
    CHECK_AND_RETURN_RET_LOG(!CheckAclRight(), ERR_DH_AUDIO_FAILED, "ACL check failed.");

    bool isInvalid = false;
    CHECK_AND_RETURN_RET_LOG(CheckOsType(devId_, isInvalid) && isInvalid, ERR_DH_AUDIO_FAILED,
        "GetOsType failed or invalid osType");
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_MIC, eventParam, 0);
    CHECK_AND_RETURN_RET_LOG(!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE),
        ERR_DH_AUDIO_FAILED, "Send event failed.");
    DHLOGD("Opening DMic event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCloseDMic(const AudioEvent &event)
{
    DHLOGI("Close mic device.");
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_CLOSE_MIC, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Closing DMic event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDMicOpened(const AudioEvent &event)
{
    (void)event;
    DHLOGD("Mic device opened.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleDMicClosed(const AudioEvent &event)
{
    DHLOGI("Dmic device closed, event.content = %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DMIC_CLOSED, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGD("Dmic closed event is sent successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleCtrlTransClosed(const AudioEvent &event)
{
    DHLOGD("Control trans closed.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::HandleNotifyRPC(const AudioEvent &event)
{
    std::lock_guard<std::mutex> dataLock(rpcWaitMutex_);
    if (event.content.length() > DAUDIO_MAX_JSON_LEN || event.content.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(event.content.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    if (!CJsonParamCheck(jParam, { KEY_RESULT })) {
        DHLOGE("Not found the keys of result.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }

    rpcResult_ = cJSON_GetObjectItem(jParam, KEY_RESULT)->valueint;
    DHLOGD("Notify RPC event: %{public}d, result: %{public}d.", event.type, rpcResult_);
    std::map<AudioEventType, uint8_t>::iterator iter = eventNotifyMap_.find(event.type);
    if (iter == eventNotifyMap_.end()) {
        DHLOGE("Invalid eventType.");
        cJSON_Delete(jParam);
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
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGD("Play status change, content: %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Spk mmap start, content: %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Spk mmap stop, content: %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Mic mmap start, content: %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Mic mmap stop, content: %{public}s.", event.content.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Wait sink device notify type: %{public}d.", type);
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
        DHLOGE("RPC notify wait timeout(%{public}ds).", RPC_WAIT_SECONDS);
        return ERR_DH_AUDIO_SA_WAIT_TIMEOUT;
    }
    if (rpcResult_ != DH_SUCCESS) {
        DHLOGE("RPC notify Result Failed.");
        return rpcResult_;
    }
    rpcNotify_ = 0;
    rpcResult_ = ERR_DH_AUDIO_FAILED;
    DHLOGD("Receive sink device notify type: %{public}d.", type);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskEnableDAudio(const std::string &args)
{
    DHLOGI("Enable audio device.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID, KEY_ATTRS })) {
        DHLOGE("The keys or values is invalid.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    CHECK_AND_FREE_RETURN_RET_LOG(dhId == ERR_DH_AUDIO_FAILED, ERR_DH_AUDIO_NOT_SUPPORT,
        jParam, "%{public}s", "Parse dhId error.");
    char *attrs = cJSON_PrintUnformatted(cJSON_GetObjectItem(jParam, KEY_ATTRS));
    CHECK_NULL_FREE_RETURN(attrs, ERR_DH_AUDIO_NULLPTR, jParam);
    std::string attrsStr(attrs);
    int32_t result = 0;
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            result = EnableDSpeaker(dhId, attrsStr);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            result = EnableDMic(dhId, attrsStr);
            break;
        default:
            DHLOGE("Unknown audio device. dhId: %{public}d.", dhId);
            result = ERR_DH_AUDIO_NOT_SUPPORT;
    }
    cJSON_Delete(jParam);
    cJSON_free(attrs);
    return result;
}

int32_t DAudioSourceDev::EnableDSpeaker(const int32_t dhId, const std::string &attrs)
{
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) != deviceMap_.end()) {
        DHLOGI("The speaker device is enabled, enable it with new data this time.");
        CHECK_NULL_RETURN(deviceMap_[dhId], ERR_DH_AUDIO_NULLPTR);
        if (deviceMap_[dhId]->EnableDevice(dhId, attrs) != DH_SUCCESS) {
            DHLOGI("Failed to enable speaker device with new data.");
            return ERR_DH_AUDIO_FAILED;
        }
        return DH_SUCCESS;
    }
    auto speaker = std::make_shared<DSpeakerDev>(devId_, shared_from_this());
    if (speaker->EnableDevice(dhId, attrs) != DH_SUCCESS) {
        DHLOGI("Failed to enable speaker device first time.");
        return ERR_DH_AUDIO_FAILED;
    }
    deviceMap_[dhId] = speaker;
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::EnableDMic(const int32_t dhId, const std::string &attrs)
{
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) != deviceMap_.end()) {
        DHLOGI("The mic device is enabled, enable it with new data this time.");
        CHECK_NULL_RETURN(deviceMap_[dhId], ERR_DH_AUDIO_NULLPTR);
        if (deviceMap_[dhId]->EnableDevice(dhId, attrs) != DH_SUCCESS) {
            DHLOGI("Failed to enable mic device with new data.");
            return ERR_DH_AUDIO_FAILED;
        }
        return DH_SUCCESS;
    }
    auto mic = std::make_shared<DMicDev>(devId_, shared_from_this());
    if (mic->EnableDevice(dhId, attrs) != DH_SUCCESS) {
        DHLOGI("Failed to enable mic device first time.");
        return ERR_DH_AUDIO_FAILED;
    }
    deviceMap_[dhId] = mic;
    return DH_SUCCESS;
}

void DAudioSourceDev::OnEnableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)funcName;
    DHLOGI("On enable task result.");
    CHECK_NULL_VOID(mgrCallback_);
    if (result.length() > DAUDIO_MAX_JSON_LEN || result.empty()) {
        return;
    }
    cJSON *jParam = cJSON_Parse(result.c_str());
    CHECK_NULL_VOID(jParam);
    if (!CJsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return;
    }
    mgrCallback_->OnEnableAudioResult(std::string(cJSON_GetObjectItem(jParam, KEY_DEV_ID)->valuestring),
        std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring), resultCode);
    cJSON_Delete(jParam);
}

int32_t DAudioSourceDev::TaskDisableDAudio(const std::string &args)
{
    DHLOGI("Task disable daudio.");
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Parse dhId error. hdId: %{public}d.", dhId);
        return ERR_DH_AUDIO_NULLPTR;
    }

    DHLOGI("Parsed dhId = %{public}d", dhId);
    int32_t ret = ERR_DH_AUDIO_NOT_SUPPORT;
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            ret = DisableDSpeaker(dhId);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            ret = DisableDMic(dhId);
            break;
        default:
            DHLOGE("Unknown audio device. hdId: %{public}d.", dhId);
    }
    DaudioRadar::GetInstance().ReportDaudioUnInit("OnDisableDAudio", AudioUnInit::DISABLED,
        BizState::BIZ_STATE_END, ret);
    return ret;
}

int32_t DAudioSourceDev::DisableDSpeaker(const int32_t dhId)
{
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGI("The speaker device is already disabled.");
        return DH_SUCCESS;
    }
    auto ioDev = deviceMap_[dhId];
    CHECK_NULL_RETURN(ioDev, ERR_DH_AUDIO_NULLPTR);
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
    CHECK_NULL_RETURN(ioDev, ERR_DH_AUDIO_NULLPTR);
    return ioDev->DisableDevice(dhId);
}

void DAudioSourceDev::OnDisableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)funcName;
    DHLOGI("On disable task result.");
    CHECK_NULL_VOID(mgrCallback_);
    if (result.length() > DAUDIO_MAX_JSON_LEN || result.empty()) {
        return;
    }
    cJSON *jParam = cJSON_Parse(result.c_str());
    CHECK_NULL_VOID(jParam);
    if (!CJsonParamCheck(jParam, { KEY_DEV_ID, KEY_DH_ID })) {
        DHLOGE("Not found the keys.");
        cJSON_Delete(jParam);
        return;
    }
    mgrCallback_->OnDisableAudioResult(std::string(cJSON_GetObjectItem(jParam, KEY_DEV_ID)->valuestring),
        std::string(cJSON_GetObjectItem(jParam, KEY_DH_ID)->valuestring), resultCode);
    cJSON_Delete(jParam);
}

void DAudioSourceDev::NotifyFwkRunning(const std::string &devId, const std::string &dhId)
{
    DAudioSourceManager::GetInstance().OnHardwareStateChanged(devId, dhId, DaudioBusinessState::RUNNING);
    if (!isFull_.load()) {
        DAudioSourceManager::GetInstance().OnDataSyncTrigger(devId);
    }
}

void DAudioSourceDev::NotifyFwkIdle(const std::string &devId, const std::string &dhId)
{
    DAudioSourceManager::GetInstance().OnHardwareStateChanged(devId, dhId, DaudioBusinessState::IDLE);
}

int32_t DAudioSourceDev::CreateSpkEngine(std::shared_ptr<DAudioIoDev> speaker)
{
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speaker->InitSenderEngine(DAudioSourceManager::GetInstance().getSenderProvider());
    DaudioRadar::GetInstance().ReportSpeakerOpenProgress("InitSenderEngine", SpeakerOpen::INIT_ENGINE, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker init sender Engine, error code %{public}d.", ret);
        return ret;
    }
    ret = speaker->InitCtrlTrans();
    DaudioRadar::GetInstance().ReportSpeakerOpenProgress("InitCtrlTrans", SpeakerOpen::TRANS_CONTROL, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker InitCtrlTrans, error code %{public}d.", ret);
        return ret;
    }
    ret = WaitForRPC(NOTIFY_OPEN_CTRL_RESULT);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker init sender engine, create ctrl error.");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskOpenDSpeaker(const std::string &args)
{
    DAudioHitrace trace("DAudioSourceDev::TaskOpenDSpeaker");
    DHLOGI("Task open speaker args: %{public}s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        DHLOGE("args length error. 0 or max.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("The IO device is invaild.");
        NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_RESULT_FAILED, dhId);
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = CreateSpkEngine(speaker);
    if (ret != DH_SUCCESS) {
        DHLOGE("Create speaker engine failed.");
        NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_INIT_ENGINE_FAILED, dhId);
        return ret;
    }
    cJSON *jAudioParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jAudioParam, ERR_DH_AUDIO_NULLPTR);
    to_json(jAudioParam, speaker->GetAudioParam());
    std::string dhIdString = std::to_string(dhId);
    ret = NotifySinkDev(OPEN_SPEAKER, jAudioParam, dhIdString);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open speaker failed, error code %{public}d.", ret);
        cJSON_Delete(jAudioParam);
        NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_NOTIFY_SINK_FAILED, dhId);
        return ret;
    }
    ret = OpenDSpeakerInner(speaker, dhId);
    if (ret != DH_SUCCESS) {
        cJSON_Delete(jAudioParam);
        DHLOGE("Task Open DSpeaker Execute failed, error code %{public}d.", ret);
        return ret;
    }
    NotifyFwkRunning(devId_, std::to_string(dhId));
    cJSON_Delete(jAudioParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::ParseDhidFromEvent(std::string args)
{
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_FAILED);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON *dhIdItem = cJSON_GetObjectItem(jParam, KEY_DH_ID);
    if (dhIdItem == NULL || !cJSON_IsString(dhIdItem)) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(dhIdItem->valuestring));
    cJSON_Delete(jParam);
    DHLOGD("Parsed dhId is: %{public}d.", dhId);
    return dhId;
}

int32_t DAudioSourceDev::ConvertString2Int(std::string val)
{
    if (!CheckIsNum(val)) {
        DHLOGE("String is not number. str:%{public}s.", val.c_str());
        return ERR_DH_AUDIO_FAILED;
    }
    return std::atoi(val.c_str());
}

int32_t DAudioSourceDev::OpenDSpeakerInner(std::shared_ptr<DAudioIoDev> &speaker, const int32_t dhId)
{
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speaker->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker setup failed, error code %{public}d.", ret);
        NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_TRANS_SETUP_FAILED, dhId);
        return ret;
    }
    ret = speaker->Start();
    DaudioRadar::GetInstance().ReportSpeakerOpen("Start", SpeakerOpen::NOTIFY_HDF,
        BizState::BIZ_STATE_END, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker start failed, error code %{public}d.", ret);
        speaker->Stop();
        speaker->Release();
        NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_TRANS_START_FAILED, dhId);
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseSpkNew(const std::string &args)
{
    DHLOGI("Close speaker new");
    cJSON *jAudioParam = nullptr;
    int32_t dhId = ParseDhidFromEvent(args);
    CHECK_AND_RETURN_RET_LOG(dhId == ERR_DH_AUDIO_FAILED, ERR_DH_AUDIO_NULLPTR,
        "%{public}s", "Parse dhId error.");
    NotifySinkDev(CLOSE_SPEAKER, jAudioParam, std::to_string(dhId));
    bool closeStatus = true;
    auto speaker = FindIoDevImpl(args);
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    if (speaker->Stop() != DH_SUCCESS) {
        DHLOGE("Speaker stop failed.");
        closeStatus = false;
    }
    if (speaker->Release() != DH_SUCCESS) {
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
    DHLOGI("Task close speaker, args: %{public}s.", args.c_str());
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(args);
    if (speaker == nullptr) {
        DHLOGE("Speaker already closed.");
        NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
        return DH_SUCCESS;
    }
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        DHLOGE("args length error.");
        NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_FAILED, dhId);
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t ret = CloseSpkNew(args);
    DaudioRadar::GetInstance().ReportSpeakerClose("CloseSpkNew", SpeakerClose::NOTIFY_HDF,
        BizState::BIZ_STATE_END, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Close spk failed.");
        NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_FAILED, dhId);
        return ret;
    }
    NotifyHDF(NOTIFY_CLOSE_SPEAKER_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    NotifyFwkIdle(devId_, std::to_string(dhId));
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CreateMicEngine(std::shared_ptr<DAudioIoDev> mic)
{
    if (mic == nullptr) {
        DHLOGE("Mic device not init");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = mic->InitReceiverEngine(DAudioSourceManager::GetInstance().getReceiverProvider());
    DaudioRadar::GetInstance().ReportMicOpenProgress("InitReceiverEngine", MicOpen::INIT_ENGINE, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init receiver engine failed.");
        return ret;
    }
    ret = mic->InitCtrlTrans();
    DaudioRadar::GetInstance().ReportMicOpenProgress("InitCtrlTrans", MicOpen::TRANS_CONTROL, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("mic InitCtrlTrans, error code %{public}d.", ret);
        return ret;
    }
    ret = WaitForRPC(NOTIFY_OPEN_CTRL_RESULT);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic init sender engine, create ctrl error.");
        return ret;
    }
    ret = mic->SetUp();
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic setup failed.");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskOpenDMic(const std::string &args)
{
    DHLOGI("Task open mic, args: %{public}s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    CHECK_AND_RETURN_RET_LOG(dhId == ERR_DH_AUDIO_FAILED, ERR_DH_AUDIO_FAILED,
        "%{public}s", "Failed to parse dhardware id.");
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device not init");
        NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_RESULT_FAILED, dhId);
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = CreateMicEngine(mic);
    if (ret != DH_SUCCESS) {
        DHLOGE("Create mic engine failed.");
        NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_INIT_ENGINE_FAILED, dhId);
        return ret;
    }
    cJSON *jAudioParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jAudioParam, ERR_DH_AUDIO_NULLPTR);
    to_json(jAudioParam, mic->GetAudioParam());
    ret = NotifySinkDev(OPEN_MIC, jAudioParam, std::to_string(dhId));
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify sink open mic failed, error code %{public}d.", ret);
        mic->Release();
        NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_NOTIFY_SINK_FAILED, dhId);
        cJSON_Delete(jAudioParam);
        return ret;
    }
    ret = mic->Start();
    DaudioRadar::GetInstance().ReportMicOpen("Start", MicOpen::NOTIFY_HDF,
        BizState::BIZ_STATE_END, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Mic start failed, error code %{public}d.", ret);
        mic->Stop();
        mic->Release();
        NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_TRANS_START_FAILED, dhId);
        cJSON_Delete(jAudioParam);
        return ret;
    }
    NotifyHDF(NOTIFY_OPEN_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    NotifyFwkRunning(devId_, std::to_string(dhId));
    cJSON_Delete(jAudioParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::CloseMicNew(const std::string &args)
{
    DHLOGI("Close mic new.");
    cJSON *jAudioParam = nullptr;
    int32_t dhId = ParseDhidFromEvent(args);
    CHECK_AND_RETURN_RET_LOG(dhId == ERR_DH_AUDIO_FAILED, ERR_DH_AUDIO_NULLPTR,
        "%{public}s", "Parse dhId error.");
    NotifySinkDev(CLOSE_MIC, jAudioParam, std::to_string(dhId));

    auto mic = FindIoDevImpl(args);
    CHECK_NULL_RETURN(mic, DH_SUCCESS);
    if (mic->Stop() != DH_SUCCESS || mic->Release() != DH_SUCCESS) {
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskCloseDMic(const std::string &args)
{
    DHLOGI("Task close mic, args: %{public}s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        DHLOGE("Args length err. 0 or max.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto mic = FindIoDevImpl(args);
    if (mic == nullptr) {
        DHLOGE("Mic device already closed.");
        NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
        return DH_SUCCESS;
    }
    int32_t ret = CloseMicNew(args);
    DaudioRadar::GetInstance().ReportMicClose("CloseMicNew", MicClose::NOTIFY_HDF,
        BizState::BIZ_STATE_END, ret);
    if (ret != DH_SUCCESS) {
        DHLOGE("Task close mic error.");
        NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_FAILED, dhId);
        return ret;
    }
    NotifyHDF(NOTIFY_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS, dhId);
    NotifyFwkIdle(devId_, std::to_string(dhId));
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskDMicClosed(const std::string &args)
{
    DHLOGI("Task dmic closed, args: %{public}s.", args.c_str());
    if (args.length() > DAUDIO_MAX_JSON_LEN || args.empty()) {
        DHLOGE("Args length err. 0 or max.");
        return ERR_DH_AUDIO_SA_PARAM_INVALID;
    }
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto mic = FindIoDevImpl(args);
    CHECK_NULL_RETURN(mic, DH_SUCCESS);
    AudioEvent event(MIC_CLOSED, args);
    return mic->NotifyHdfAudioEvent(event, dhId);
}

int32_t DAudioSourceDev::TaskSetVolume(const std::string &args)
{
    DHLOGD("Task set volume, args: %{public}s.", args.c_str());
    AudioEvent event(getEventTypeFromArgs(args), args);
    return SendAudioEventToRemote(event);
}

int32_t DAudioSourceDev::TaskChangeVolume(const std::string &args)
{
    DHLOGD("Task change volume, args: %{public}s.", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON *dhIdItem = cJSON_GetObjectItem(jParam, KEY_DH_ID);
    if (dhIdItem == NULL || !cJSON_IsString(dhIdItem)) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(dhIdItem->valuestring));
    cJSON_Delete(jParam);
    return NotifyHDF(AudioEventType::VOLUME_CHANGE, args, dhId);
}

int32_t DAudioSourceDev::TaskChangeFocus(const std::string &args)
{
    DHLOGD("Task change focus, args: %{public}s.", args.c_str());
    int32_t dhId = ParseDhidFromEvent(args);
    if (dhId == ERR_DH_AUDIO_FAILED) {
        DHLOGE("Failed to parse dhardware id.");
        return ERR_DH_AUDIO_FAILED;
    }
    return NotifyHDF(AudioEventType::AUDIO_FOCUS_CHANGE, args, dhId);
}

int32_t DAudioSourceDev::TaskChangeRenderState(const std::string &args)
{
    DHLOGD("Task change render state, args: %{public}s.", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);

    if (!CJsonParamCheck(jParam, { KEY_DH_ID })) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON *dhIdItem = cJSON_GetObjectItem(jParam, KEY_DH_ID);
    if (dhIdItem == NULL || !cJSON_IsString(dhIdItem)) {
        DHLOGE("Not found the keys of dhId.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t dhId = ConvertString2Int(std::string(dhIdItem->valuestring));
    cJSON_Delete(jParam);
    return NotifyHDF(AudioEventType::AUDIO_RENDER_STATE_CHANGE, args, dhId);
}

int32_t DAudioSourceDev::TaskPlayStatusChange(const std::string &args)
{
    DHLOGD("Task play status change, content: %{public}s.", args.c_str());
    AudioEvent audioEvent(CHANGE_PLAY_STATUS, args);
    if (SendAudioEventToRemote(audioEvent) != DH_SUCCESS) {
        DHLOGE("Task Play status change failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto speaker = FindIoDevImpl(args);
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);

    std::string changeType = ParseStringFromArgs(args, KEY_CHANGE_TYPE);
    if (changeType == AUDIO_EVENT_RESTART) {
        if (speaker->Restart() != DH_SUCCESS) {
            DHLOGE("Speaker restart failed.");
            return ERR_DH_AUDIO_FAILED;
        }
    } else if (changeType == AUDIO_EVENT_PAUSE) {
        if (speaker->Pause() != DH_SUCCESS) {
            DHLOGE("Speaker Pause failed.");
            return ERR_DH_AUDIO_FAILED;
        }
    } else {
        DHLOGE("Play status error.");
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::SendAudioEventToRemote(const AudioEvent &event)
{
    // because: type: CHANGE_PLAY_STATUS / VOLUME_MUTE_SET / VOLUME_SET, so speaker
    std::shared_ptr<DAudioIoDev> speaker = nullptr;
    if (event.type == VOLUME_SET || event.type == VOLUME_MUTE_SET) {
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

    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
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
    DHLOGI("Task spk mmap start, content: %{public}s.", args.c_str());
    auto speaker = FindIoDevImpl(args);
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = speaker->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task spk mmap start fail, error code: %{public}d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskSpkMmapStop(const std::string &args)
{
    DHLOGI("Task spk mmap stop, content: %{public}s.", args.c_str());
    auto speaker = FindIoDevImpl(args);
    CHECK_NULL_RETURN(speaker, ERR_DH_AUDIO_NULLPTR);
    speaker->MmapStop();
    return DH_SUCCESS;
}

int32_t DAudioSourceDev::TaskMicMmapStart(const std::string &args)
{
    DHLOGI("Task mic mmap start, content: %{public}s.", args.c_str());
    auto mic = FindIoDevImpl(args);
    CHECK_NULL_RETURN(mic, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = mic->MmapStart();
    if (ret != DH_SUCCESS) {
        DHLOGE("Task mic mmap start fail, error code: %{public}d.", ret);
    }
    return ret;
}

int32_t DAudioSourceDev::TaskMicMmapStop(const std::string &args)
{
    DHLOGI("Task mic mmap stop, content: %{public}s.", args.c_str());
    auto mic = FindIoDevImpl(args);
    CHECK_NULL_RETURN(mic, ERR_DH_AUDIO_NULLPTR);
    mic->MmapStop();
    return DH_SUCCESS;
}

void DAudioSourceDev::OnTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName)
{
    (void)resultCode;
    (void)result;
    (void)funcName;
    DHLOGD("OnTaskResult. resultcode: %{public}d, result: %{public}s, funcName: %{public}s", resultCode, result.c_str(),
        funcName.c_str());
}

int32_t DAudioSourceDev::NotifySinkDev(const AudioEventType type, const cJSON *Param, const std::string dhId)
{
    CHECK_AND_RETURN_RET_LOG(!isRpcOpen_.load(), ERR_DH_AUDIO_FAILED, "Network connection failure, rpc is not open!");
    std::random_device rd;
    const uint32_t randomTaskCode = rd();
    constexpr uint32_t eventOffset = 4;
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddNumberToObject(jParam, KEY_EVENT_TYPE, static_cast<int32_t>(type));
    cJSON_AddNumberToObject(jParam, KEY_USERID, static_cast<int32_t>(userId_));
    cJSON_AddNumberToObject(jParam, KEY_TOKENID, static_cast<int32_t>(tokenId_));
    cJSON_AddStringToObject(jParam, KEY_ACCOUNTID, accountId_.c_str());
    cJSON *jParamCopy = cJSON_Duplicate(Param, 1);
    cJSON_AddItemToObject(jParam, KEY_AUDIO_PARAM, jParamCopy);
    cJSON_AddStringToObject(jParam, KEY_RANDOM_TASK_CODE, std::to_string(randomTaskCode).c_str());
    DHLOGI("Notify sink dev, new engine, random task code:%{public}s", std::to_string(randomTaskCode).c_str());
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    int32_t dhIdInt = ConvertString2Int(dhId);
    CHECK_AND_FREE_RETURN_RET_LOG(deviceMap_.find(dhIdInt) == deviceMap_.end(), ERR_DH_AUDIO_NULLPTR,
        jParam, "speaker or mic dev is null. find index: %{public}d.", dhIdInt);
    auto ioDev = deviceMap_[dhIdInt];
    CHECK_AND_FREE_RETURN_RET_LOG(type == OPEN_CTRL || type == CLOSE_CTRL, ERR_DH_AUDIO_NULLPTR,
        jParam, "In new engine mode, ctrl is not allowed.");
    char *content = cJSON_PrintUnformatted(jParam);
    CHECK_AND_FREE_RETURN_RET_LOG(content == nullptr, ERR_DH_AUDIO_NULLPTR, jParam, "Failed to create JSON data");
    if (ioDev == nullptr) {
        cJSON_Delete(jParam);
        cJSON_free(content);
        return ERR_DH_AUDIO_NULLPTR;
    }
    ioDev->SendMessage(static_cast<uint32_t>(type), std::string(content), devId_);
    if (type == CLOSE_SPEAKER || type == CLOSE_MIC) {
        // Close spk || Close mic  do not need to wait RPC
        cJSON_Delete(jParam);
        cJSON_free(content);
        return DH_SUCCESS;
    }
    cJSON_Delete(jParam);
    cJSON_free(content);
    return WaitForRPC(static_cast<AudioEventType>(static_cast<int32_t>(type) + eventOffset));
}

int32_t DAudioSourceDev::NotifyHDF(const AudioEventType type, const std::string result, const int32_t dhId)
{
    DHLOGI("Notify HDF framework the result, event type: %{public}d; result: %{public}s.", type, result.c_str());
    std::lock_guard<std::mutex> devLck(ioDevMtx_);
    if (deviceMap_.find(dhId) == deviceMap_.end()) {
        DHLOGE("Speaker or mic dev is null. dhId: %{public}d", dhId);
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto ioDev = deviceMap_[dhId];
    CHECK_NULL_RETURN(ioDev, ERR_DH_AUDIO_NULLPTR);
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

void DAudioSourceDev::to_json(cJSON *j, const AudioParam &param)
{
    CHECK_NULL_VOID(j);
    cJSON_AddNumberToObject(j, KEY_SAMPLING_RATE, param.comParam.sampleRate);
    cJSON_AddNumberToObject(j, KEY_FORMAT, param.comParam.bitFormat);
    cJSON_AddNumberToObject(j, KEY_CHANNELS, param.comParam.channelMask);
    cJSON_AddNumberToObject(j, KEY_FRAMESIZE, param.comParam.frameSize);
    cJSON_AddNumberToObject(j, KEY_CODEC_TYPE, param.comParam.codecType);
    cJSON_AddNumberToObject(j, KEY_CONTENT_TYPE, param.renderOpts.contentType);
    cJSON_AddNumberToObject(j, KEY_STREAM_USAGE, param.renderOpts.streamUsage);
    cJSON_AddNumberToObject(j, KEY_RENDER_FLAGS, param.renderOpts.renderFlags);
    cJSON_AddNumberToObject(j, KEY_CAPTURE_FLAGS, param.captureOpts.capturerFlags);
    cJSON_AddNumberToObject(j, KEY_SOURCE_TYPE, param.captureOpts.sourceType);
}

void DAudioSourceDev::SetTokenId(uint64_t value)
{
    tokenId_ = value;
}

int32_t DAudioSourceDev::ParseValueFromCjson(std::string args, std::string key)
{
    DHLOGD("ParseValueFromCjson");
    cJSON *jParam = cJSON_Parse(args.c_str());
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_FAILED);
    CHECK_AND_FREE_RETURN_RET_LOG(!CJsonParamCheck(jParam, { key }), ERR_DH_AUDIO_FAILED, jParam, "Not found key");
    cJSON *retItem = cJSON_GetObjectItem(jParam, key.c_str());
    CHECK_AND_FREE_RETURN_RET_LOG(retItem == NULL || !cJSON_IsNumber(retItem),
        ERR_DH_AUDIO_FAILED, jParam, "Not found key result");
    int32_t ret = retItem->valueint;
    cJSON_Delete(jParam);
    return ret;
}

int32_t DAudioSourceDev::CheckOsType(std::string &networkId, bool &isInvalid)
{
    std::vector<DistributedHardware::DmDeviceInfo> dmDeviceInfoList;
    int32_t errCode = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", dmDeviceInfoList);
    CHECK_AND_RETURN_RET_LOG(errCode != DH_SUCCESS, ERR_DH_AUDIO_FAILED,
        "Get device manager trusted device list fail, errCode %{public}d", errCode);
    for (const auto& dmDeviceInfo : dmDeviceInfoList) {
        if (dmDeviceInfo.networkId == networkId) {
            int32_t osType = ParseValueFromCjson(dmDeviceInfo.extraData, KEY_OS_TYPE);
            if (osType == INVALID_OS_TYPE && osType != ERR_DH_AUDIO_FAILED) {
                isInvalid = true;
            }
            DHLOGI("remote found, osType: %{public}d, isInvalid: %{public}d", osType, isInvalid);
            return DH_SUCCESS;
        }
    }
    DHLOGI("remote not found.");
    return DH_SUCCESS;
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
    mapEventFuncs_[EVENT_DMIC_CLOSED] = &DAudioSourceDev::SourceEventHandler::DMicClosedCallback;
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

void DAudioSourceDev::SourceEventHandler::ProcessEventInner(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    switch (event->GetInnerEventId()) {
        case EVENT_VOLUME_SET:
            SetVolumeCallback(event);
            break;
        case EVENT_VOLUME_CHANGE:
            ChangeVolumeCallback(event);
            break;
        case EVENT_AUDIO_FOCUS_CHANGE:
            ChangeFocusCallback(event);
            break;
        case EVENT_AUDIO_RENDER_STATE_CHANGE:
            ChangeRenderStateCallback(event);
            break;
        case EVENT_CHANGE_PLAY_STATUS:
            PlayStatusChangeCallback(event);
            break;
        case EVENT_MMAP_SPK_START:
            SpkMmapStartCallback(event);
            break;
        case EVENT_MMAP_SPK_STOP:
            SpkMmapStopCallback(event);
            break;
        case EVENT_MMAP_MIC_START:
            MicMmapStartCallback(event);
            break;
        case EVENT_MMAP_MIC_STOP:
            MicMmapStopCallback(event);
            break;
        default:
            break;
    }
}

void DAudioSourceDev::SourceEventHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    DHLOGI("Event Id=%{public}d", event->GetInnerEventId());
    switch (event->GetInnerEventId()) {
        case EVENT_DAUDIO_ENABLE:
            EnableDAudioCallback(event);
            break;
        case EVENT_DAUDIO_DISABLE:
            DisableDAudioCallback(event);
            break;
        case EVENT_OPEN_SPEAKER:
            OpenDSpeakerCallback(event);
            break;
        case EVENT_CLOSE_SPEAKER:
            CloseDSpeakerCallback(event);
            break;
        case EVENT_OPEN_MIC:
            OpenDMicCallback(event);
            break;
        case EVENT_CLOSE_MIC:
            CloseDMicCallback(event);
            break;
        case EVENT_DMIC_CLOSED:
            DMicClosedCallback(event);
            break;
        case EVENT_VOLUME_SET:
        case EVENT_VOLUME_CHANGE:
        case EVENT_AUDIO_FOCUS_CHANGE:
        case EVENT_AUDIO_RENDER_STATE_CHANGE:
        case EVENT_CHANGE_PLAY_STATUS:
        case EVENT_MMAP_SPK_START:
        case EVENT_MMAP_SPK_STOP:
        case EVENT_MMAP_MIC_START:
        case EVENT_MMAP_MIC_STOP:
            ProcessEventInner(event);
            break;
        default:
            DHLOGE("Event Id is invaild. %{public}d", event->GetInnerEventId());
            break;
    }
}

void DAudioSourceDev::SourceEventHandler::EnableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    auto jsonString = event->GetSharedObject<std::string>().get();
    CHECK_NULL_VOID(jsonString);
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskEnableDAudio(*jsonString) != DH_SUCCESS) {
        DHLOGE("Open ctrl channel failed.");
    }
}

void DAudioSourceDev::SourceEventHandler::DisableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    auto jsonString = event->GetSharedObject<std::string>().get();
    CHECK_NULL_VOID(jsonString);
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskDisableDAudio(*jsonString) != DH_SUCCESS) {
        DHLOGE("Disable distributed audio failed.");
    }
}

void DAudioSourceDev::SourceEventHandler::OpenDSpeakerCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskCloseDMic(eventParam) != DH_SUCCESS) {
        DHLOGE("Close mic failed.");
        return;
    }
    DHLOGI("Close mic successfully.");
}

void DAudioSourceDev::SourceEventHandler::DMicClosedCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskDMicClosed(eventParam) != DH_SUCCESS) {
        DHLOGE("Deal dmic closed failed.");
        return;
    }
    DHLOGI("Deal dmic closed successfully.");
}

void DAudioSourceDev::SourceEventHandler::SetVolumeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
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
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskChangeRenderState(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process render state change event.");
        return;
    }
    DHLOGD("Processing render state change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::PlayStatusChangeCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskPlayStatusChange(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to process playing status change event.");
        return;
    }
    DHLOGD("Processing playing status change event successfully.");
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskSpkMmapStart(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to start speaker with mmap mode.");
        return;
    }
    DHLOGD("Start speaker with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::SpkMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskSpkMmapStop(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to stop speaker with mmap mode.");
        return;
    }
    DHLOGD("Stop speaker with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::MicMmapStartCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskMicMmapStart(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to start mic with mmap mode.");
        return;
    }
    DHLOGD("Start mic with mmap mode successfully.");
}

void DAudioSourceDev::SourceEventHandler::MicMmapStopCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    auto sourceDevObj = sourceDev_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    if (sourceDevObj->TaskMicMmapStop(eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to stop mic with mmap mode.");
        return;
    }
    DHLOGD("Stop mic with mmap mode successfully.");
}

int32_t DAudioSourceDev::SourceEventHandler::GetEventParam(const AppExecFwk::InnerEvent::Pointer &event,
    std::string &eventParam)
{
    CHECK_NULL_RETURN(event, ERR_DH_AUDIO_NULLPTR);
    std::shared_ptr<AudioEvent> paramObj = event->GetSharedObject<AudioEvent>();
    CHECK_NULL_RETURN(paramObj, ERR_DH_AUDIO_NULLPTR);
    eventParam = paramObj->content;
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
