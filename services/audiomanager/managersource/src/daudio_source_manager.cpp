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

#include "daudio_source_manager.h"

#include <dlfcn.h>
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "xcollie/watchdog.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceManager"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint32_t MAX_DEVICE_ID_LENGTH = 200;
constexpr uint32_t MAX_DISTRIBUTED_HARDWARE_ID_LENGTH = 100;
constexpr uint32_t EVENT_MANAGER_ENABLE_DAUDIO = 11;
constexpr uint32_t EVENT_MANAGER_DISABLE_DAUDIO = 12;
}
IMPLEMENT_SINGLE_INSTANCE(DAudioSourceManager);
using AVTransProviderClass = IAVEngineProvider *(*)(const std::string &);

const std::string SENDER_SO_NAME = "libdistributed_av_sender.z.so";
const std::string GET_SENDER_PROVIDER_FUNC = "GetAVSenderEngineProvider";
const std::string RECEIVER_SO_NAME = "libdistributed_av_receiver.z.so";
const std::string GET_RECEIVER_PROVIDER_FUNC = "GetAVReceiverEngineProvider";
#ifdef __LP64__
const std::string LIB_LOAD_PATH = "/system/lib64/";
#else
const std::string LIB_LOAD_PATH = "/system/lib/";
#endif

DAudioSourceManager::DAudioSourceManager()
{
    DHLOGD("Distributed audio source manager constructed.");
}

DAudioSourceManager::~DAudioSourceManager()
{
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }

    isHicollieRunning_.store(false);
    if (listenThread_.joinable()) {
        listenThread_.join();
    }
    DHLOGD("Distributed audio source manager destructed.");
}

int32_t DAudioSourceManager::Init(const sptr<IDAudioIpcCallback> &callback)
{
    DHLOGI("Init audio source manager.");
    CHECK_NULL_RETURN(callback, ERR_DH_AUDIO_NULLPTR);
    if (DAudioHdiHandler::GetInstance().InitHdiHandler() != DH_SUCCESS) {
        DHLOGE("Init Hdi handler failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (GetLocalDeviceNetworkId(localDevId_) != DH_SUCCESS) {
        DHLOGE("Get local network id failed.");
        return ERR_DH_AUDIO_FAILED;
    }

    ipcCallback_ = callback;
    daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    int32_t ret = LoadAVSenderEngineProvider();
    if (ret != DH_SUCCESS) {
        DHLOGE("load av transport sender engine provider failed");
        return ERR_DH_AUDIO_FAILED;
    }
    ret = LoadAVReceiverEngineProvider();
    if (ret != DH_SUCCESS) {
        DHLOGE("load av transport receiver engine provider failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (!isHicollieRunning_.load()) {
        isHicollieRunning_.store(true);
        listenThread_ = std::thread(&DAudioSourceManager::ListenAudioDev, this);
        if (pthread_setname_np(listenThread_.native_handle(), LISTEN_THREAD) != DH_SUCCESS) {
            DHLOGE("Dev clear thread setname failed.");
        }
    }
    // init event handler
    auto runner = AppExecFwk::EventRunner::Create(true);
    CHECK_NULL_RETURN(runner, ERR_DH_AUDIO_NULLPTR);
    handler_ = std::make_shared<DAudioSourceManager::SourceManagerHandler>(runner);
    DHLOGI("Init DAudioManager successfuly.");
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::UnInit()
{
    DHLOGI("Uninit audio source manager.");
    UnloadAVReceiverEngineProvider();
    UnloadAVSenderEngineProvider();
    {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        for (auto iter = audioDevMap_.begin(); iter != audioDevMap_.end(); iter++) {
            if (iter->second.dev == nullptr) {
                continue;
            }
            iter->second.dev->SleepAudioDev();
        }
        audioDevMap_.clear();
        DHLOGI("Audio dev map cleared.");
    }
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }

    isHicollieRunning_.store(false);
    if (listenThread_.joinable()) {
        listenThread_.join();
    }

    ipcCallback_ = nullptr;
    daudioMgrCallback_ = nullptr;
    if (DAudioHdiHandler::GetInstance().UninitHdiHandler() != DH_SUCCESS) {
        DHLOGE("Uninit Hdi handler failed.");
        return ERR_DH_AUDIO_FAILED;
    }

    CHECK_NULL_RETURN(handler_, DH_SUCCESS);
    while (!handler_->IsIdle()) {
        DHLOGD("manager handler is running, wait for idle.");
        usleep(WAIT_HANDLER_IDLE_TIME_US);
    }
    DHLOGI("Uninit audio source manager exit.");
    return DH_SUCCESS;
}

static bool CheckParams(const std::string &devId, const std::string &dhId)
{
    DHLOGD("Checking params of daudio.");
    if (devId.empty() || dhId.empty() ||
        devId.size() > MAX_DEVICE_ID_LENGTH || dhId.size() > MAX_DISTRIBUTED_HARDWARE_ID_LENGTH) {
        return false;
    }
    return true;
}

int32_t DAudioSourceManager::EnableDAudio(const std::string &devId, const std::string &dhId,
    const std::string &version, const std::string &attrs, const std::string &reqId)
{
    DHLOGI("Enable distributed audio, devId: %{public}s, dhId: %{public}s, version: %{public}s, reqId: %{public}s.",
        GetAnonyString(devId).c_str(), dhId.c_str(), version.c_str(), reqId.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddStringToObject(jParam, KEY_VERSION, version.c_str());
    cJSON_AddStringToObject(jParam, KEY_ATTRS, attrs.c_str());
    cJSON_AddStringToObject(jParam, KEY_REQID, reqId.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    if (jsonString == nullptr) {
        DHLOGE("Failed to create JSON data");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto eventParam = std::make_shared<std::string>(jsonString);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MANAGER_ENABLE_DAUDIO, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        cJSON_Delete(jParam);
        cJSON_free(jsonString);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
    DHLOGI("Enable audio task generate successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::DoEnableDAudio(const std::string &args)
{
    std::string devId = ParseStringFromArgs(args, KEY_DEV_ID);
    std::string dhId = ParseStringFromArgs(args, KEY_DH_ID);
    std::string version = ParseStringFromArgs(args, KEY_VERSION);
    std::string attrs = ParseStringFromArgs(args, KEY_ATTRS);
    std::string reqId = ParseStringFromArgs(args, KEY_REQID);
    DHLOGI("Do Enable distributed audio, devId: %{public}s, dhId: %{public}s, version:%{public}s, reqId:%{public}s.",
        GetAnonyString(devId).c_str(), dhId.c_str(), version.c_str(), reqId.c_str());
    if (!CheckParams(devId, dhId) || attrs.empty()) {
        DHLOGE("Enable params are incorrect.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<DAudioSourceDev> sourceDev = nullptr;
    {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        auto device = audioDevMap_.find(devId);
        if (device == audioDevMap_.end()) {
            if (CreateAudioDevice(devId) != DH_SUCCESS) {
                return ERR_DH_AUDIO_FAILED;
            }
        }
        audioDevMap_[devId].ports[dhId] = reqId;
        sourceDev = audioDevMap_[devId].dev;
    }
    DHLOGI("Call source dev to enable daudio.");
    if (sourceDev == nullptr) {
        DHLOGE("Source dev is nullptr.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t result = sourceDev->EnableDAudio(dhId, attrs);
    return OnEnableDAudio(devId, dhId, result);
}

int32_t DAudioSourceManager::DisableDAudio(const std::string &devId, const std::string &dhId, const std::string &reqId)
{
    DHLOGI("Disable distributed audio, devId: %{public}s, dhId: %{public}s, reqId: %{public}s.",
        GetAnonyString(devId).c_str(), dhId.c_str(), reqId.c_str());
    CHECK_NULL_RETURN(handler_, ERR_DH_AUDIO_NULLPTR);
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, devId.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, dhId.c_str());
    cJSON_AddStringToObject(jParam, KEY_REQID, reqId.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    if (jsonString == nullptr) {
        DHLOGE("Failed to create JSON data");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto eventParam = std::make_shared<std::string>(jsonString);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MANAGER_DISABLE_DAUDIO, eventParam, 0);
    if (!handler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        DHLOGE("Send event failed.");
        cJSON_Delete(jParam);
        cJSON_free(jsonString);
        return ERR_DH_AUDIO_FAILED;
    }
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
    DHLOGI("Disable audio task generate successfully.");
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::DoDisableDAudio(const std::string &args)
{
    std::string devId = ParseStringFromArgs(args, KEY_DEV_ID);
    std::string dhId = ParseStringFromArgs(args, KEY_DH_ID);
    std::string reqId = ParseStringFromArgs(args, KEY_REQID);
    DHLOGI("Do Disable distributed audio, devId: %{public}s, dhId: %{public}s, reqId:%{public}s.",
        GetAnonyString(devId).c_str(), dhId.c_str(), reqId.c_str());
    if (!CheckParams(devId, dhId)) {
        DHLOGE("Disable params are incorrect.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::shared_ptr<DAudioSourceDev> sourceDev = nullptr;
    {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        auto device = audioDevMap_.find(devId);
        if (device == audioDevMap_.end()) {
            DHLOGE("Audio device not exist.");
            return ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST;
        }
        CHECK_NULL_RETURN(audioDevMap_[devId].dev, DH_SUCCESS);
        audioDevMap_[devId].ports[dhId] = reqId;
        sourceDev = audioDevMap_[devId].dev;
    }
    DHLOGI("Call source dev to disable daudio.");
    int32_t result = sourceDev->DisableDAudio(dhId);
    return OnDisableDAudio(devId, dhId, result);
}

int32_t DAudioSourceManager::HandleDAudioNotify(const std::string &devId, const std::string &dhId,
    const int32_t eventType, const std::string &eventContent)
{
    DHLOGD("Receive audio event from devId: %{public}s, event type: %{public}d. event content: %{public}s.",
        GetAnonyString(devId).c_str(), eventType, eventContent.c_str());
    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }

    // now ctrl channel is also goto here, please sure here not crash.
    cJSON *jParam = cJSON_Parse(eventContent.c_str());
    if (CJsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE })) {
        DHLOGD("Receive audio notify from sink, random task code: %{public}s",
            cJSON_GetObjectItemCaseSensitive(jParam, KEY_RANDOM_TASK_CODE)->valuestring);
    }

    std::shared_ptr<DAudioSourceDev> sourceDev = nullptr;
    {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        auto device = audioDevMap_.find(devId);
        if (device == audioDevMap_.end()) {
            DHLOGE("Audio device not exist.");
            cJSON_Delete(jParam);
            return ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST;
        }
        sourceDev = audioDevMap_[devId].dev;
    }

    AudioEvent audioEvent(eventType, eventContent);
    sourceDev->NotifyEvent(audioEvent);
    cJSON_Delete(jParam);
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGD("Distributed audio notify, devId: %{public}s, dhId: %{public}s, eventType: %{public}d.",
        GetAnonyString(devId).c_str(), dhId.c_str(), eventType);
    {
        std::lock_guard<std::mutex> lck(remoteSvrMutex_);
        auto sinkProxy = sinkServiceMap_.find(devId);
        if (sinkProxy != sinkServiceMap_.end()) {
            if (sinkProxy->second != nullptr) {
                sinkProxy->second->DAudioNotify(localDevId_, dhId, eventType, eventContent);
                return DH_SUCCESS;
            }
        }
    }

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_NULL_RETURN(samgr, ERR_DH_AUDIO_NULLPTR);
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, devId);
    CHECK_NULL_RETURN(remoteObject, ERR_DH_AUDIO_NULLPTR);
    sptr<IDAudioSink> remoteSvrProxy = iface_cast<IDAudioSink>(remoteObject);
    CHECK_NULL_RETURN(remoteSvrProxy, ERR_DH_AUDIO_NULLPTR);
    {
        std::lock_guard<std::mutex> lck(remoteSvrMutex_);
        sinkServiceMap_[devId] = remoteSvrProxy;
        remoteSvrProxy->DAudioNotify(localDevId_, dhId, eventType, eventContent);
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::OnEnableDAudio(const std::string &devId, const std::string &dhId, const int32_t result)
{
    DHLOGI("On enable distributed audio devId: %{public}s, dhId: %{public}s, ret: %{public}d.",
        GetAnonyString(devId).c_str(), dhId.c_str(), result);
    std::string reqId = GetRequestId(devId, dhId);
    if (reqId.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (result != DH_SUCCESS) {
        DeleteAudioDevice(devId, dhId);
    }

    CHECK_NULL_RETURN(ipcCallback_, ERR_DH_AUDIO_NULLPTR);
    return ipcCallback_->OnNotifyRegResult(devId, dhId, reqId, result, "");
}

int32_t DAudioSourceManager::OnHardwareStateChanged(const std::string &devId, const std::string &dhId,
    const int32_t state)
{
    DHLOGI("On distributed hardware state changed devId: %{public}s, dhId: %{public}s, ret: %{public}d.",
        GetAnonyString(devId).c_str(), dhId.c_str(), state);

    CHECK_NULL_RETURN(ipcCallback_, ERR_DH_AUDIO_NULLPTR);
    return ipcCallback_->OnHardwareStateChanged(devId, dhId, state);
}

int32_t DAudioSourceManager::OnDataSyncTrigger(const std::string &devId)
{
    DHLOGI("On data sync trigger devId: %{public}s.", GetAnonyString(devId).c_str());

    CHECK_NULL_RETURN(ipcCallback_, ERR_DH_AUDIO_NULLPTR);
    return ipcCallback_->OnDataSyncTrigger(devId);
}

int32_t DAudioSourceManager::OnDisableDAudio(const std::string &devId, const std::string &dhId, const int32_t result)
{
    DHLOGI("On disable distributed audio devId: %{public}s, dhId: %{public}s, ret: %{public}d.",
        GetAnonyString(devId).c_str(), dhId.c_str(), result);
    std::string reqId = GetRequestId(devId, dhId);
    if (reqId.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (result == DH_SUCCESS) {
        DeleteAudioDevice(devId, dhId);
    }

    CHECK_NULL_RETURN(ipcCallback_, ERR_DH_AUDIO_NULLPTR);
    return ipcCallback_->OnNotifyUnregResult(devId, dhId, reqId, result, "");
}

int32_t DAudioSourceManager::CreateAudioDevice(const std::string &devId)
{
    DHLOGI("Create audio device.");
    auto sourceDev = std::make_shared<DAudioSourceDev>(devId, daudioMgrCallback_);
    if (sourceDev->AwakeAudioDev() != DH_SUCCESS) {
        DHLOGE("Create new audio device failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    AudioDevice device = { devId, sourceDev };
    audioDevMap_[devId] = device;
    return DH_SUCCESS;
}

void DAudioSourceManager::DeleteAudioDevice(const std::string &devId, const std::string &dhId)
{
    DHLOGI("Delete audio device, devId = %{public}s, dhId = %{public}s.", GetAnonyString(devId).c_str(), dhId.c_str());
    {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        audioDevMap_[devId].ports.erase(dhId);
        if (!audioDevMap_[devId].ports.empty()) {
            DHLOGI("audioDevMap_[devId].ports is not empty");
            return;
        }
    }
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    DHLOGI("audioDevMap_[devId].ports is empty");
    devClearThread_ = std::thread(&DAudioSourceManager::ClearAudioDev, this, devId);
    if (pthread_setname_np(devClearThread_.native_handle(), DEVCLEAR_THREAD) != DH_SUCCESS) {
        DHLOGE("Dev clear thread setname failed.");
    }
}

std::string DAudioSourceManager::GetRequestId(const std::string &devId, const std::string &dhId)
{
    std::lock_guard<std::mutex> lock(devMapMtx_);
    auto dev = audioDevMap_.find(devId);
    if (dev == audioDevMap_.end()) {
        DHLOGE("Audio device not exist.");
        return "";
    }
    auto port = audioDevMap_[devId].ports.find(dhId);
    if (port == audioDevMap_[devId].ports.end()) {
        DHLOGE("Audio port not exist.");
        return "";
    }
    return port->second;
}

void DAudioSourceManager::ClearAudioDev(const std::string &devId)
{
    DHLOGI("ClearAudioDev, devId = %{public}s.", GetAnonyString(devId).c_str());
    std::lock_guard<std::mutex> lock(devMapMtx_);
    if (audioDevMap_[devId].ports.empty()) {
        DHLOGI("audioDevMap_[devId].ports is empty.");
        CHECK_NULL_VOID(audioDevMap_[devId].dev);
        audioDevMap_[devId].dev->SleepAudioDev();
        DHLOGI("back from SleepAudioDev.");
        audioDevMap_.erase(devId);
    }
}

void DAudioSourceManager::RestoreThreadStatus()
{
    std::lock_guard<std::mutex> lock(devMapMtx_);
    if (!audioDevMap_.empty()) {
        for (auto &iter : audioDevMap_) {
            CHECK_NULL_VOID(iter.second.dev);
            iter.second.dev->SetThreadStatusFlag(true);
        }
    }
}

void DAudioSourceManager::ListenAudioDev()
{
    auto taskFunc = [this]() {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        for (auto &iter : audioDevMap_) {
            CHECK_NULL_VOID(iter.second.dev);
            if (iter.second.dev->GetThreadStatusFlag()) {
                iter.second.dev->SetThreadStatusFlag(false);
            } else {
                DHLOGE("Exit the current process hicollie");
                _Exit(0);
            }
        }
    };
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask("SourceService", taskFunc,
        WATCHDOG_INTERVAL_TIME, WATCHDOG_DELAY_TIME);

    while (isHicollieRunning_.load()) {
        {
            std::lock_guard<std::mutex> lock(devMapMtx_);
            RestoreThreadStatus();
        }
        usleep(SLEEP_TIME);
    }
}

int32_t DAudioSourceManager::LoadAVSenderEngineProvider()
{
    DHLOGI("LoadAVSenderEngineProvider enter");
    char path[PATH_MAX + 1] = {0x00};
    if ((LIB_LOAD_PATH.length() + SENDER_SO_NAME.length()) > PATH_MAX ||
        realpath((LIB_LOAD_PATH + SENDER_SO_NAME).c_str(), path) == nullptr) {
        DHLOGE("File open failed");
        return ERR_DH_AUDIO_NULLPTR;
    }
    pSHandler_ = dlopen(path, RTLD_LAZY | RTLD_NODELETE);
    CHECK_NULL_RETURN(pSHandler_, ERR_DH_AUDIO_NULLPTR);
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pSHandler_,
        GET_SENDER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %{public}s", dlerror());
        dlclose(pSHandler_);
        pSHandler_ = nullptr;
        return ERR_DH_AUDIO_NULLPTR;
    }
    sendProviderPtr_ = getEngineFactoryFunc(OWNER_NAME_D_SPEAKER);
    DHLOGI("LoadAVSenderEngineProvider exit");
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::UnloadAVSenderEngineProvider()
{
    DHLOGI("UnloadAVSenderEngineProvider enter");
    if (pSHandler_ != nullptr) {
        dlclose(pSHandler_);
        pSHandler_ = nullptr;
    }
    sendProviderPtr_ = nullptr;
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::LoadAVReceiverEngineProvider()
{
    DHLOGI("LoadAVReceiverEngineProvider enter");
    char path[PATH_MAX + 1] = {0x00};
    if ((LIB_LOAD_PATH.length() + RECEIVER_SO_NAME.length()) > PATH_MAX ||
        realpath((LIB_LOAD_PATH + RECEIVER_SO_NAME).c_str(), path) == nullptr) {
        DHLOGE("File canonicalization failed");
        return ERR_DH_AUDIO_NULLPTR;
    }
    pRHandler_ = dlopen(path, RTLD_LAZY | RTLD_NODELETE);
    CHECK_NULL_RETURN(pRHandler_, ERR_DH_AUDIO_NULLPTR);
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pRHandler_,
        GET_RECEIVER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %{public}s", dlerror());
        dlclose(pRHandler_);
        pRHandler_ = nullptr;
        return ERR_DH_AUDIO_NULLPTR;
    }
    rcvProviderPtr_ = getEngineFactoryFunc(OWNER_NAME_D_MIC);
    DHLOGI("LoadAVReceiverEngineProvider success");
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::UnloadAVReceiverEngineProvider()
{
    DHLOGI("UnloadAVReceiverEngineProvider");
    if (pRHandler_ != nullptr) {
        dlclose(pRHandler_);
        pRHandler_ = nullptr;
    }
    return DH_SUCCESS;
}

IAVEngineProvider *DAudioSourceManager::getSenderProvider()
{
    return sendProviderPtr_;
}

IAVEngineProvider *DAudioSourceManager::getReceiverProvider()
{
    return rcvProviderPtr_;
}

DAudioSourceManager::SourceManagerHandler::SourceManagerHandler(const std::shared_ptr<AppExecFwk::EventRunner>
    &runner) : AppExecFwk::EventHandler(runner)
{
    DHLOGD("Event handler is constructing.");
    mapEventFuncs_[EVENT_MANAGER_ENABLE_DAUDIO] = &DAudioSourceManager::SourceManagerHandler::EnableDAudioCallback;
    mapEventFuncs_[EVENT_MANAGER_DISABLE_DAUDIO] = &DAudioSourceManager::SourceManagerHandler::DisableDAudioCallback;
}

DAudioSourceManager::SourceManagerHandler::~SourceManagerHandler() {}

void DAudioSourceManager::SourceManagerHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto iter = mapEventFuncs_.find(event->GetInnerEventId());
    if (iter == mapEventFuncs_.end()) {
        DHLOGE("Event Id is invalid. %{public}d.", event->GetInnerEventId());
        return;
    }
    SourceManagerFunc &func = iter->second;
    (this->*func)(event);
}

void DAudioSourceManager::SourceManagerHandler::EnableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    DHLOGI("Enable audio device, param:%{public}s.", eventParam.c_str());
    DAudioSourceManager::GetInstance().DoEnableDAudio(eventParam);
}

void DAudioSourceManager::SourceManagerHandler::DisableDAudioCallback(const AppExecFwk::InnerEvent::Pointer &event)
{
    CHECK_NULL_VOID(event);
    std::string eventParam;
    if (GetEventParam(event, eventParam) != DH_SUCCESS) {
        DHLOGE("Failed to get event parameters.");
        return;
    }
    DHLOGI("Disable audio device, param:%{public}s.", eventParam.c_str());
    DAudioSourceManager::GetInstance().DoDisableDAudio(eventParam);
}

int32_t DAudioSourceManager::SourceManagerHandler::GetEventParam(const AppExecFwk::InnerEvent::Pointer &event,
    std::string &eventParam)
{
    CHECK_NULL_RETURN(event, ERR_DH_AUDIO_NULLPTR);
    auto jsonString = event->GetSharedObject<std::string>().get();
    CHECK_NULL_RETURN(jsonString, ERR_DH_AUDIO_NULLPTR);
    eventParam = *jsonString;
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
