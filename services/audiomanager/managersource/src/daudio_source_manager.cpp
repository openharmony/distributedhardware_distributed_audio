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
    if (callback == nullptr) {
        DHLOGE("Callback is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
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
    isHicollieRunning_.store(true);
    listenThread_ = std::thread(&DAudioSourceManager::ListenAudioDev, this);
    if (pthread_setname_np(listenThread_.native_handle(), LISTEN_THREAD) != DH_SUCCESS) {
        DHLOGE("Dev clear thread setname failed.");
    }
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
    DHLOGI("Enable distributed audio, devId: %s, dhId: %s, version: %s, reqId: %s.", GetAnonyString(devId).c_str(),
        dhId.c_str(), version.c_str(), reqId.c_str());
    if (!CheckParams(devId, dhId) || attrs.empty()) {
        DHLOGE("Enable params are incorrect.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::lock_guard<std::mutex> lock(devMapMtx_);
    auto dev = audioDevMap_.find(devId);
    if (dev == audioDevMap_.end()) {
        if (CreateAudioDevice(devId) != DH_SUCCESS) {
            return ERR_DH_AUDIO_FAILED;
        }
    }
    audioDevMap_[devId].ports[dhId] = reqId;
    return audioDevMap_[devId].dev->EnableDAudio(dhId, attrs);
}

int32_t DAudioSourceManager::DisableDAudio(const std::string &devId, const std::string &dhId, const std::string &reqId)
{
    DHLOGI("Disable distributed audio, devId: %s, dhId: %s, reqId: %s.", GetAnonyString(devId).c_str(), dhId.c_str(),
        reqId.c_str());
    if (!CheckParams(devId, dhId)) {
        DHLOGE("Enable params are incorrect.");
        return ERR_DH_AUDIO_FAILED;
    }
    std::lock_guard<std::mutex> lock(devMapMtx_);
    auto dev = audioDevMap_.find(devId);
    if (dev == audioDevMap_.end()) {
        DHLOGE("Audio device not exist.");
        return ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST;
    }
    if (audioDevMap_[devId].dev == nullptr) {
        DHLOGE("Audio device is null.");
        return DH_SUCCESS;
    }
    audioDevMap_[devId].ports[dhId] = reqId;
    return audioDevMap_[devId].dev->DisableDAudio(dhId);
}

int32_t DAudioSourceManager::HandleDAudioNotify(const std::string &devId, const std::string &dhId,
    const int32_t eventType, const std::string &eventContent)
{
    DHLOGD("Receive audio event from devId: %s, event type: %d. event content: %s.",
        GetAnonyString(devId).c_str(), eventType, eventContent.c_str());
    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }

    // now ctrl channel is also goto here, please sure here not crash.
    json jParam = json::parse(eventContent, nullptr, false);
    if (JsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE })) {
        DHLOGD("Receive audio notify from sink, random task code: %s",
            ((std::string)jParam[KEY_RANDOM_TASK_CODE]).c_str());
    }

    std::lock_guard<std::mutex> lock(devMapMtx_);
    auto dev = audioDevMap_.find(devId);
    if (dev == audioDevMap_.end()) {
        DHLOGE("Audio device not exist.");
        return ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST;
    }

    AudioEvent audioEvent(eventType, eventContent);
    audioDevMap_[devId].dev->NotifyEvent(audioEvent);
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGD("Distributed audio notify, devId: %s, dhId: %s, eventType: %d.", GetAnonyString(devId).c_str(),
        dhId.c_str(), eventType);
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
    if (samgr == nullptr) {
        DHLOGE("Failed to get system ability mgr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, devId);
    if (remoteObject == nullptr) {
        DHLOGE("Object is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    sptr<IDAudioSink> remoteSvrProxy = iface_cast<IDAudioSink>(remoteObject);
    if (remoteSvrProxy == nullptr) {
        DHLOGE("Failed to get remote daudio sink SA.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    {
        std::lock_guard<std::mutex> lck(remoteSvrMutex_);
        sinkServiceMap_[devId] = remoteSvrProxy;
        remoteSvrProxy->DAudioNotify(localDevId_, dhId, eventType, eventContent);
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::OnEnableDAudio(const std::string &devId, const std::string &dhId, const int32_t result)
{
    DHLOGI("On enable distributed audio devId: %s, dhId: %s, ret: %d.", GetAnonyString(devId).c_str(), dhId.c_str(),
        result);
    std::string reqId = GetRequestId(devId, dhId);
    if (reqId.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (result != DH_SUCCESS) {
        DeleteAudioDevice(devId, dhId);
    }

    if (ipcCallback_ == nullptr) {
        DHLOGE("Audio Ipc callback is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return ipcCallback_->OnNotifyRegResult(devId, dhId, reqId, result, "");
}

int32_t DAudioSourceManager::OnDisableDAudio(const std::string &devId, const std::string &dhId, const int32_t result)
{
    DHLOGI("On disable distributed audio devId: %s, dhId: %s, ret: %d.", GetAnonyString(devId).c_str(), dhId.c_str(),
        result);
    std::string reqId = GetRequestId(devId, dhId);
    if (reqId.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (result == DH_SUCCESS) {
        DeleteAudioDevice(devId, dhId);
    }

    if (ipcCallback_ == nullptr) {
        DHLOGE("Audio Ipc callback is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
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
    DHLOGI("Delete audio device.");
    std::lock_guard<std::mutex> lock(devMapMtx_);
    audioDevMap_[devId].ports.erase(dhId);
    if (!audioDevMap_[devId].ports.empty()) {
        return;
    }
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
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
    std::lock_guard<std::mutex> lock(devMapMtx_);
    if (audioDevMap_[devId].ports.empty()) {
        audioDevMap_[devId].dev->SleepAudioDev();
        audioDevMap_.erase(devId);
    }
}

void DAudioSourceManager::ListenAudioDev()
{
    auto taskFunc = [this]() {
        std::lock_guard<std::mutex> lock(devMapMtx_);
        for (auto &iter : audioDevMap_) {
            if (iter.second.dev->GetThreadStatusFlag()) {
                iter.second.dev->SetThreadStatusFlag();
            } else {
                DHLOGE("Exit the current proces");
                _Exit(0);
            }
        }
    };
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask("SourceService", taskFunc,
        WATCHDOG_INTERVAL_TIME, WATCHDOG_DELAY_TIME);

    while (isHicollieRunning_.load()) {
        {
            std::lock_guard<std::mutex> lock(devMapMtx_);
            if (!audioDevMap_.empty()) {
                for (auto &iter : audioDevMap_) {
                    iter.second.dev->RestoreThreadStatus();
                }
            }
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
    if (pSHandler_ == nullptr) {
        DHLOGE("%s handler load failed, failed reason : %s", path, dlerror());
        return ERR_DH_AUDIO_NULLPTR;
    }
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pSHandler_,
        GET_SENDER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %s", dlerror());
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
    if (pRHandler_ == nullptr) {
        DHLOGE("%s handler load failed, failed reason : %s", path, dlerror());
        return ERR_DH_AUDIO_NULLPTR;
    }
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pRHandler_,
        GET_RECEIVER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %s", dlerror());
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
} // DistributedHardware
} // OHOS
