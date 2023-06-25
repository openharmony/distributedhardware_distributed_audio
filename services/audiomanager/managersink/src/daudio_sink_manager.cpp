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

#include "daudio_sink_manager.h"

#include <dlfcn.h>
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkManager"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioSinkManager);
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
DAudioSinkManager::DAudioSinkManager()
{
    DHLOGD("Distributed audio sink manager constructed.");
}

DAudioSinkManager::~DAudioSinkManager()
{
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    DHLOGD("Distributed audio sink manager deconstructed.");
}

int32_t DAudioSinkManager::Init()
{
    DHLOGI("Init audio sink manager.");
    int32_t ret = GetLocalDeviceNetworkId(localNetworkId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get local network id failed, ret: %d.", ret);
        return ret;
    }
    // new 方式
    IsParamEnabled(AUDIO_ENGINE_FLAG, engineFlag_);
    if (engineFlag_ == true) {
        ret = LoadAVReceiverEngineProvider();
        if (ret != DH_SUCCESS || rcvProviderPtr_ == nullptr) {
            DHLOGE("Load av transport receiver engine provider failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        ret = rcvProviderPtr_->RegisterProviderCallback(std::make_shared<EngineProviderListener>());
        if (ret != DH_SUCCESS) {
            DHLOGE("Register av transport receiver Provider Callback failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        DHLOGI("LoadAVReceiverEngineProvider success.");

        ret = LoadAVSenderEngineProvider();
        if (ret != DH_SUCCESS || sendProviderPtr_ == nullptr) {
            DHLOGI("Load av transport sender engine provider failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        ret = sendProviderPtr_->RegisterProviderCallback(std::make_shared<EngineProviderListener>());
        if (ret != DH_SUCCESS) {
            DHLOGE("Register av transport sender Provider Callback failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        DHLOGE("LoadAVSenderEngineProvider success.");
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::UnInit()
{
    DHLOGI("UnInit audio sink manager.");
    if (engineFlag_ == true) {
        UnloadAVSenderEngineProvider();
        UnloadAVReceiverEngineProvider();
    }
    {
        std::lock_guard<std::mutex> remoteSvrLock(remoteSvrMutex_);
        sourceServiceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> devMapLock(devMapMutex_);
        for (auto iter = audioDevMap_.begin(); iter != audioDevMap_.end(); iter++) {
            if (iter->second != nullptr) {
                iter->second->SleepAudioDev();
            }
        }
        audioDevMap_.clear();
    }
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    return DH_SUCCESS;
}

void DAudioSinkManager::OnSinkDevReleased(const std::string &devId)
{
    DHLOGI("Release audio device devId: %s.", GetAnonyString(devId).c_str());
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    devClearThread_ = std::thread(&DAudioSinkManager::ClearAudioDev, this, devId);
    if (pthread_setname_np(devClearThread_.native_handle(), DEVCLEAR_THREAD) != DH_SUCCESS) {
        DHLOGE("Dev clear thread setname failed.");
    }
}

int32_t DAudioSinkManager::HandleDAudioNotify(const std::string &devId, const std::string &dhId,
    const int32_t eventType, const std::string &eventContent)
{
    DHLOGD("Receive audio event from devId: %s, event type: %d. event content: %s.",
        GetAnonyString(devId).c_str(), eventType, eventContent.c_str());

    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()
        || !CheckDevIdIsLegal(devId) || eventType < 0 || eventType > MAX_EVENT_TYPE_NUM) {
        return ERR_DH_AUDIO_FAILED;
    }

    // now ctrl channel is also goto here, please sure here not crash. 
    json jParam = json::parse(eventContent, nullptr, false);
    if (JsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE })) {
        DHLOGD("Receive audio notify from source, random task code: %s",
            ((std::string)jParam[KEY_RANDOM_TASK_CODE]).c_str());
    }

    std::lock_guard<std::mutex> lock(devMapMutex_);
    auto iter = audioDevMap_.find(devId);
    if (iter == audioDevMap_.end() && CreateAudioDevice(devId) != DH_SUCCESS) {
        return ERR_DH_AUDIO_FAILED;
    }
    NotifyEvent(devId, eventType, eventContent);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::CreateAudioDevice(const std::string &devId)
{
    DHLOGI("Create audio sink dev.");
    std::lock_guard<std::mutex> lock(devMapMutex_);
    if (audioDevMap_.find(devId) != audioDevMap_.end()) {
        DHLOGI("Audio sink dev in map. devId: %s.", GetAnonyString(devId).c_str());
        return DH_SUCCESS;
    }
    auto dev = std::make_shared<DAudioSinkDev>(devId);
    if (dev->AwakeAudioDev() != DH_SUCCESS) {
        DHLOGE("Awake audio dev failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    // wuhaobo zhushi 不论old 还是new 都需要调用init
    int32_t ret = dev->InitAVTransEngines(sendProviderPtr_, rcvProviderPtr_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init av transport sender engine failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    audioDevMap_.emplace(devId, dev);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGD("Distributed audio notify, devId: %s, dhId: %s, eventType: %d.",
        GetAnonyString(devId).c_str(), dhId.c_str(), eventType);

    {
        std::lock_guard<std::mutex> lck(remoteSvrMutex_);
        auto sinkProxy = sourceServiceMap_.find(devId);
        if (sinkProxy != sourceServiceMap_.end()) {
            if (sinkProxy->second != nullptr) {
                sinkProxy->second->DAudioNotify(localNetworkId_, dhId, eventType, eventContent);
                return DH_SUCCESS;
            }
        }
    }

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DHLOGE("Failed to get system ability mgr.");
        return ERR_DH_AUDIO_SA_GET_SAMGR_FAILED;
    }
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID, devId);
    if (remoteObject == nullptr) {
        DHLOGE("remoteObject is null.");
        return ERR_DH_AUDIO_SA_GET_REMOTE_SINK_FAILED;
    }
    sptr<IDAudioSource> remoteSvrProxy = iface_cast<IDAudioSource>(remoteObject);
    if (remoteSvrProxy == nullptr) {
        DHLOGE("Failed to get remote daudio sink SA.");
        return ERR_DH_AUDIO_SA_GET_REMOTE_SINK_FAILED;
    }
    {
        std::lock_guard<std::mutex> lck(remoteSvrMutex_);
        sourceServiceMap_[devId] = remoteSvrProxy;
        remoteSvrProxy->DAudioNotify(localNetworkId_, dhId, eventType, eventContent);
    }
    return DH_SUCCESS;
}

void DAudioSinkManager::NotifyEvent(const std::string &devId, const int32_t eventType, const std::string &eventContent)
{
    AudioEvent audioEvent(eventType, eventContent);
    audioDevMap_[devId]->NotifyEvent(audioEvent);
}

void DAudioSinkManager::ClearAudioDev(const std::string &devId)
{
    std::lock_guard<std::mutex> lock(devMapMutex_);
    auto dev = audioDevMap_.find(devId);
    if (dev == audioDevMap_.end()) {
        DHLOGD("Device not register.");
        return;
    }
    if (dev->second == nullptr) {
        DHLOGD("Device already released.");
        return;
    }
    dev->second->SleepAudioDev();
    audioDevMap_.erase(devId);
}

int32_t DAudioSinkManager::LoadAVReceiverEngineProvider()
{
    DHLOGI("LoadAVReceiverEngineProvider enter");
    char path[PATH_MAX + 1] = {0x00};
    if ((LIB_LOAD_PATH.length() + RECEIVER_SO_NAME.length()) > PATH_MAX ||
        realpath((LIB_LOAD_PATH + RECEIVER_SO_NAME).c_str(), path) == nullptr) {
        DHLOGE("File open failed");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    pRHandler_ = dlopen(path, RTLD_LAZY | RTLD_NODELETE);
    if (pRHandler_ == nullptr) {
        DHLOGE("%s handler load failed, failed reason : %s", path, dlerror());
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pRHandler_,
        GET_RECEIVER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %s", dlerror());
        dlclose(pRHandler_);
        pRHandler_ = nullptr;
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    rcvProviderPtr_ = getEngineFactoryFunc(OWNER_NAME_D_SPEAKER);
    DHLOGE("LoadAVReceiverEngineProvider success");
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::UnloadAVReceiverEngineProvider()
{
    DHLOGI("UnloadAVReceiverEngineProvider");
    if (pRHandler_ != nullptr) {
        dlclose(pRHandler_);
        pRHandler_ = nullptr;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::LoadAVSenderEngineProvider()
{
    DHLOGI("LoadAVSenderEngineProvider enter");
    char path[PATH_MAX + 1] = {0x00};
    if ((LIB_LOAD_PATH.length() + SENDER_SO_NAME.length()) > PATH_MAX ||
        realpath((LIB_LOAD_PATH + SENDER_SO_NAME).c_str(), path) == nullptr) {
        DHLOGE("File open failed");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    pSHandler_ = dlopen(path, RTLD_LAZY | RTLD_NODELETE);
    if (pSHandler_ == nullptr) {
        DHLOGE("%s handler load failed, failed reason : %s", path, dlerror());
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    AVTransProviderClass getEngineFactoryFunc = (AVTransProviderClass)dlsym(pSHandler_,
        GET_SENDER_PROVIDER_FUNC.c_str());
    if (getEngineFactoryFunc == nullptr) {
        DHLOGE("av transport engine factory function handler is null, failed reason : %s", dlerror());
        dlclose(pSHandler_);
        pSHandler_ = nullptr;
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }
    sendProviderPtr_ = getEngineFactoryFunc(OWNER_NAME_D_MIC);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::UnloadAVSenderEngineProvider()
{
    DHLOGI("UnloadAVSenderEngineProvider enter");
    if (pSHandler_ != nullptr) {
        dlclose(pSHandler_);
        pSHandler_ = nullptr;
    }
    return DH_SUCCESS;
}

int32_t EngineProviderListener::OnProviderEvent(const AVTransEvent &event)
{
    DHLOGI("On provider event :%d", event.type);
    // wuhaobo zhushi 这里等source要求打开后才会回调上来；创建设备
    if (event.type == EventType::EVENT_CHANNEL_OPENED) {
        DHLOGI("CreateAudioDevice enter");
        DAudioSinkManager::GetInstance().CreateAudioDevice(event.peerDevId);
        DHLOGI("CreateAudioDevice end");
    } else if (event.type == EventType::EVENT_CHANNEL_CLOSED) {
        DHLOGI("CreateAudioDevice enter");
        DAudioSinkManager::GetInstance().ClearAudioDev(event.peerDevId);
        DHLOGI("CreateAudioDevice end");
    } else {
        DHLOGE("Invaild event type.");
    }
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
