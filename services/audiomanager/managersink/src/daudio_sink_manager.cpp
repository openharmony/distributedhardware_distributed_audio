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
DAudioSinkManager::DAudioSinkManager()
{
    DHLOGI("Distributed audio sink manager constructed.");
}

DAudioSinkManager::~DAudioSinkManager()
{
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    DHLOGI("Distributed audio sink manager deconstructed.");
}

int32_t DAudioSinkManager::Init()
{
    DHLOGI("Init audio sink manager.");
    int32_t ret = GetLocalDeviceNetworkId(localNetworkId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get local network id failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::UnInit()
{
    DHLOGI("UnInit audio sink manager.");
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
    DHLOGI("Receive audio event from devId: %s, event type: %d.", GetAnonyString(devId).c_str(), eventType);

    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }

    json jParam = json::parse(eventContent, nullptr, false);
    if (JsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE }) && CheckIsNum((std::string)jParam[KEY_RANDOM_TASK_CODE])) {
        int32_t randomCode = std::stoi((std::string)jParam[KEY_RANDOM_TASK_CODE]);
        DHLOGI("Receive audio notify from source, random task code: %d", randomCode);
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
    auto dev = std::make_shared<DAudioSinkDev>(devId);
    if (dev->AwakeAudioDev() != DH_SUCCESS) {
        DHLOGE("Awake audio dev failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    audioDevMap_.emplace(devId, dev);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGI("Distributed audio notify, devId: %s, dhId: %s, eventType: %d.",
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
} // namespace DistributedHardware
} // namespace OHOS
