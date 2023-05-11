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

#include "if_system_ability_manager.h"
#include "iservice_registry.h"

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
constexpr uint32_t MAX_DISTRIBUTED_HAREWARE_ID_LENGTH = 100;
}

IMPLEMENT_SINGLE_INSTANCE(DAudioSourceManager);
DAudioSourceManager::DAudioSourceManager()
{
    DHLOGI("Distributed audio source manager constructed.");
}

DAudioSourceManager::~DAudioSourceManager()
{
    if (devClearThread_.joinable()) {
        devClearThread_.join();
    }
    DHLOGI("Distributed audio source manager destructed.");
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
    return DH_SUCCESS;
}

int32_t DAudioSourceManager::UnInit()
{
    DHLOGI("Uninit audio source manager.");
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
    DHLOGI("Checking oarams of daudio.");
    if (devId.empty() || dhId.empty() ||
        devId.size() > MAX_DEVICE_ID_LENGTH || dhId.size() > MAX_DISTRIBUTED_HAREWARE_ID_LENGTH) {
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
    DHLOGI("Handle distributed audio notify, devId: %s, dhId: %s, eventType: %d.", GetAnonyString(devId).c_str(),
        dhId.c_str(), eventType);
    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()) {
        return ERR_DH_AUDIO_FAILED;
    }

    json jParam = json::parse(eventContent, nullptr, false);
    if (JsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE })) {
        DHLOGI("Receive audio notify from sink, random task code: %s",
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
    DHLOGI("Distributed audio notify, devId: %s, dhId: %s, eventType: %d.", GetAnonyString(devId).c_str(),
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
        return ERR_DH_AUDIO_SA_GET_SAMGR_FAILED;
    }
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, devId);
    if (remoteObject == nullptr) {
        DHLOGE("Object is null.");
        return ERR_DH_AUDIO_SA_GET_REMOTE_SINK_FAILED;
    }
    sptr<IDAudioSink> remoteSvrProxy = iface_cast<IDAudioSink>(remoteObject);
    if (remoteSvrProxy == nullptr) {
        DHLOGE("Failed to get remote daudio sink SA.");
        return ERR_DH_AUDIO_SA_GET_REMOTE_SINK_FAILED;
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
} // DistributedHardware
} // OHOS