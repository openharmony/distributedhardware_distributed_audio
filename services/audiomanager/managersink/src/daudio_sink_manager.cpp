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
static const std::string PARAM_CLOSE_SPEAKER = "{\"audioParam\":null,\"dhId\":\"" +
    std::to_string(PIN_OUT_SPEAKER) + "\",\"eventType\":12}";
static const std::string PARAM_CLOSE_MIC = "{\"audioParam\":null,\"dhId\":\"" +
    std::to_string(PIN_IN_MIC) + "\",\"eventType\":22}";
const int DEFAULT_DEVICE_SECURITY_LEVEL = -1;

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

int32_t DAudioSinkManager::Init(const sptr<IDAudioSinkIpcCallback> &sinkCallback)
{
    DHLOGI("Init audio sink manager.");
    initCallback_ = std::make_shared<DeviceInitCallback>();
    ipcSinkCallback_ = sinkCallback;
    CHECK_AND_RETURN_RET_LOG(GetLocalDeviceNetworkId(localNetworkId_) != DH_SUCCESS,
        ERR_DH_AUDIO_FAILED, "%{public}s", "Get local network id failed.");
    CHECK_AND_RETURN_RET_LOG(LoadAVReceiverEngineProvider() != DH_SUCCESS,
        ERR_DH_AUDIO_FAILED, "%{public}s", "Load av receiver engine failed.");
    CHECK_NULL_RETURN(rcvProviderPtr_, ERR_DH_AUDIO_FAILED);
    providerListener_ = std::make_shared<EngineProviderListener>();
    if (rcvProviderPtr_->RegisterProviderCallback(providerListener_) != DH_SUCCESS) {
        DHLOGE("Register av receiver engine callback failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Load av receiver engine success.");

    if (LoadAVSenderEngineProvider() != DH_SUCCESS) {
        DHLOGI("Load av sender engine provider failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    CHECK_NULL_RETURN(sendProviderPtr_, ERR_DH_AUDIO_FAILED);
    if (sendProviderPtr_->RegisterProviderCallback(providerListener_) != DH_SUCCESS) {
        DHLOGE("Register av sender engine callback failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    CHECK_AND_RETURN_RET_LOG(sendProviderPtr_->RegisterProviderCallback(providerListener_) != DH_SUCCESS,
        ERR_DH_AUDIO_FAILED, "%{public}s", "Register av sender engine callback failed.");
    DHLOGI("Load av sender engine success.");
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::UnInit()
{
    DHLOGI("UnInit audio sink manager.");
    UnloadAVSenderEngineProvider();
    UnloadAVReceiverEngineProvider();
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
    ipcSinkCallback_ = nullptr;
    return DH_SUCCESS;
}

void DAudioSinkManager::OnSinkDevReleased(const std::string &devId)
{
    DHLOGI("Release audio device devId: %{public}s.", GetAnonyString(devId).c_str());
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
    DHLOGD("Receive audio event from devId: %{public}s, event type: %{public}d. event content: %{public}s.",
        GetAnonyString(devId).c_str(), eventType, eventContent.c_str());

    if (eventContent.length() > DAUDIO_MAX_JSON_LEN || eventContent.empty()
        || !CheckDevIdIsLegal(devId) || eventType < 0 || eventType > MAX_EVENT_TYPE_NUM) {
        return ERR_DH_AUDIO_FAILED;
    }

    // now ctrl channel is also goto here, please sure here not crash.
    cJSON *jParam = cJSON_Parse(eventContent.c_str());
    if (CJsonParamCheck(jParam, { KEY_RANDOM_TASK_CODE })) {
        DHLOGD("Receive audio notify from source, random task code: %{public}s",
            cJSON_GetObjectItemCaseSensitive(jParam, KEY_RANDOM_TASK_CODE)->valuestring);
    }
    bool isDevExisted = false;
    {
        std::lock_guard<std::mutex> lock(devMapMutex_);
        isDevExisted = audioDevMap_.find(devId) != audioDevMap_.end();
    }
    if (!isDevExisted) {
        DHLOGE("Device is not exist, devId: %{public}s, dhId: %{public}s.", GetAnonyString(devId).c_str(),
            GetAnonyString(dhId).c_str());
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_FAILED;
    }
    NotifyEvent(devId, eventType, eventContent);
    cJSON_Delete(jParam);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::CreateAudioDevice(const std::string &devId)
{
    DHLOGI("Create audio sink dev.");
    std::shared_ptr<DAudioSinkDev> dev = nullptr;
    {
        std::lock_guard<std::mutex> lock(devMapMutex_);
        if (audioDevMap_.find(devId) != audioDevMap_.end()) {
            DHLOGI("Audio sink dev in map. devId: %{public}s.", GetAnonyString(devId).c_str());
            dev = audioDevMap_[devId];
        } else {
            dev = std::make_shared<DAudioSinkDev>(devId, ipcSinkCallback_);
            audioDevMap_.emplace(devId, dev);
        }
    }
    int32_t dhId;
    bool isSpkOrMic = false;
    if (channelState_ == ChannelState::MIC_CONTROL_OPENED) {
        dhId = PIN_IN_MIC;
        isSpkOrMic = false;
    } else if (channelState_ == ChannelState::SPK_CONTROL_OPENED) {
        dhId = PIN_OUT_SPEAKER;
        isSpkOrMic = true;
    } else {
        DHLOGE("Channel state error.");
        return ERR_DH_AUDIO_NOT_SUPPORT;
    }
    int32_t ret = InitAudioDevice(dev, devId, isSpkOrMic);
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_RETURN(jParam, ERR_DH_AUDIO_NULLPTR);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(dhId).c_str());
    cJSON_AddNumberToObject(jParam, KEY_RESULT, ret);
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::string eventContent = std::string(jsonData);
    cJSON_free(jsonData);
    cJSON_Delete(jParam);
    const int32_t SLEEP_TIME = 300;
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    NotifyEvent(devId, CTRL_OPENED, eventContent);
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::InitAudioDevice(std::shared_ptr<DAudioSinkDev> dev, const std::string &devId,
    bool isSpkOrMic)
{
    DHLOGI("Init audio device.");
    if (dev == nullptr) {
        DHLOGE("dev is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret;
    if (isSpkOrMic) {
        ret = dev->InitAVTransEngines(ChannelState::SPK_CONTROL_OPENED, rcvProviderPtr_);
    } else {
        ret = VerifySecurityLevel(devId);
        if (ret != DH_SUCCESS) {
            DHLOGE("Verify security level failed.");
            return ERR_DH_AUDIO_FAILED;
        }
        dev->SetDevLevelStatus(true);
        ret = dev->InitAVTransEngines(ChannelState::MIC_CONTROL_OPENED, sendProviderPtr_);
    }
    if (ret != DH_SUCCESS) {
        DHLOGE("Init av transport engine failed.");
        dev->JudgeDeviceStatus();
        return ERR_DH_AUDIO_FAILED;
    }
    ret = dev->AwakeAudioDev();
    if (ret != DH_SUCCESS) {
        DHLOGE("Awake audio dev failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    return ret;
}

int32_t DAudioSinkManager::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGD("Distributed audio notify, devId: %{public}s, dhId: %{public}s, eventType: %{public}d.",
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
    CHECK_NULL_RETURN(samgr, ERR_DH_AUDIO_NULLPTR);

    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID, devId);
    CHECK_NULL_RETURN(remoteObject, ERR_DH_AUDIO_NULLPTR);

    sptr<IDAudioSource> remoteSvrProxy = iface_cast<IDAudioSource>(remoteObject);
    CHECK_NULL_RETURN(remoteSvrProxy, ERR_DH_AUDIO_NULLPTR);
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
    std::lock_guard<std::mutex> lock(devMapMutex_);
    DHLOGI("Notify event, devId: %{public}s.", GetAnonyString(devId).c_str());
    CHECK_AND_RETURN_LOG(audioDevMap_.find(devId) == audioDevMap_.end(),
        "%{public}s", "Notify event error, dev not exist.");
    CHECK_NULL_VOID(audioDevMap_[devId]);
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
    CHECK_NULL_VOID(dev->second);
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
    rcvProviderPtr_ = getEngineFactoryFunc(OWNER_NAME_D_SPEAKER);
    DHLOGI("LoadAVReceiverEngineProvider success.");
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

void DAudioSinkManager::SetChannelState(const std::string &content)
{
    DHLOGI("The channel state belong to %{public}s.", content.c_str());
    if (content.find(OWNER_NAME_D_SPEAKER) != content.npos) {
        channelState_ = ChannelState::SPK_CONTROL_OPENED;
    } else if (content.find(OWNER_NAME_D_MIC) != content.npos) {
        channelState_ = ChannelState::MIC_CONTROL_OPENED;
    }
}

int32_t EngineProviderListener::OnProviderEvent(const AVTransEvent &event)
{
    DHLOGI("On event :%{public}d, eventContent: %{public}s.", event.type, event.content.c_str());
    if (event.type == EventType::EVENT_CHANNEL_OPENED) {
        DHLOGI("Received control channel opened event, create audio device for peerDevId=%{public}s, "
            "content=%{public}s.", GetAnonyString(event.peerDevId).c_str(), event.content.c_str());
        DAudioSinkManager::GetInstance().SetChannelState(event.content);
        DAudioSinkManager::GetInstance().CreateAudioDevice(event.peerDevId);
    } else if (event.type == EventType::EVENT_CHANNEL_CLOSED) {
        DHLOGI("Received control channel closed event, clear audio device for peerDevId=%{public}s",
            GetAnonyString(event.peerDevId).c_str());
        std::string eventStr = event.content;
        DAudioSinkManager::GetInstance().NotifyEvent(event.peerDevId, DISABLE_DEVICE, eventStr);
    } else {
        DHLOGE("Invaild event type.");
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::PauseDistributedHardware(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(devMapMutex_);
    if (audioDevMap_.find(networkId) != audioDevMap_.end()) {
        DHLOGI("Audio sink dev in map. devId: %{public}s.", GetAnonyString(networkId).c_str());
        audioDevMap_[networkId]->PauseDistributedHardware(networkId);
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::ResumeDistributedHardware(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(devMapMutex_);
    if (audioDevMap_.find(networkId) != audioDevMap_.end()) {
        DHLOGI("Audio sink dev in map. devId: %{public}s.", GetAnonyString(networkId).c_str());
        audioDevMap_[networkId]->ResumeDistributedHardware(networkId);
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkManager::StopDistributedHardware(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(devMapMutex_);
    if (audioDevMap_.find(networkId) != audioDevMap_.end()) {
        DHLOGI("Audio sink dev in map. devId: %{public}s.", GetAnonyString(networkId).c_str());
        audioDevMap_[networkId]->StopDistributedHardware(networkId);
    }
    return DH_SUCCESS;
}

bool DAudioSinkManager::CheckDeviceSecurityLevel(const std::string &srcDeviceId, const std::string &dstDeviceId)
{
    DHLOGI("CheckDeviceSecurityLevel srcDeviceId %{public}s, dstDeviceId %{public}s.",
        srcDeviceId.c_str(), dstDeviceId.c_str());
    std::string srcUdid = GetUdidByNetworkId(srcDeviceId);
    if (srcUdid.empty()) {
        DHLOGE("src udid is empty");
        return false;
    }
    std::string dstUdid = GetUdidByNetworkId(dstDeviceId);
    if (dstUdid.empty()) {
        DHLOGE("dst udid is empty");
        return false;
    }
    DHLOGI("CheckDeviceSecurityLevel srcUdid %{public}s, dstUdid %{public}s.",
        GetAnonyString(srcUdid).c_str(), GetAnonyString(dstUdid).c_str());
    int32_t srcDeviceSecurityLevel = GetDeviceSecurityLevel(srcUdid);
    int32_t dstDeviceSecurityLevel = GetDeviceSecurityLevel(dstUdid);
    DHLOGI("SrcDeviceSecurityLevel, level is %{public}d", srcDeviceSecurityLevel);
    DHLOGI("dstDeviceSecurityLevel, level is %{public}d", dstDeviceSecurityLevel);
    if (srcDeviceSecurityLevel == DEFAULT_DEVICE_SECURITY_LEVEL ||
        srcDeviceSecurityLevel < dstDeviceSecurityLevel) {
        DHLOGE("The device security of source device is lower.");
        return false;
    }
    return true;
}

int32_t DAudioSinkManager::GetDeviceSecurityLevel(const std::string &udid)
{
    DeviceIdentify devIdentify;
    devIdentify.length = DEVICE_ID_MAX_LEN;
    int32_t ret = memcpy_s(devIdentify.identity, DEVICE_ID_MAX_LEN, udid.c_str(), DEVICE_ID_MAX_LEN);
    if (ret != DH_SUCCESS) {
        DHLOGE("Str copy failed %{public}d", ret);
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    DeviceSecurityInfo *info = nullptr;
    ret = RequestDeviceSecurityInfo(&devIdentify, nullptr, &info);
    if (ret != DH_SUCCESS) {
        DHLOGE("Request device security info failed %{public}d", ret);
        FreeDeviceSecurityInfo(info);
        info = nullptr;
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    int32_t level = 0;
    ret = GetDeviceSecurityLevelValue(info, &level);
    DHLOGE("Get device security level, level is %{public}d", level);
    FreeDeviceSecurityInfo(info);
    info = nullptr;
    if (ret != DH_SUCCESS) {
        DHLOGE("Get device security level failed %{public}d", ret);
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    return level;
}

std::string DAudioSinkManager::GetUdidByNetworkId(const std::string &networkId)
{
    if (networkId.empty()) {
        DHLOGE("networkId is empty!");
        return "";
    }
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, initCallback_);
    if (ret != ERR_OK) {
        DHLOGE("InitDeviceManager failed ret = %{public}d", ret);
    }
    std::string udid = "";
    ret = DeviceManager::GetInstance().GetUdidByNetworkId(PKG_NAME, networkId, udid);
    if (ret != ERR_OK) {
        DHLOGE("GetUdidByNetworkId failed ret = %{public}d", ret);
        return "";
    }
    return udid;
}

int32_t DAudioSinkManager::VerifySecurityLevel(const std::string &devId)
{
    std::string subType = "mic";
    int32_t ret = ipcSinkCallback_->OnNotifyResourceInfo(ResourceEventType::EVENT_TYPE_QUERY_RESOURCE, subType, devId,
        isSensitive_, isSameAccount_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Query resource failed, ret: %{public}d", ret);
        return ret;
    }
    DHLOGI("VerifySecurityLevel isSensitive: %{public}d, isSameAccount: %{public}d", isSensitive_, isSameAccount_);
    if (isSensitive_ && !isSameAccount_) {
        DHLOGE("Privacy resource must be logged in with same account.");
        return ERR_DH_AUDIO_FAILED;
    }

    std::string sinkDevId = "";
    ret = GetLocalDeviceNetworkId(sinkDevId);
    if (ret != DH_SUCCESS) {
        DHLOGE("GetLocalDeviceNetworkId failed, ret: %{public}d", ret);
        return ret;
    }
    if (isSensitive_ && !CheckDeviceSecurityLevel(devId, sinkDevId)) {
        DHLOGE("Check device security level failed!");
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

void DeviceInitCallback::OnRemoteDied()
{
    DHLOGI("DeviceInitCallback OnRemoteDied");
}
} // namespace DistributedHardware
} // namespace OHOS
