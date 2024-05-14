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

#include "daudio_sink_handler.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_sink_load_callback.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkHandler"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioSinkHandler);

DAudioSinkHandler::DAudioSinkHandler()
{
    DHLOGD("DAudio sink handler constructed.");
    if (!dAudioSinkIpcCallback_) {
        dAudioSinkIpcCallback_ = new DAudioSinkIpcCallback();
    }
}

DAudioSinkHandler::~DAudioSinkHandler()
{
    DHLOGD("DAudio sink handler destructed.");
}

int32_t DAudioSinkHandler::InitSink(const std::string &params)
{
    DHLOGI("Init sink handler.");
    if (dAudioSinkProxy_ == nullptr) {
        sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHECK_NULL_RETURN(samgr, ERR_DH_AUDIO_NULLPTR);
        sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
        int32_t ret = samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
        if (ret != ERR_OK) {
            DHLOGE("Failed to Load systemAbility ret code: %{public}d.", ret);
            DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_INIT_FAIL, DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID,
                ERR_DH_AUDIO_SA_LOAD_FAILED, "daudio sink LoadSystemAbility call failed.");
            return ERR_DH_AUDIO_SA_LOAD_FAILED;
        }
    }

    std::unique_lock<std::mutex> lock(sinkProxyMutex_);
    auto waitStatus = sinkProxyConVar_.wait_for(lock, std::chrono::milliseconds(AUDIO_LOADSA_TIMEOUT_MS),
        [this]() { return dAudioSinkProxy_ != nullptr; });
    if (!waitStatus) {
        DHLOGE("Audio load sa timeout.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_INIT_FAIL, DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID,
            ERR_DH_AUDIO_SA_LOAD_FAILED, "daudio sink sa load timeout.");
        return ERR_DH_AUDIO_SA_LOAD_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkHandler::ReleaseSink()
{
    DHLOGI("Release sink handler.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    if (dAudioSinkProxy_ == nullptr) {
        DHLOGE("Daudio sink proxy not init.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_INIT_FAIL, DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID,
            ERR_DH_AUDIO_SA_PROXY_NOT_INIT, "daudio sink proxy not init.");
        return ERR_DH_AUDIO_SA_PROXY_NOT_INIT;
    }

    int32_t ret = dAudioSinkProxy_->ReleaseSink();
    dAudioSinkProxy_ = nullptr;
    return ret;
}

int32_t DAudioSinkHandler::SubscribeLocalHardware(const std::string &dhId, const std::string &param)
{
    DHLOGI("Subscribe to local hardware.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    CHECK_NULL_RETURN(dAudioSinkProxy_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    if (dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    std::string reduceDhId = ReduceDhIdPrefix(dhId);
    int32_t ret = dAudioSinkProxy_->SubscribeLocalHardware(reduceDhId, param);
    return ret;
}

int32_t DAudioSinkHandler::UnsubscribeLocalHardware(const std::string &dhId)
{
    DHLOGI("Unsubscribe from local hardware.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    CHECK_NULL_RETURN(dAudioSinkProxy_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    if (dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    std::string reduceDhId = ReduceDhIdPrefix(dhId);
    int32_t ret = dAudioSinkProxy_->UnsubscribeLocalHardware(reduceDhId);
    return ret;
}

void DAudioSinkHandler::OnRemoteSinkSvrDied(const wptr<IRemoteObject> &remote)
{
    DHLOGI("The daudio service of sink device died.");
    sptr<IRemoteObject> remoteObject = remote.promote();
    CHECK_NULL_VOID(remoteObject);

    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    if (dAudioSinkProxy_ != nullptr) {
        dAudioSinkProxy_->AsObject()->RemoveDeathRecipient(sinkSvrRecipient_);
        dAudioSinkProxy_ = nullptr;
    }
}

void DAudioSinkHandler::FinishStartSA(const std::string &param, const sptr<IRemoteObject> &remoteObject)
{
    DHLOGI("Finish start SA.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    remoteObject->AddDeathRecipient(sinkSvrRecipient_);
    dAudioSinkProxy_ = iface_cast<IDAudioSink>(remoteObject);
    if ((dAudioSinkProxy_ == nullptr) || (!dAudioSinkProxy_->AsObject())) {
        DHLOGE("Failed to get daudio sink proxy.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_INIT_FAIL, DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID,
            ERR_DH_AUDIO_SA_PROXY_NOT_INIT, "daudio sink get proxy failed.");
        return;
    }
    dAudioSinkProxy_->InitSink(param, dAudioSinkIpcCallback_);
    sinkProxyConVar_.notify_one();
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_INIT, "daudio sink sa load success.");
}

void DAudioSinkHandler::DAudioSinkSvrRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DAudioSinkHandler::GetInstance().OnRemoteSinkSvrDied(remote);
}

IDistributedHardwareSink *GetSinkHardwareHandler()
{
    DHLOGD("Get sink hardware handler.");
    return &DAudioSinkHandler::GetInstance();
}

int32_t DAudioSinkHandler::RegisterPrivacyResources(std::shared_ptr<PrivacyResourcesListener> listener)
{
    DHLOGI("RegisterPrivacyResources start.");
    CHECK_NULL_RETURN(dAudioSinkIpcCallback_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    dAudioSinkIpcCallback_->PushPrivacyResCallback(listener);
    return DH_SUCCESS;
}

int32_t DAudioSinkHandler::PauseDistributedHardware(const std::string &networkId)
{
    DHLOGI("pause distributed hardware.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    CHECK_NULL_RETURN(dAudioSinkProxy_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    return dAudioSinkProxy_->PauseDistributedHardware(networkId);
}

int32_t DAudioSinkHandler::ResumeDistributedHardware(const std::string &networkId)
{
    DHLOGI("resume distributed hardware.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    CHECK_NULL_RETURN(dAudioSinkProxy_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    return dAudioSinkProxy_->ResumeDistributedHardware(networkId);
}

int32_t DAudioSinkHandler::StopDistributedHardware(const std::string &networkId)
{
    DHLOGI("stop distributed hardware.");
    std::lock_guard<std::mutex> lock(sinkProxyMutex_);
    CHECK_NULL_RETURN(dAudioSinkProxy_, ERR_DH_AUDIO_SA_PROXY_NOT_INIT);
    return dAudioSinkProxy_->StopDistributedHardware(networkId);
}
} // namespace DistributedHardware
} // namespace OHOS