/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "daudio_manager_callback.h"

#include <string>
#include <hdf_base.h>
#include <cstdlib>
#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "iproxy_broker.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hdf_operate.h"
#include "daudio_hdi_handler.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHdiHandler"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioHdiHandler);

DAudioHdiHandler::DAudioHdiHandler()
{
    DHLOGD("Distributed audio hdi handler construct.");
    audioHdiRecipient_ = new AudioHdiRecipient();
}

DAudioHdiHandler::~DAudioHdiHandler()
{
    DHLOGD("Distributed audio hdi handler deconstructed.");
}

int32_t DAudioHdiHandler::InitHdiHandler()
{
    DHLOGI("Init hdi handler.");
    if (audioSrvHdf_ != nullptr) {
        return DH_SUCCESS;
    }

    DHLOGD("Load hdf driver start.");
    int32_t ret = DaudioHdfOperate::GetInstance().LoadDaudioHDFImpl();
    if (ret != DH_SUCCESS) {
        DHLOGE("Load hdf driver failed, ret: %{public}d", ret);
        return ret;
    }
    DHLOGD("Load hdf driver end.");

    audioSrvHdf_ = IDAudioManager::Get(HDF_AUDIO_SERVICE_NAME.c_str(), false);
    CHECK_NULL_RETURN(audioSrvHdf_, ERR_DH_AUDIO_NULLPTR);
    remote_ = OHOS::HDI::hdi_objcast<IDAudioManager>(audioSrvHdf_);
    remote_->AddDeathRecipient(audioHdiRecipient_);
    DHLOGI("Init hdi handler success.");
    return DH_SUCCESS;
}

int32_t DAudioHdiHandler::UninitHdiHandler()
{
    DHLOGI("Unload hdf driver start.");
    CHECK_NULL_RETURN(remote_, ERR_DH_AUDIO_NULLPTR);
    remote_->RemoveDeathRecipient(audioHdiRecipient_);
    CHECK_NULL_RETURN(audioSrvHdf_, DH_SUCCESS);

    int32_t ret = DaudioHdfOperate::GetInstance().UnLoadDaudioHDFImpl();
    if (ret != DH_SUCCESS) {
        DHLOGE("Unload hdf driver failed, ret: %{public}d", ret);
        return ret;
    }
    DHLOGI("Uninit hdi handler success.");
    return DH_SUCCESS;
}

int32_t DAudioHdiHandler::RegisterAudioDevice(const std::string &devId, const int32_t dhId,
    const std::string &capability, const std::shared_ptr<IDAudioHdiCallback> &callbackObjParam)
{
    DHLOGI("Register audio device, adpname: %{public}s, dhId: %{public}d", GetAnonyString(devId).c_str(), dhId);
    CHECK_NULL_RETURN(audioSrvHdf_, ERR_DH_AUDIO_NULLPTR);
    std::string searchKey;
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            searchKey = devId + "Speaker" + std::to_string(dhId);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            searchKey = devId + "Mic" + std::to_string(dhId);
            break;
        case AUDIO_DEVICE_TYPE_UNKNOWN:
        default:
            DHLOGE("Unknown audio device.");
            return ERR_DH_AUDIO_NOT_SUPPORT;
    }
    {
        std::lock_guard<std::mutex> devLck(devMapMtx_);
        auto call = mapAudioMgrCallback_.find(searchKey);
        if (call == mapAudioMgrCallback_.end()) {
            const sptr<DAudioManagerCallback> callbackptr(new DAudioManagerCallback(callbackObjParam));
            mapAudioMgrCallback_.emplace(searchKey, callbackptr);
        }
        auto dhIds = mapAudioMgrDhIds_.find(devId);
        if (dhIds != mapAudioMgrDhIds_.end()) {
            dhIds->second.insert(dhId);
        } else {
            std::set<int32_t> newDhIds;
            newDhIds.insert(dhId);
            mapAudioMgrDhIds_.emplace(devId, newDhIds);
        }
    }

    auto iter = mapAudioMgrCallback_.find(searchKey);
    int32_t res = audioSrvHdf_->RegisterAudioDevice(devId, dhId, capability, iter->second);
    if (res != HDF_SUCCESS) {
        DHLOGE("Call hdf proxy register failed, res: %{public}d", res);
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioHdiHandler::UnRegisterAudioDevice(const std::string &devId, const int32_t dhId)
{
    DHLOGI("Unregister audio device, adpname: %{public}s, dhId: %{public}d", GetAnonyString(devId).c_str(), dhId);
    CHECK_NULL_RETURN(audioSrvHdf_, ERR_DH_AUDIO_NULLPTR);
    int32_t res = audioSrvHdf_->UnRegisterAudioDevice(devId, dhId);
    if (res != HDF_SUCCESS) {
        DHLOGE("Call hdf proxy unregister failed, res: %{public}d", res);
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }

    {
        std::lock_guard<std::mutex> devLck(devMapMtx_);
        auto iter = mapAudioMgrDhIds_.find(devId);
        if (iter == mapAudioMgrDhIds_.end()) {
            DHLOGE("Can not find register devId. devId: %{public}s", GetAnonyString(devId).c_str());
            return ERR_DH_AUDIO_SA_CALLBACK_NOT_FOUND;
        }

        iter->second.erase(dhId);
        if (iter->second.empty()) {
            mapAudioMgrDhIds_.erase(devId);
        }
    }
    return DH_SUCCESS;
}

void DAudioHdiHandler::ProcessEventMsg(const AudioEvent &audioEvent, DAudioEvent &newEvent)
{
    switch (audioEvent.type) {
        case AudioEventType::NOTIFY_OPEN_SPEAKER_RESULT:
            newEvent.type = AUDIO_EVENT_OPEN_SPK_RESULT;
            break;
        case AudioEventType::NOTIFY_CLOSE_SPEAKER_RESULT:
            newEvent.type = AUDIO_EVENT_CLOSE_SPK_RESULT;
            break;
        case AudioEventType::NOTIFY_OPEN_MIC_RESULT:
            newEvent.type = AUDIO_EVENT_OPEN_MIC_RESULT;
            break;
        case AudioEventType::NOTIFY_CLOSE_MIC_RESULT:
            newEvent.type = AUDIO_EVENT_CLOSE_MIC_RESULT;
            break;
        case AudioEventType::VOLUME_CHANGE:
            newEvent.type = AUDIO_EVENT_VOLUME_CHANGE;
            break;
        case AudioEventType::SPEAKER_CLOSED:
            newEvent.type = AUDIO_EVENT_SPK_CLOSED;
            break;
        case AudioEventType::MIC_CLOSED:
            newEvent.type = AUDIO_EVENT_MIC_CLOSED;
            break;
        case AudioEventType::AUDIO_FOCUS_CHANGE:
            newEvent.type = AUDIO_EVENT_FOCUS_CHANGE;
            break;
        case AudioEventType::AUDIO_RENDER_STATE_CHANGE:
            newEvent.type = AUDIO_EVENT_RENDER_STATE_CHANGE;
            break;
        case AudioEventType::NOTIFY_HDF_SPK_DUMP:
            newEvent.type = AUDIO_EVENT_SPK_DUMP;
            break;
        case AudioEventType::NOTIFY_HDF_MIC_DUMP:
            newEvent.type = AUDIO_EVENT_MIC_DUMP;
            break;
        default:
            DHLOGE("Unsupport audio event.");
            break;
    }
}

int32_t DAudioHdiHandler::NotifyEvent(const std::string &devId, const int32_t dhId,
    const int32_t streamId, const AudioEvent &audioEvent)
{
    DHLOGD("Notify event adpname: %{public}s, dhId: %{public}d, event type: %{public}d, event content: %{public}s.",
        GetAnonyString(devId).c_str(), dhId, audioEvent.type, audioEvent.content.c_str());
    DAudioEvent newEvent = {AUDIO_EVENT_UNKNOWN, audioEvent.content};
    ProcessEventMsg(audioEvent, newEvent);

    CHECK_NULL_RETURN(audioSrvHdf_, ERR_DH_AUDIO_NULLPTR);
    if (audioSrvHdf_->NotifyEvent(devId, dhId, streamId, newEvent) != HDF_SUCCESS) {
        DHLOGE("Call hdf proxy NotifyEvent failed.");
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    return DH_SUCCESS;
}

void DAudioHdiHandler::AudioHdiRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DHLOGE("Exit the current process remote died.");
    _Exit(0);
}
} // namespace DistributedHardware
} // namespace OHOS
