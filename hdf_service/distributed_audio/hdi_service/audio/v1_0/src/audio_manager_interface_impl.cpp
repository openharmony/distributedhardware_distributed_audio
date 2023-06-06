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

#include "audio_manager_interface_impl.h"

#include <hdf_base.h>
#include "hdf_device_object.h"
#include <sstream>

#include "daudio_constants.h"
#include "daudio_errcode.h"
#include "daudio_events.h"
#include "daudio_log.h"
#include "daudio_utils.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioManagerInterfaceImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
AudioManagerInterfaceImpl *AudioManagerInterfaceImpl::audioManager_ = nullptr;
std::mutex AudioManagerInterfaceImpl::audioManagerMtx_;
extern "C" IAudioManager *AudioManagerImplGetInstance(void)
{
    return AudioManagerInterfaceImpl::GetAudioManager();
}

AudioManagerInterfaceImpl::AudioManagerInterfaceImpl()
{
    DHLOGD("Distributed audio manager constructed.");
}

AudioManagerInterfaceImpl::~AudioManagerInterfaceImpl()
{
    DHLOGD("Distributed audio manager destructed.");
}

int32_t AudioManagerInterfaceImpl::GetAllAdapters(std::vector<AudioAdapterDescriptor> &descs)
{
    DHLOGI("Get all distributed audio adapters.");
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);

    std::transform(mapAudioAdapter_.begin(), mapAudioAdapter_.end(), std::back_inserter(descs),
        [](auto& adp) { return adp.second->GetAdapterDesc(); });

    DHLOGI("Get adapters success, total is (%zu). ", mapAudioAdapter_.size());
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::LoadAdapter(const AudioAdapterDescriptor &desc, sptr<IAudioAdapter> &adapter)
{
    DHLOGI("Load distributed audio adapter: %s.", GetAnonyString(desc.adapterName).c_str());
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(desc.adapterName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Load audio adapter failed, can not find adapter.");
        adapter = nullptr;
        return HDF_FAILURE;
    }

    int32_t ret = adp->second->AdapterLoad();
    if (ret != DH_SUCCESS) {
        DHLOGE("Load audio adapter failed, adapter return: %d.", ret);
        adapter = nullptr;
        return HDF_FAILURE;
    }

    adapter = adp->second;
    DHLOGI("Load adapter success.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::UnloadAdapter(const std::string &adapterName)
{
    DHLOGI("Unload distributed audio adapter: %s.", GetAnonyString(adapterName).c_str());
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adapterName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Unload audio adapter failed, can not find adapter.");
        return HDF_SUCCESS;
    }

    int32_t ret = adp->second->AdapterUnload();
    if (ret != DH_SUCCESS) {
        DHLOGE("Unload audio adapter failed, adapter return: %d.", ret);
        return HDF_SUCCESS;
    }
    DHLOGI("Unload adapter success.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::ReleaseAudioManagerObject()
{
    DHLOGD("Release distributed audio manager object.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::AddAudioDevice(const std::string &adpName, const uint32_t devId,
    const std::string &caps, const sptr<IDAudioCallback> &callback)
{
    DHLOGI("Add audio device name: %s, device: %d.", GetAnonyString(adpName).c_str(), devId);
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end()) {
        int32_t ret = CreateAdapter(adpName, devId, callback);
        if (ret != DH_SUCCESS) {
            DHLOGE("Create audio adapter failed.");
            return ERR_DH_AUDIO_HDF_FAIL;
        }
    }
    adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end() || adp->second == nullptr) {
        DHLOGE("Audio device has not been created  or is null ptr.");
        return ERR_DH_AUDIO_HDF_INVALID_OPERATION;
    }
    switch (GetDevTypeByDHId(devId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            adp->second->SetSpeakerCallback(callback);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            adp->second->SetMicCallback(callback);
            break;
        case AUDIO_DEVICE_TYPE_UNKNOWN:
        default:
            DHLOGE("DhId is illegal, devType is unknow.");
            return ERR_DH_AUDIO_HDF_FAIL;
    }
    int32_t ret = adp->second->AddAudioDevice(devId, caps);
    if (ret != DH_SUCCESS) {
        DHLOGE("Add audio device failed, adapter return: %d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }

    DAudioDevEvent event = { adpName,
                             devId,
                             HDF_AUDIO_DEVICE_ADD,
                             0,
                             adp->second->GetVolumeGroup(devId),
                             adp->second->GetInterruptGroup(devId) };
    ret = NotifyFwk(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify audio fwk failed, ret = %d.", ret);
        return ret;
    }
    DHLOGI("Add audio device success.");
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::RemoveAudioDevice(const std::string &adpName, const uint32_t devId)
{
    DHLOGI("Remove audio device name: %s, device: %d.", GetAnonyString(adpName).c_str(), devId);
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end() || adp->second == nullptr) {
        DHLOGE("Audio device has not been created  or is null ptr.");
        return ERR_DH_AUDIO_HDF_INVALID_OPERATION;
    }

    int32_t ret = adp->second->RemoveAudioDevice(devId);
    if (ret != DH_SUCCESS) {
        DHLOGE("Remove audio device failed, adapter return: %d.", ret);
        return ret;
    }

    DAudioDevEvent event = { adpName, devId, HDF_AUDIO_DEVICE_REMOVE, 0, 0, 0 };
    ret = NotifyFwk(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify audio fwk failed, ret = %d.", ret);
    }
    if (adp->second->IsPortsNoReg()) {
        mapAudioAdapter_.erase(adpName);
    }
    DHLOGI("Remove audio device success, mapAudioAdapter size() is : %d .", mapAudioAdapter_.size());
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::Notify(const std::string &adpName, const uint32_t devId, const DAudioEvent &event)
{
    DHLOGI("Notify event, adapter name: %s. event type: %d", GetAnonyString(adpName).c_str(),
        event.type);
    auto adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Notify failed, can not find adapter.");
        return ERR_DH_AUDIO_HDF_INVALID_OPERATION;
    }

    int32_t ret = adp->second->Notify(devId, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify failed, adapter return: %d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::NotifyFwk(const DAudioDevEvent &event)
{
    DHLOGD("Notify audio fwk event(type:%d, adapter:%s, pin:%d).", event.eventType,
        GetAnonyString(event.adapterName).c_str(), event.devId);
    std::stringstream ss;
    ss << "EVENT_TYPE=" << event.eventType << ";NID=" << event.adapterName << ";PIN=" << event.devId << ";VID=" <<
        event.volGroupId << ";IID=" << event.iptGroupId;
    std::string eventInfo = ss.str();
    int ret = HdfDeviceObjectSetServInfo(deviceObject_, eventInfo.c_str());
    if (ret != HDF_SUCCESS) {
        DHLOGE("Set service info failed, ret = %d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    ret = HdfDeviceObjectUpdate(deviceObject_);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Update service info failed, ret = %d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }

    DHLOGI("Notify audio fwk success.");
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::CreateAdapter(const std::string &adpName, const uint32_t devId,
    const sptr<IDAudioCallback> &callback)
{
    if (callback == nullptr) {
        DHLOGE("Adapter callback is null.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    if (devId != PIN_OUT_DAUDIO_DEFAULT && devId != PIN_IN_DAUDIO_DEFAULT) {
        DHLOGE("Pin is not default, can not create audio adapter.");
        return ERR_DH_AUDIO_HDF_FAIL;
    }

    AudioAdapterDescriptor desc = { adpName };
    sptr<AudioAdapterInterfaceImpl> adapter(new AudioAdapterInterfaceImpl(desc));
    if (adapter == nullptr) {
        DHLOGE("Create new audio adapter failed.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    mapAudioAdapter_.insert(std::make_pair(adpName, adapter));
    return DH_SUCCESS;
}

void AudioManagerInterfaceImpl::SetDeviceObject(struct HdfDeviceObject *deviceObject)
{
    deviceObject_ = deviceObject;
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOSf
