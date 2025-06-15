/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_HDF_OPERATE_H
#define OHOS_DAUDIO_HDF_OPERATE_H

#include <atomic>
#include <condition_variable>
#include <mutex>

#include "iservstat_listener_hdi.h"
#include "idevmgr_hdi.h"
#include "iservmgr_hdi.h"
#include "single_instance.h"
#include <v2_0/id_audio_manager.h>

namespace OHOS {
namespace DistributedHardware {
const std::string AUDIO_SERVICE_NAME = "daudio_primary_service";
const std::string AUDIOEXT_SERVICE_NAME = "daudio_ext_service";
constexpr uint16_t AUDIO_INVALID_VALUE = 0xffff;
constexpr int32_t AUDIO_WAIT_TIME = 5000;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
using OHOS::HDI::ServiceManager::V1_0::IServiceManager;
using OHOS::HDI::ServiceManager::V1_0::IServStatListener;
using OHOS::HDI::ServiceManager::V1_0::ServiceStatus;
using OHOS::HDI::ServiceManager::V1_0::ServStatListenerStub;
using OHOS::HDI::DistributedAudio::Audioext::V2_0::IDAudioManager;
using OHOS::HDI::DistributedAudio::Audioext::V2_0::IDAudioHdfCallback;
using OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent;

class FwkDAudioHdfCallback;
class DaudioHdfOperate {
DECLARE_SINGLE_INSTANCE(DaudioHdfOperate);

public:
    int32_t LoadDaudioHDFImpl();
    int32_t UnLoadDaudioHDFImpl();
    void ResetRefCount();

private:
    int32_t WaitLoadService(const std::string& servName);
    OHOS::sptr<IServStatListener> MakeServStatListener();
    int32_t LoadDevice();
    int32_t UnLoadDevice();
    int32_t RegisterHdfListener();
    int32_t UnRegisterHdfListener();

private:
    OHOS::sptr<IDeviceManager> devmgr_;
    OHOS::sptr<IServiceManager> servMgr_;
    OHOS::sptr<IDAudioManager> audioSrvHdf_;
    OHOS::sptr<FwkDAudioHdfCallback> fwkDAudioHdfCallback_;
    std::atomic<uint16_t> audioServStatus_ = AUDIO_INVALID_VALUE;
    std::atomic<uint16_t> audioextServStatus_ = AUDIO_INVALID_VALUE;
    std::condition_variable hdfOperateCon_;
    std::mutex hdfOperateMutex_;
    int32_t hdfLoadRef_ = 0;
    std::mutex hdfLoadRefMutex_;
};

class DAudioHdfServStatListener : public OHOS::HDI::ServiceManager::V1_0::ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const ServiceStatus &)>;
    explicit DAudioHdfServStatListener(StatusCallback callback) : callback_(std::move(callback))
    {
    }
    ~DAudioHdfServStatListener() override = default;
    void OnReceive(const ServiceStatus& status) override;

private:
    StatusCallback callback_;
};

class FwkDAudioHdfCallback : public IDAudioHdfCallback {
protected:
    int32_t NotifyEvent(int32_t devId, const DAudioEvent& event) override;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_HDF_OPERATE_H