/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "daudio_hdf_operate.h"

#include <hdf_io_service_if.h>
#include <hdf_base.h>

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHdfServStatListener"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DaudioHdfOperate);
void DAudioHdfServStatListener::OnReceive(const ServiceStatus& status)
{
    DHLOGI("Service status on receive.");
    if (status.serviceName == AUDIO_SERVICE_NAME || status.serviceName == AUDIOEXT_SERVICE_NAME) {
        callback_(status);
    }
}

int32_t DaudioHdfOperate::LoadDaudioHDFImpl()
{
    if (audioServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START &&
        audioextServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGD("Service has already start.");
        return DH_SUCCESS;
    }
    servMgr_ = IServiceManager::Get();
    devmgr_ = IDeviceManager::Get();
    CHECK_NULL_RETURN(servMgr_, ERR_DH_AUDIO_NULLPTR);
    CHECK_NULL_RETURN(devmgr_, ERR_DH_AUDIO_NULLPTR);

    ::OHOS::sptr<IServStatListener> listener(
        new DAudioHdfServStatListener(DAudioHdfServStatListener::StatusCallback([&](const ServiceStatus& status) {
            DHLOGI("Load audio service status callback, serviceName: %{public}s, status: %{public}d",
                status.serviceName.c_str(), status.status);
            std::unique_lock<std::mutex> lock(hdfOperateMutex_);
            if (status.serviceName == AUDIO_SERVICE_NAME) {
                audioServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            } else if (status.serviceName == AUDIOEXT_SERVICE_NAME) {
                audioextServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            }
    })));
    if (servMgr_->RegisterServiceStatusListener(listener, DEVICE_CLASS_AUDIO) != HDF_SUCCESS) {
        DHLOGE("Failed to register the service status listener.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    int32_t ret = devmgr_->LoadDevice(AUDIO_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (WaitLoadService(AUDIO_SERVICE_NAME) != DH_SUCCESS) {
        DHLOGE("Wait load audio service failed!");
        return ERR_DH_AUDIO_FAILED;
    }
    ret = devmgr_->LoadDevice(AUDIOEXT_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        return ERR_DH_AUDIO_FAILED;
    }
    if (WaitLoadExtService(AUDIOEXT_SERVICE_NAME) != DH_SUCCESS) {
        DHLOGE("Wait load provider service failed!");
        return ERR_DH_AUDIO_FAILED;
    }

    if (servMgr_->UnregisterServiceStatusListener(listener) != HDF_SUCCESS) {
        DHLOGE("Failed to unregister the service status listener.");
    }
    return DH_SUCCESS;
}

int32_t DaudioHdfOperate::WaitLoadService(const std::string& servName)
{
    std::unique_lock<std::mutex> lock(hdfOperateMutex_);
    DHLOGD("WaitLoadService start service %s, status %hu", servName.c_str(), this->audioServStatus_.load());
    hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(WAIT_TIME), [this] {
        return (this->audioServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    });

    if (this->audioServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGE("Wait load service %{public}s failed, status %{public}hu", servName.c_str(),
            this->audioServStatus_.load());
        return ERR_DH_AUDIO_FAILED;
    }

    return DH_SUCCESS;
}

int32_t DaudioHdfOperate::WaitLoadExtService(const std::string& servName)
{
    std::unique_lock<std::mutex> lock(hdfOperateMutex_);
    DHLOGD("WaitLoadService start service %s, status %hu", servName.c_str(), this->audioextServStatus_.load());
    hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(WAIT_TIME), [this] {
        return (this->audioextServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    });

    if (this->audioextServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGE("Wait load service %{public}s failed, status %{public}hu", servName.c_str(),
            this->audioextServStatus_.load());
        return ERR_DH_AUDIO_FAILED;
    }

    return DH_SUCCESS;
}

int32_t DaudioHdfOperate::UnLoadDaudioHDFImpl()
{
    DHLOGI("UnLoad daudio hdf impl begin!");
    devmgr_ = IDeviceManager::Get();
    CHECK_NULL_RETURN(devmgr_, ERR_DH_AUDIO_NULLPTR);

    int32_t ret = devmgr_->UnloadDevice(AUDIO_SERVICE_NAME);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Unload audio service failed, ret: %{public}d", ret);
    }
    ret = devmgr_->UnloadDevice(AUDIOEXT_SERVICE_NAME);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Unload device failed, ret: %{public}d", ret);
    }
    audioServStatus_.store(INVALID_VALUE);
    audioextServStatus_.store(INVALID_VALUE);
    DHLOGI("UnLoad daudio hdf impl end!");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS