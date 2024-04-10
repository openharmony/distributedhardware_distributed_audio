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

#include "daudio_ipc_callback.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioIpcCallback"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioIpcCallback::OnNotifyRegResult(const std::string &devId, const std::string &dhId,
    const std::string &reqId, int32_t status, const std::string &resultData)
{
    DHLOGI("On notify the registration result, devId: %{public}s, dhId: %{public}s, status: %{public}d, "
        "resultData: %{public}s, reqId: %{public}s", GetAnonyString(devId).c_str(), dhId.c_str(),
        status, resultData.c_str(), reqId.c_str());

    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN ||
        reqId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    std::lock_guard<std::mutex> registerLck(registerMapMtx_);
    auto iter = registerCallbackMap_.find(reqId);
    if (iter != registerCallbackMap_.end()) {
        std::string reduceDhId = AddDhIdPrefix(dhId);
        iter->second->OnRegisterResult(devId, reduceDhId, status, resultData);
        registerCallbackMap_.erase(reqId);
        return DH_SUCCESS;
    }

    return ERR_DH_AUDIO_SA_CALLBACK_NOT_FOUND;
}

int32_t DAudioIpcCallback::OnNotifyUnregResult(const std::string &devId, const std::string &dhId,
    const std::string &reqId, int32_t status, const std::string &resultData)
{
    DHLOGI("On notify the unregistration result, devId: %{public}s, dhId: %{public}s, status: %{public}d, "
        "resultData: %{public}s, reqId: %{public}s", GetAnonyString(devId).c_str(), dhId.c_str(),
        status, resultData.c_str(), reqId.c_str());

    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN ||
        reqId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    std::lock_guard<std::mutex> registerLck(unregisterMapMtx_);
    auto iter = unregisterCallbackMap_.find(reqId);
    if (iter != unregisterCallbackMap_.end()) {
        std::string reduceDhId = AddDhIdPrefix(dhId);
        iter->second->OnUnregisterResult(devId, reduceDhId, status, resultData);
        unregisterCallbackMap_.erase(reqId);
        return DH_SUCCESS;
    }
    return ERR_DH_AUDIO_SA_CALLBACK_NOT_FOUND;
}

void DAudioIpcCallback::PushRegisterCallback(const std::string &reqId,
    const std::shared_ptr<RegisterCallback> &callback)
{
    DHLOGD("Push register callback, reqId: %{public}s", reqId.c_str());
    std::lock_guard<std::mutex> registerLck(registerMapMtx_);
    registerCallbackMap_.emplace(reqId, callback);
}

void DAudioIpcCallback::PopRegisterCallback(const std::string &reqId)
{
    DHLOGD("Pop register callback, reqId: %{public}s", reqId.c_str());
    std::lock_guard<std::mutex> registerLck(registerMapMtx_);
    registerCallbackMap_.erase(reqId);
}

void DAudioIpcCallback::PushUnregisterCallback(const std::string &reqId,
    const std::shared_ptr<UnregisterCallback> &callback)
{
    DHLOGD("Push unregister callback, reqId: %{public}s", reqId.c_str());
    std::lock_guard<std::mutex> registerLck(unregisterMapMtx_);
    unregisterCallbackMap_.emplace(reqId, callback);
}

void DAudioIpcCallback::PopUnregisterCallback(const std::string &reqId)
{
    DHLOGD("Pop unregister callback, reqId: %{public}s", reqId.c_str());
    std::lock_guard<std::mutex> registerLck(unregisterMapMtx_);
    unregisterCallbackMap_.erase(reqId);
}
} // DistributedHardware
} // OHOS