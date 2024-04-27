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

#ifndef OHOS_DAUDIO_IPC_CALLBACK_H
#define OHOS_DAUDIO_IPC_CALLBACK_H

#include <map>
#include <mutex>

#include "daudio_ipc_callback_stub.h"
#include "idistributed_hardware_source.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioIpcCallback : public DAudioIpcCallbackStub {
public:
    DAudioIpcCallback() = default;
    ~DAudioIpcCallback() override = default;

    int32_t OnNotifyRegResult(const std::string &devId, const std::string &dhId, const std::string &reqId,
        int32_t status, const std::string &resultData) override;
    int32_t OnNotifyUnregResult(const std::string &devId, const std::string &dhId, const std::string &reqId,
        int32_t status, const std::string &resultData) override;
    int32_t OnHardwareStateChanged(const std::string &devId, const std::string &dhId, int32_t status) override;
    int32_t OnDataSyncTrigger(const std::string &devId) override;

    void PushRegisterCallback(const std::string &reqId, const std::shared_ptr<RegisterCallback> &callback);
    void PopRegisterCallback(const std::string &reqId);
    void PushUnregisterCallback(const std::string &reqId, const std::shared_ptr<UnregisterCallback> &callback);
    void PopUnregisterCallback(const std::string &reqId);
    void RegisterStateListener(const std::shared_ptr<DistributedHardwareStateListener> &listener);
    void UnRegisterStateListener();
    void RegisterTriggerListener(const std::shared_ptr<DataSyncTriggerListener> &listener);
    void UnRegisterTriggerListener();

private:
    std::mutex registerMapMtx_;
    std::map<std::string, std::shared_ptr<RegisterCallback>> registerCallbackMap_;
    std::mutex unregisterMapMtx_;
    std::map<std::string, std::shared_ptr<UnregisterCallback>> unregisterCallbackMap_;
    std::mutex stateListenerMtx_;
    std::shared_ptr<DistributedHardwareStateListener> stateListener_ = nullptr;
    std::mutex triggerListenerMtx_;
    std::shared_ptr<DataSyncTriggerListener> triggerListener_ = nullptr;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_IPC_CALLBACK_H