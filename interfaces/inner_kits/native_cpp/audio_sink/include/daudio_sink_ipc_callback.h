/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_SINK_IPC_CALLBACK_H
#define OHOS_DAUDIO_SINK_IPC_CALLBACK_H

#include <vector>
#include <mutex>

#include "daudio_sink_ipc_callback_stub.h"
#include "idistributed_hardware_sink.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkIpcCallback : public DAudioSinkIpcCallbackStub {
public:
    DAudioSinkIpcCallback() = default;
    ~DAudioSinkIpcCallback() override = default;

    int32_t OnNotifyResourceInfo(const ResourceEventType &type, const std::string &subType,
        const std::string &networkId, bool &isSensitive, bool &isSameAccount) override;
    void PushPrivacyResCallback(const std::shared_ptr<PrivacyResourcesListener> &listener);

private:
    std::mutex privacyResMtx_;
    std::vector<std::shared_ptr<PrivacyResourcesListener>> privacyResCallback_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_IPC_CALLBACK_H