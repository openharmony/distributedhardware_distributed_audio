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

#ifndef OHOS_DAUDIO_SINK_IPC_CALLBACK_PROXY_H
#define OHOS_DAUDIO_SINK_IPC_CALLBACK_PROXY_H

#include "idaudio_sink_ipc_callback.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkIpcCallbackProxy : public IRemoteProxy<IDAudioSinkIpcCallback> {
public:
    explicit DAudioSinkIpcCallbackProxy(const sptr<IRemoteObject> impl) : IRemoteProxy<IDAudioSinkIpcCallback>(impl) {}

    ~DAudioSinkIpcCallbackProxy() {}
    int32_t OnNotifyResourceInfo(const ResourceEventType &type, const std::string &subType,
        const std::string &networkId, bool &isSensitive, bool &isSameAccount) override;

private:
    static inline BrokerDelegator<DAudioSinkIpcCallbackProxy> delegator_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_IPC_CALLBACK_PROXY_H