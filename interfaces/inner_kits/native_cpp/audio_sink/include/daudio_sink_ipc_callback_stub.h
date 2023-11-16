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

#ifndef OHOS_DAUDIO_SINK_IPC_CALLBACK_STUB_H
#define OHOS_DAUDIO_SINK_IPC_CALLBACK_STUB_H

#include <map>

#include "idaudio_sink_ipc_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkIpcCallbackStub : public IRemoteStub<IDAudioSinkIpcCallback> {
public:
    DAudioSinkIpcCallbackStub();
    virtual ~DAudioSinkIpcCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t OnNotifyResourceInfoInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);

    using DAudioSinkCallbackFunc = int32_t (DAudioSinkIpcCallbackStub::*)(MessageParcel &data, MessageParcel &reply,
        MessageOption &option);
    std::map<int32_t, DAudioSinkCallbackFunc> memberFuncMap_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_IPC_CALLBACK_STUB_H