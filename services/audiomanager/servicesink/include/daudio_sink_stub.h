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

#ifndef OHOS_DAUDIO_SINK_STUB_H
#define OHOS_DAUDIO_SINK_STUB_H

#include <map>

#include "idaudio_sink.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkStub : public IRemoteStub<IDAudioSink> {
public:
    DAudioSinkStub();
    ~DAudioSinkStub() override;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

private:
    int32_t InitSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t ReleaseSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t SubscribeLocalHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t UnsubscribeLocalHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t DAudioNotifyInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    bool VerifyPermission();
    int32_t PauseDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t ResumeDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t StopDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    bool HasAccessDHPermission();

    using DAudioSinkServiceFunc = int32_t (DAudioSinkStub::*)(MessageParcel &data, MessageParcel &reply,
        MessageOption &option);
    std::unordered_map<int32_t, DAudioSinkServiceFunc> memberFuncMap_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_STUB_H