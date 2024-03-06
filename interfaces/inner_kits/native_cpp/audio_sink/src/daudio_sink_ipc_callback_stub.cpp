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

#include "daudio_sink_ipc_callback_stub.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkIpcCallbackStub"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkIpcCallbackStub::DAudioSinkIpcCallbackStub() : IRemoteStub(true)
{
    memberFuncMap_[NOTIFY_RESOURCEINFO] = &DAudioSinkIpcCallbackStub::OnNotifyResourceInfoInner;
}

int32_t DAudioSinkIpcCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHLOGI("On remote request, code: %{public}u", code);
    std::u16string desc = DAudioSinkIpcCallbackStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        DHLOGE("RemoteDesc is invalid.");
        return ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN;
    }

    std::map<int32_t, DAudioSinkCallbackFunc>::iterator iter = memberFuncMap_.find(code);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid request code.");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    DAudioSinkCallbackFunc &func = iter->second;
    return (this->*func)(data, reply, option);
}

int32_t DAudioSinkIpcCallbackStub::OnNotifyResourceInfoInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int32_t ret = DH_SUCCESS;
    bool isSensitive;
    bool isSameAccount;
    do {
        ResourceEventType type = static_cast<ResourceEventType>(data.ReadInt32());
        std::string subType = data.ReadString();
        std::string networkId = data.ReadString();
        ret = OnNotifyResourceInfo(type, subType, networkId, isSensitive, isSameAccount);
    } while (0);
    reply.WriteInt32(ret);
    reply.WriteBool(isSensitive);
    reply.WriteBool(isSameAccount);
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS