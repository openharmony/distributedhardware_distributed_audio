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

#include "daudio_ipc_callback_stub.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioIpcCallbackStub"

namespace OHOS {
namespace DistributedHardware {
DAudioIpcCallbackStub::DAudioIpcCallbackStub() : IRemoteStub(true)
{
    memberFuncMap_[NOTIFY_REGRESULT] = &DAudioIpcCallbackStub::OnNotifyRegResultInner;
    memberFuncMap_[NOTIFY_UNREGRESULT] = &DAudioIpcCallbackStub::OnNotifyUnregResultInner;
    memberFuncMap_[NOTIFY_STATE_CHANGED] = &DAudioIpcCallbackStub::OnHardwareStateChangedInner;
    memberFuncMap_[NOTIFY_DATASYNC_TRIGGER] = &DAudioIpcCallbackStub::OnDataSyncTriggerInner;
}

int32_t DAudioIpcCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHLOGI("On remote request, code: %{public}u", code);
    std::u16string desc = DAudioIpcCallbackStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        DHLOGE("RemoteDesc is invalid.");
        return ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN;
    }

    std::map<int32_t, DAudioCallbackFunc>::iterator iter = memberFuncMap_.find(code);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid request code.");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    DAudioCallbackFunc &func = iter->second;
    return (this->*func)(data, reply, option);
}

int32_t DAudioIpcCallbackStub::OnNotifyRegResultInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string reqId = data.ReadString();
    int32_t status = data.ReadInt32();
    std::string resultData = data.ReadString();
    int32_t ret = OnNotifyRegResult(networkId, dhId, reqId, status, resultData);
    return ret;
}

int32_t DAudioIpcCallbackStub::OnNotifyUnregResultInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string reqId = data.ReadString();
    int32_t status = data.ReadInt32();
    std::string resultData = data.ReadString();
    int32_t ret = OnNotifyUnregResult(networkId, dhId, reqId, status, resultData);
    return ret;
}

int32_t DAudioIpcCallbackStub::OnHardwareStateChangedInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    int32_t status = data.ReadInt32();
    int32_t ret = OnHardwareStateChanged(networkId, dhId, status);
    return ret;
}

int32_t DAudioIpcCallbackStub::OnDataSyncTriggerInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    int32_t ret = OnDataSyncTrigger(networkId);
    return ret;
}
} // DistributedHardware
} // OHOS