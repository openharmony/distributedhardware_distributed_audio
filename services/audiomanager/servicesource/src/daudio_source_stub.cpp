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

#include "daudio_source_stub.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_callback_proxy.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceStub"

namespace OHOS {
namespace DistributedHardware {
DAudioSourceStub::DAudioSourceStub()
{
    memberFuncMap_[INIT_SOURCE] = &DAudioSourceStub::InitSourceInner;
    memberFuncMap_[RELEASE_SOURCE] = &DAudioSourceStub::ReleaseSourceInner;
    memberFuncMap_[REGISTER_DISTRIBUTED_HARDWARE] = &DAudioSourceStub::RegisterDistributedHardwareInner;
    memberFuncMap_[UNREGISTER_DISTRIBUTED_HARDWARE] = &DAudioSourceStub::UnregisterDistributedHardwareInner;
    memberFuncMap_[CONFIG_DISTRIBUTED_HARDWARE] = &DAudioSourceStub::ConfigDistributedHardwareInner;
    memberFuncMap_[DAUDIO_NOTIFY] = &DAudioSourceStub::DAudioNotifyInner;
}

int32_t DAudioSourceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string desc = DAudioSourceStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        DHLOGE("Remote desc is invalid.");
        return ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN;
    }

    const auto &iter = memberFuncMap_.find(code);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid request code.");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    DAudioSourceServiceFunc &func = iter->second;
    return (this->*func)(data, reply, option);
}

int32_t DAudioSourceStub::InitSourceInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string param = data.ReadString();
    sptr<IRemoteObject> remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        DHLOGE("Read param failed.");
        return ERR_DH_AUDIO_SA_READ_PARAM_FAILED;
    }

    sptr<DAudioIpcCallbackProxy> dAudioIpcCallbackProxy(new DAudioIpcCallbackProxy(remoteObject));
    int32_t ret = InitSource(param, dAudioIpcCallbackProxy);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::ReleaseSourceInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t ret = ReleaseSource();
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::RegisterDistributedHardwareInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string version = data.ReadString();
    std::string attrs = data.ReadString();
    std::string reqId = data.ReadString();
    EnableParam enableParam;
    enableParam.version = version;
    enableParam.attrs = attrs;

    int32_t ret = RegisterDistributedHardware(networkId, dhId, enableParam, reqId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::UnregisterDistributedHardwareInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string reqId = data.ReadString();

    int32_t ret = UnregisterDistributedHardware(networkId, dhId, reqId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::ConfigDistributedHardwareInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string key = data.ReadString();
    std::string value = data.ReadString();

    int32_t ret = ConfigDistributedHardware(networkId, dhId, key, value);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::DAudioNotifyInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    int32_t eventType = data.ReadInt32();
    std::string eventContent = data.ReadString();

    DAudioNotify(networkId, dhId, eventType, eventContent);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
