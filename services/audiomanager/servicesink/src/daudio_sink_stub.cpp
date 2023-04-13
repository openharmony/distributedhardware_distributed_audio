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

#include "daudio_sink_stub.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkStub"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkStub::DAudioSinkStub()
{
    DHLOGI("Distributed audio sink stub constructed.");
    memberFuncMap_[INIT_SINK] = &DAudioSinkStub::InitSinkInner;
    memberFuncMap_[RELEASE_SINK] = &DAudioSinkStub::ReleaseSinkInner;
    memberFuncMap_[SUBSCRIBE_LOCAL_HARDWARE] = &DAudioSinkStub::SubscribeLocalHardwareInner;
    memberFuncMap_[UNSUBSCRIBE_LOCAL_HARDWARE] = &DAudioSinkStub::UnsubscribeLocalHardwareInner;
    memberFuncMap_[DAUDIO_NOTIFY] = &DAudioSinkStub::DAudioNotifyInner;
}

DAudioSinkStub::~DAudioSinkStub()
{
    DHLOGI("Distributed audio sink stub deconstructed.");
}

int32_t DAudioSinkStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHLOGI("On remote request, code: %d.", code);
    std::u16string desc = DAudioSinkStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        DHLOGE("RemoteDesc is invalid.");
        return ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN;
    }

    const auto &iter = memberFuncMap_.find(code);
    if (iter == memberFuncMap_.end()) {
        DHLOGE("Invalid request code.");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    DAudioSinkServiceFunc &func = iter->second;
    return (this->*func)(data, reply, option);
}

int32_t DAudioSinkStub::InitSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string param = data.ReadString();
    int32_t ret = InitSink(param);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::ReleaseSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t ret = ReleaseSink();
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::SubscribeLocalHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string dhId = data.ReadString();
    std::string param = data.ReadString();
    int32_t ret = SubscribeLocalHardware(dhId, param);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::UnsubscribeLocalHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string dhId = data.ReadString();
    int32_t ret = UnsubscribeLocalHardware(dhId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::DAudioNotifyInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
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