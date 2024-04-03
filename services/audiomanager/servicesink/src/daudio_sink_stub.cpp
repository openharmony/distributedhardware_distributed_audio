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

#include "daudio_sink_stub.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_log.h"
#include "daudio_sink_ipc_callback_proxy.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkStub"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkStub::DAudioSinkStub() : IRemoteStub(true)
{
    DHLOGD("Distributed audio sink stub constructed.");
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::INIT_SINK)] =
        &DAudioSinkStub::InitSinkInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::RELEASE_SINK)] =
        &DAudioSinkStub::ReleaseSinkInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::SUBSCRIBE_LOCAL_HARDWARE)] =
        &DAudioSinkStub::SubscribeLocalHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::UNSUBSCRIBE_LOCAL_HARDWARE)] =
        &DAudioSinkStub::UnsubscribeLocalHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::DAUDIO_NOTIFY)] =
        &DAudioSinkStub::DAudioNotifyInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::PAUSE_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::PauseDistributedHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::RESUME_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::ResumeDistributedHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::STOP_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::StopDistributedHardwareInner;
}

DAudioSinkStub::~DAudioSinkStub()
{
    DHLOGD("Distributed audio sink stub deconstructed.");
}

int32_t DAudioSinkStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHLOGD("On remote request, code: %{public}d.", code);
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

bool DAudioSinkStub::VerifyPermission()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, AUDIO_PERMISSION_NAME);
    if (result == Security::AccessToken::PERMISSION_GRANTED) {
        return true;
    }
    return false;
}

int32_t DAudioSinkStub::InitSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
    std::string param = data.ReadString();
    sptr<IRemoteObject> remoteObject = data.ReadRemoteObject();
    CHECK_NULL_RETURN(remoteObject, ERR_DH_AUDIO_NULLPTR);
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    int32_t ret = InitSink(param, dAudioSinkIpcCallbackProxy);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::ReleaseSinkInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
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

int32_t DAudioSinkStub::PauseDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!HasAccessDHPermission()) {
        DHLOGE("The caller has no ACCESS_DISTRIBUTED_HARDWARE permission.");
        return ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL;
    }
    std::string networkId = data.ReadString();
    int32_t ret = PauseDistributedHardware(networkId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::ResumeDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!HasAccessDHPermission()) {
        DHLOGE("The caller has no ACCESS_DISTRIBUTED_HARDWARE permission.");
        return ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL;
    }
    std::string networkId = data.ReadString();
    int32_t ret = ResumeDistributedHardware(networkId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSinkStub::StopDistributedHardwareInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!HasAccessDHPermission()) {
        DHLOGE("The caller has no ACCESS_DISTRIBUTED_HARDWARE permission.");
        return ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL;
    }
    std::string networkId = data.ReadString();
    int32_t ret = StopDistributedHardware(networkId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

bool DAudioSinkStub::HasAccessDHPermission()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    const std::string permissionName = "ohos.permission.ACCESS_DISTRIBUTED_HARDWARE";
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    return (result == Security::AccessToken::PERMISSION_GRANTED);
}
} // namespace DistributedHardware
} // namespace OHOS