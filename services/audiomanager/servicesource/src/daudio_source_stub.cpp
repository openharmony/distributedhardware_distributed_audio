/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_callback_proxy.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceStub"

namespace OHOS {
namespace DistributedHardware {
DAudioSourceStub::DAudioSourceStub() : IRemoteStub(true)
{
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::INIT_SOURCE)] =
        &DAudioSourceStub::InitSourceInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::RELEASE_SOURCE)] =
        &DAudioSourceStub::ReleaseSourceInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::REGISTER_DISTRIBUTED_HARDWARE)] =
        &DAudioSourceStub::RegisterDistributedHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::UNREGISTER_DISTRIBUTED_HARDWARE)] =
        &DAudioSourceStub::UnregisterDistributedHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::CONFIG_DISTRIBUTED_HARDWARE)] =
        &DAudioSourceStub::ConfigDistributedHardwareInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::DAUDIO_NOTIFY)] =
        &DAudioSourceStub::DAudioNotifyInner;
    memberFuncMap_[static_cast<uint32_t>(IDAudioSourceInterfaceCode::UPDATE_WORKMODE)] =
        &DAudioSourceStub::UpdateDAudioWorkModeInner;
}

int32_t DAudioSourceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHLOGI("On remote request, code: %{public}d.", code);
    std::u16string desc = DAudioSourceStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        DHLOGE("Remote desc is invalid.");
        return ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN;
    }

    switch (code) {
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::INIT_SOURCE):
            return InitSourceInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::RELEASE_SOURCE):
            return ReleaseSourceInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::REGISTER_DISTRIBUTED_HARDWARE):
            return RegisterDistributedHardwareInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::UNREGISTER_DISTRIBUTED_HARDWARE):
            return UnregisterDistributedHardwareInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::CONFIG_DISTRIBUTED_HARDWARE):
            return ConfigDistributedHardwareInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::DAUDIO_NOTIFY):
            return DAudioNotifyInner(data, reply, option);
        case static_cast<uint32_t>(IDAudioSourceInterfaceCode::UPDATE_WORKMODE):
            return UpdateDAudioWorkModeInner(data, reply, option);
        default:
            DHLOGE("Invalid request code.");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_DH_AUDIO_NOT_FOUND_KEY;
}

bool DAudioSourceStub::VerifyPermission()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, AUDIO_PERMISSION_NAME);
    if (result == Security::AccessToken::PERMISSION_GRANTED) {
        return true;
    }
    return false;
}

int32_t DAudioSourceStub::InitSourceInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
    std::string param = data.ReadString();
    sptr<IRemoteObject> remoteObject = data.ReadRemoteObject();
    CHECK_NULL_RETURN(remoteObject, ERR_DH_AUDIO_NULLPTR);
    sptr<DAudioIpcCallbackProxy> dAudioIpcCallbackProxy(new DAudioIpcCallbackProxy(remoteObject));
    int32_t ret = InitSource(param, dAudioIpcCallbackProxy);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::ReleaseSourceInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
    int32_t ret = ReleaseSource();
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::RegisterDistributedHardwareInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
    std::string networkId = data.ReadString();
    std::string dhId = data.ReadString();
    std::string version = data.ReadString();
    std::string attrs = data.ReadString();
    std::string reqId = data.ReadString();
    EnableParam enableParam;
    enableParam.sinkVersion = version;
    enableParam.sinkAttrs = attrs;

    int32_t ret = RegisterDistributedHardware(networkId, dhId, enableParam, reqId);
    reply.WriteInt32(ret);
    return DH_SUCCESS;
}

int32_t DAudioSourceStub::UnregisterDistributedHardwareInner(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
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
    if (!VerifyPermission()) {
        DHLOGE("Permission verification fail.");
        return ERR_DH_AUDIO_SA_PERMISSION_FAIED;
    }
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

int32_t DAudioSourceStub::UpdateDAudioWorkModeInner(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t ret = 0;
    do {
        CHECK_AND_RETURN_RET_LOG(!VerifyPermission(), ERR_DH_AUDIO_SA_PERMISSION_FAIED,
            "Permission verification fail.");
        std::string devId = data.ReadString();
        std::string dhId = data.ReadString();
        WorkModeParam params(-1, 0, 0, 0);
        params.fd = data.ReadFileDescriptor();
        params.sharedMemLen = data.ReadInt32();
        params.scene = data.ReadUint32();
        params.isAVsync = data.ReadInt32();
        CHECK_AND_RETURN_RET_LOG(devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN
            || params.fd < 0 || params.sharedMemLen < 0, ERR_DH_AUDIO_SA_DEVID_ILLEGAL, "Workmode param is illegal.");
        ret = UpdateDistributedHardwareWorkMode(devId, dhId, params);
        DHLOGI("DistributedAudioSourceStub UpdateDistributedHardwareWorkMode %{public}d", ret);
    } while (0);
    reply.WriteInt32(ret);
    return ret;
}
} // namespace DistributedHardware
} // namespace OHOS
