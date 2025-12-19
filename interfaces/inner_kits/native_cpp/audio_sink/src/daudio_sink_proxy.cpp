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

#include "daudio_sink_proxy.h"

#include "anonymous_string.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkProxy"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioSinkProxy::InitSink(const std::string &params, const sptr<IDAudioSinkIpcCallback> &sinkCallback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (Remote() == nullptr || sinkCallback == nullptr) {
        DHLOGE("remote service or sinkCallback is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    if (!data.WriteString(params) || !data.WriteRemoteObject(sinkCallback->AsObject())) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::INIT_SINK), data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSinkProxy::ReleaseSink()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::RELEASE_SINK), data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSinkProxy::SubscribeLocalHardware(const std::string &dhId, const std::string &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }
    if (dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    if (!data.WriteString(dhId) || !data.WriteString(param)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::SUBSCRIBE_LOCAL_HARDWARE),
        data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSinkProxy::UnsubscribeLocalHardware(const std::string &dhId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }
    if (dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    if (!data.WriteString(dhId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::UNSUBSCRIBE_LOCAL_HARDWARE),
        data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

void DAudioSinkProxy::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return;
    }
    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return;
    }
    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteInt32(eventType) ||
        !data.WriteString(eventContent)) {
        return;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::DAUDIO_NOTIFY), data, reply, option);
}

int32_t DAudioSinkProxy::PauseDistributedHardware(const std::string &networkId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(networkId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::PAUSE_DISTRIBUTED_HARDWARE),
        data, reply, option);
    return reply.ReadInt32();
}

int32_t DAudioSinkProxy::ResumeDistributedHardware(const std::string &networkId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(networkId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::RESUME_DISTRIBUTED_HARDWARE),
        data, reply, option);
    return reply.ReadInt32();
}

int32_t DAudioSinkProxy::StopDistributedHardware(const std::string &networkId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(networkId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    if (Remote() == nullptr) {
        DHLOGE("remote service is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::STOP_DISTRIBUTED_HARDWARE),
        data, reply, option);
    return reply.ReadInt32();
}

int32_t DAudioSinkProxy::SetAccessListener(const sptr<IAccessListener> &listener, int32_t timeOut,
    const std::string &pkgName)
{
    DHLOGI("SetAccessListener");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_AND_RETURN_RET_LOG(!data.WriteInterfaceToken(GetDescriptor()), ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED,
        "write token failed.");
    CHECK_AND_RETURN_RET_LOG(listener == nullptr, ERR_DH_AUDIO_NULLPTR, "listener is null.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteRemoteObject(listener->AsObject()), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED,
        "write listener failed.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteInt32(timeOut), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED, "write timeOut failed.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteString(pkgName), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED, "write pkgName failed.");
    CHECK_AND_RETURN_RET_LOG(Remote() == nullptr, ERR_DH_AUDIO_NULLPTR, "remote service is null.");

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::SET_ACCESS_LISTENER),
        data, reply, option);
    return reply.ReadInt32();
}

int32_t DAudioSinkProxy::RemoveAccessListener(const std::string &pkgName)
{
    DHLOGI("RemoveAccessListener");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_AND_RETURN_RET_LOG(!data.WriteInterfaceToken(GetDescriptor()), ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED,
        "write token failed.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteString(pkgName), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED, "write pkgName failed.");
    CHECK_AND_RETURN_RET_LOG(Remote() == nullptr, ERR_DH_AUDIO_NULLPTR, "remote service is null.");

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::REMOVE_ACCESS_LISTENER),
        data, reply, option);
    return reply.ReadInt32();
}

int32_t DAudioSinkProxy::SetAuthorizationResult(const std::string &requestId, bool granted)
{
    DHLOGI("SetAuthorizationResult, requestId: %{public}s, granted: %{public}d",
        GetAnonyString(requestId).c_str(), granted);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_AND_RETURN_RET_LOG(!data.WriteInterfaceToken(GetDescriptor()), ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED,
        "write token failed.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteString(requestId), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED,
        "write requestId failed.");
    CHECK_AND_RETURN_RET_LOG(!data.WriteBool(granted), ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED, "write granted failed.");
    CHECK_AND_RETURN_RET_LOG(Remote() == nullptr, ERR_DH_AUDIO_NULLPTR, "remote service is null.");

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::SET_AUTHORIZATION_RESULT),
        data, reply, option);
    return reply.ReadInt32();
}
} // namespace DistributedHardware
} // namespace OHOS