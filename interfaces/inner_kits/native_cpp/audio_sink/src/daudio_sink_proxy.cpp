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

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSinkInterfaceCode::STOP_DISTRIBUTED_HARDWARE),
        data, reply, option);
    return reply.ReadInt32();
}
} // namespace DistributedHardware
} // namespace OHOS