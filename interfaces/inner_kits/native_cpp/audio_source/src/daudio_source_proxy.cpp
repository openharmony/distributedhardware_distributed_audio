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

#include "daudio_source_proxy.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceProxy"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioSourceProxy::InitSource(const std::string &params, const sptr<IDAudioIpcCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(params) || !data.WriteRemoteObject(callback->AsObject())) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::INIT_SOURCE), data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSourceProxy::ReleaseSource()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::RELEASE_SOURCE), data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSourceProxy::RegisterDistributedHardware(const std::string &devId, const std::string &dhId,
    const EnableParam &param, const std::string &reqId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }
    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN ||
        reqId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteString(param.sinkVersion) ||
        !data.WriteString(param.sinkAttrs) || !data.WriteString(reqId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::REGISTER_DISTRIBUTED_HARDWARE),
        data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSourceProxy::UnregisterDistributedHardware(const std::string &devId, const std::string &dhId,
    const std::string &reqId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }
    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN ||
        reqId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteString(reqId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::UNREGISTER_DISTRIBUTED_HARDWARE),
        data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioSourceProxy::ConfigDistributedHardware(const std::string &devId, const std::string &dhId,
    const std::string &key, const std::string &value)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }
    if (devId.length() > DAUDIO_MAX_DEVICE_ID_LEN || dhId.length() > DAUDIO_MAX_DEVICE_ID_LEN) {
        return ERR_DH_AUDIO_SA_DEVID_ILLEGAL;
    }
    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteString(key) || !data.WriteString(value)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::CONFIG_DISTRIBUTED_HARDWARE),
        data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

void DAudioSourceProxy::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
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

    Remote()->SendRequest(static_cast<uint32_t>(IDAudioSourceInterfaceCode::DAUDIO_NOTIFY),
        data, reply, option);
}
} // namespace DistributedHardware
} // namespace OHOS