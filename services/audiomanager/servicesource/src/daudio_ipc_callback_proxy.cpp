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

#include "daudio_ipc_callback_proxy.h"

#include "daudio_errorcode.h"
#include "daudio_ipc_interface_code.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioIpcCallbackProxy"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioIpcCallbackProxy::OnNotifyRegResult(const std::string &devId, const std::string &dhId,
    const std::string &reqId, int32_t status, const std::string &resultData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteString(reqId) || !data.WriteInt32(status) ||
        !data.WriteString(resultData)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(NOTIFY_REGRESULT, data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}

int32_t DAudioIpcCallbackProxy::OnNotifyUnregResult(const std::string &devId, const std::string &dhId,
    const std::string &reqId, int32_t status, const std::string &resultData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    if (!data.WriteString(devId) || !data.WriteString(dhId) || !data.WriteString(reqId) || !data.WriteInt32(status) ||
        !data.WriteString(resultData)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(static_cast<uint32_t>(NOTIFY_UNREGRESULT), data, reply, option);
    int32_t ret = reply.ReadInt32();
    return ret;
}
} // namespace DistributedHardware
} // namespace OHOS