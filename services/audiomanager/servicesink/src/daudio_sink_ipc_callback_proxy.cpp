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

#include "daudio_sink_ipc_callback_proxy.h"

#include "daudio_errorcode.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkIpcCallbackProxy"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioSinkIpcCallbackProxy::OnNotifyResourceInfo(const ResourceEventType &type, const std::string &subType,
    const std::string &networkId, bool &isSensitive, bool &isSameAccount)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_DH_AUDIO_SA_WRITE_INTERFACE_TOKEN_FAILED;
    }

    int32_t resType = static_cast<int32_t>(type);
    if (!data.WriteInt32(resType) || !data.WriteString(subType) || !data.WriteString(networkId)) {
        return ERR_DH_AUDIO_SA_WRITE_PARAM_FAIED;
    }

    Remote()->SendRequest(NOTIFY_RESOURCEINFO, data, reply, option);
    int32_t ret = reply.ReadInt32();
    isSensitive = reply.ReadBool();
    isSameAccount = reply.ReadBool();
    return ret;
}
} // namespace DistributedHardware
} // namespace OHOS