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

#include "daudio_sink_ipc_callback.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkIpcCallback"

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioSinkIpcCallback::OnNotifyResourceInfo(const ResourceEventType &type, const std::string &subType,
    const std::string &networkId, bool &isSensitive, bool &isSameAccount)
{
    DHLOGI("On notify the resource info, subType: %{public}s, networkId: %{public}s, isSensitive: "
        "%{public}d, isSameAccount: %{public}d", subType.c_str(), GetAnonyString(networkId).c_str(),
        isSensitive, isSameAccount);

    int32_t ret = DH_SUCCESS;
    std::lock_guard<std::mutex> resourceLck(privacyResMtx_);
    auto iter = privacyResCallback_.begin();
    if (iter != privacyResCallback_.end()) {
        ret = (*iter)->OnPrivaceResourceMessage(type, subType, networkId, isSensitive, isSameAccount);
    }
    return ret;
}

void DAudioSinkIpcCallback::PushPrivacyResCallback(const std::shared_ptr<PrivacyResourcesListener> &callback)
{
    DHLOGD("Push resource info callback");
    std::lock_guard<std::mutex> resourceLck(privacyResMtx_);
    privacyResCallback_.push_back(callback);
}
} // DistributedHardware
} // OHOS