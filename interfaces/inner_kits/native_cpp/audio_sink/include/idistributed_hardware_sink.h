/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SINK_H
#define OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SINK_H

#include <string>

namespace OHOS {
namespace DistributedHardware {
const std::string COMPONENT_LOADER_GET_SINK_HANDLER = "GetSinkHardwareHandler";
enum class ResourceEventType : int32_t {
    EVENT_TYPE_QUERY_RESOURCE = 0,
    EVENT_TYPE_PULL_UP_PAGE = 1,
    EVENT_TYPE_CLOSE_PAGE = 2
};

class SubscribeCallback {
public:
    virtual int32_t OnSubscribeCallback(const std::string &dhId, int32_t status, const std::string &data) = 0;
};

class PrivacyResourcesListener {
public:
    virtual int32_t OnPrivaceResourceMessage(const ResourceEventType &type, const std::string &subType,
        const std::string &networkId, bool &isSensitive, bool &isSameAccout) = 0;
};

class IDistributedHardwareSink {
public:
    virtual int32_t InitSink(const std::string &params) = 0;
    virtual int32_t ReleaseSink() = 0;
    virtual int32_t SubscribeLocalHardware(const std::string &dhId, const std::string &params) = 0;
    virtual int32_t UnsubscribeLocalHardware(const std::string &dhId) = 0;
    virtual int32_t RegisterPrivacyResources(std::shared_ptr<PrivacyResourcesListener> listener) = 0;
    virtual int32_t PauseDistributedHardware(const std::string &networkId) = 0;
    virtual int32_t ResumeDistributedHardware(const std::string &networkId) = 0;
    virtual int32_t StopDistributedHardware(const std::string &networkId) = 0;
};
extern "C" __attribute__((visibility("default"))) IDistributedHardwareSink* GetSinkHardwareHandler();
} // namespace DistributedHardware
} // namespace OHOS
#endif
