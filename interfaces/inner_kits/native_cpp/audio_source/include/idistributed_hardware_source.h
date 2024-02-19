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

#ifndef OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SOURCE_H
#define OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SOURCE_H

#include <memory>
#include <string>

namespace OHOS {
namespace DistributedHardware {
const std::string COMPONENT_LOADER_GET_SOURCE_HANDLER = "GetSourceHardwareHandler";
class RegisterCallback {
public:
    virtual int32_t OnRegisterResult(const std::string &uuid, const std::string &dhId, int32_t status,
        const std::string &data) = 0;
};

class UnregisterCallback {
public:
    virtual int32_t OnUnregisterResult(const std::string &uuid, const std::string &dhId, int32_t status,
        const std::string &data) = 0;
};

struct EnableParam {
    std::string sourceVersion;
    std::string sourceAttrs;
    std::string sinkVersion;
    std::string sinkAttrs;
    std::string subtype;
};

class IDistributedHardwareSource {
public:
    virtual int32_t InitSource(const std::string &params) = 0;
    virtual int32_t ReleaseSource() = 0;
    virtual int32_t RegisterDistributedHardware(const std::string &uuid, const std::string &dhId,
        const EnableParam &param, std::shared_ptr<RegisterCallback> callback) = 0;
    virtual int32_t UnregisterDistributedHardware(const std::string &uuid, const std::string &dhId,
        std::shared_ptr<UnregisterCallback> callback) = 0;
    virtual int32_t ConfigDistributedHardware(const std::string &uuid, const std::string &dhId, const std::string &key,
        const std::string &value) = 0;
};
extern "C" __attribute__((visibility("default"))) IDistributedHardwareSource* GetSourceHardwareHandler();
} // namespace DistributedHardware
} // namespace OHOS
#endif
