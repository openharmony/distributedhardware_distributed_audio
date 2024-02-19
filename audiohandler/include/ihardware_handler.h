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

#ifndef OHOS_DISTRIBUTED_HARDWARE_IHARDWARE_HANDLER_H
#define OHOS_DISTRIBUTED_HARDWARE_IHARDWARE_HANDLER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {
const std::string COMPONENT_LOADER_GET_HARDWARE_HANDLER = "GetHardwareHandler";
struct DHItem {
    std::string dhId;
    std::string attrs;
    std::string subtype;
};

class PluginListener {
public:
    virtual void PluginHardware(const std::string &dhId, const std::string &attrs, const std::string &subtype) = 0;
    virtual void UnPluginHardware(const std::string &dhId) = 0;
};

class IHardwareHandler {
public:
    virtual int32_t Initialize() = 0;
    virtual std::vector<DHItem> Query() = 0;
    virtual std::map<std::string, std::string> QueryExtraInfo() = 0;
    virtual bool IsSupportPlugin() = 0;
    virtual void RegisterPluginListener(std::shared_ptr<PluginListener> listener) = 0;
    virtual void UnRegisterPluginListener() = 0;
};
extern "C" __attribute__((visibility("default"))) IHardwareHandler* GetHardwareHandler();
} // namespace DistributedHardware
} // namespace OHOS
#endif
