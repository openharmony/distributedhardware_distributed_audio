/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sourcehandlerregisterdistributedhardware_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_source_handler.h"
#include "daudio_constants.h"
#include "mock_component_enable.h"

namespace OHOS {
namespace DistributedHardware {
void SourceHandlerRegisterDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    std::string devId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    std::string version(reinterpret_cast<const char*>(data), size);
    std::string attrs(reinterpret_cast<const char*>(data), size);
    EnableParam param;
    param.sinkVersion = version;
    param.sinkAttrs = attrs;
    std::shared_ptr<RegisterCallback> callback = std::make_shared<MockComponentEnable>();

    DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SourceHandlerRegisterDistributedHardwareFuzzTest(data, size);
    return 0;
}

