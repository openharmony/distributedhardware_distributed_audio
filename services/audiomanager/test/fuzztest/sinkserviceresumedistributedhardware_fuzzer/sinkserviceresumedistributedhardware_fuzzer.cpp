/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "sinkserviceresumedistributedhardware_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_sink_service.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void SinkServiceResumeDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || size < (sizeof(int32_t))) {
        return;
    }
    std::string networkId(reinterpret_cast<const char*>(data), size);
    int32_t saId = *(reinterpret_cast<const int32_t*>(data));
    bool runOnCreate = *(reinterpret_cast<const bool*>(data));
    
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);

    dAudioSinkService->ResumeDistributedHardware(networkId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkServiceResumeDistributedHardwareFuzzTest(data, size);
    return 0;
}

