/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "sinkserviceinitsink_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_sink_service.h"
#include "daudio_sink_ipc_callback.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void SinkServiceInitSinkFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    int32_t saId = *(reinterpret_cast<const int32_t*>(data));
    std::string params(reinterpret_cast<const char*>(data), size);
    bool runOnCreate = *(reinterpret_cast<const bool*>(data));
    
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    sptr<DAudioSinkIpcCallback> dAudioSinkIpcCallback(new DAudioSinkIpcCallback());

    dAudioSinkService->InitSink(params, dAudioSinkIpcCallback);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkServiceInitSinkFuzzTest(data, size);
    return 0;
}

