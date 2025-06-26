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

#include "sinkservicedump_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "daudio_sink_service.h"
#include "daudio_sink_ipc_callback.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void SinkServiceDumpFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    size_t argsCount = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    std::vector<std::u16string> args;

    for (size_t i = 0; i < argsCount; ++i) {
        std::string utf8Str =  fdp.ConsumeRandomLengthString(100);
        std::u16string utf16Str(utf8Str.begin(), utf8Str.end());
        args.emplace_back(utf16Str);
    }

    auto dAudioSinkService = std::make_shared<DAudioSinkService>(fd, true);
    dAudioSinkService->Dump(fd, args);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkServiceDumpFuzzTest(data, size);
    return 0;
}

