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

#include "encoderonoutputchanged_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "audio_encoder.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void EncoderOnOutputChangedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    Media::Format format;
    std::shared_ptr<AudioEncoder> encoder = std::make_shared<AudioEncoder>();
    encoder->OnOutputFormatChanged(format);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::EncoderOnOutputChangedFuzzTest(data, size);
    return 0;
}

