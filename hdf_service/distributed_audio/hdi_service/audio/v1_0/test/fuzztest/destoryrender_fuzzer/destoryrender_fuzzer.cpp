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

#include "destoryrender_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "audio_adapter_interface_impl.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
void DestoryRenderFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    AudioAdapterDescriptorHAL desc;
    auto audioAdapter = std::make_shared<AudioAdapterInterfaceImpl>(desc);

    uint32_t portId = *(reinterpret_cast<const uint32_t*>(data));
    uint32_t pins = *(reinterpret_cast<const uint32_t*>(data));
    std::string tdesc(reinterpret_cast<const char*>(data), size);
    AudioDeviceDescriptorHAL deviceDes;
    deviceDes.portId = portId;
    deviceDes.pins = pins;
    deviceDes.desc = tdesc;

    audioAdapter->DestoryRender(deviceDes);
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::DistributedAudio::Audio::V1_0::DestoryRenderFuzzTest(data, size);
    return 0;
}

