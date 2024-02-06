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

#include "sinkhandlerregisterprivacyresources_fuzzer.h"

#include "daudio_sink_handler.h"
#include "mock_component_resourceinfo.h"

namespace OHOS {
namespace DistributedHardware {
void SinkHandlerRegisterPrivacyResourcesFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    std::shared_ptr<PrivacyResourcesListener> listener = std::make_shared<MockComponentResourceInfo>();
    DAudioSinkHandler::GetInstance().RegisterPrivacyResources(listener);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkHandlerRegisterPrivacyResourcesFuzzTest(data, size);
    return 0;
}

