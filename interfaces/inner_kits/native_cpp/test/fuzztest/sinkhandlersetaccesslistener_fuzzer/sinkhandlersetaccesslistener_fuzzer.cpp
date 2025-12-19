/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sinkhandlersetaccesslistener_fuzzer.h"

#include "daudio_sink_handler.h"
#include "mock_access_listener.h"

namespace OHOS {
namespace DistributedHardware {
void SinkHandlerSetAccessListenerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    sptr<IAccessListener> listener(new TestAccessListener());
    std::string pkgName(reinterpret_cast<const char*>(data), size);
    int32_t timeOut = *(reinterpret_cast<const int32_t*>(data));
    DAudioSinkHandler::GetInstance().SetAccessListener(listener, timeOut, pkgName);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkHandlerSetAccessListenerFuzzTest(data, size);
    return 0;
}
