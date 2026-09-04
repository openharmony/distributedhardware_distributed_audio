/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "sinkstubconfigdistributedhardware_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "daudio_ipc_interface_code.h"
#include "daudio_sink_service.h"
#include "daudio_sink_stub.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void SinkStubConfigDistributedHardwareFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto svc = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string networkId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string key = fdp.ConsumeRandomLengthString();
    std::string value = fdp.ConsumeRandomLengthString();
    pdata.WriteString(networkId);
    pdata.WriteString(dhId);
    pdata.WriteString(key);
    pdata.WriteString(value);
    uint32_t code = static_cast<uint32_t>(IDAudioSinkInterfaceCode::CONFIG_DISTRIBUTED_HARDWARE);
    svc->OnRemoteRequest(code, pdata, reply, option);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DistributedHardware::SinkStubConfigDistributedHardwareFuzzTest(data, size);
    return 0;
}
