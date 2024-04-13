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

#include "sinkstubonremoterequest_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <random>

#include "daudio_sink_stub.h"
#include "daudio_sink_service.h"

#include "daudio_ipc_interface_code.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
const uint32_t RANGE = 8;
void SinkStubOnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    int32_t saId = *(reinterpret_cast<const int32_t*>(data));
    bool runOnCreate = *(reinterpret_cast<const bool*>(data));
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    std::string resultData(reinterpret_cast<const char*>(data), size);
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::INIT_SINK)] =
        &DAudioSinkStub::InitSinkInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::RELEASE_SINK)] =
        &DAudioSinkStub::ReleaseSinkInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::SUBSCRIBE_LOCAL_HARDWARE)] =
        &DAudioSinkStub::SubscribeLocalHardwareInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::UNSUBSCRIBE_LOCAL_HARDWARE)] =
        &DAudioSinkStub::UnsubscribeLocalHardwareInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::DAUDIO_NOTIFY)] =
        &DAudioSinkStub::DAudioNotifyInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::PAUSE_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::PauseDistributedHardwareInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::RESUME_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::ResumeDistributedHardwareInner;
    dAudioSinkService->memberFuncMap_[static_cast<uint32_t>(IDAudioSinkInterfaceCode::STOP_DISTRIBUTED_HARDWARE)] =
        &DAudioSinkStub::StopDistributedHardwareInner;
    const uint32_t code = rd() % RANGE;
    dAudioSinkService->OnRemoteRequest(code, pdata, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkStubOnRemoteRequestFuzzTest(data, size);
    return 0;
}

