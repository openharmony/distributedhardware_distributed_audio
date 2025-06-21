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

#include "sinkstubdaudiosinkstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <random>
#include <fuzzer/FuzzedDataProvider.h>

#include "daudio_sink_ipc_callback_proxy.h"
#include "daudio_sink_stub.h"
#include "daudio_sink_service.h"

#include "daudio_ipc_interface_code.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

inline std::string ConsumeRandomString(FuzzedDataProvider& fdp, size_t maxLength)
{
    return fdp.ConsumeRandomLengthString(maxLength);
}
namespace OHOS {
namespace DistributedHardware {
void SinkStubDaudioSinkStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
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
    const uint32_t code = fdp.ConsumeIntegral<const uint32_t>();
    dAudioSinkService->OnRemoteRequest(code, pdata, reply, option);
}

void SinkStubSubscribeLocalHardwareInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->SubscribeLocalHardwareInner(pdata, reply, option);
}

void SinkStubUnsubscribeLocalHardwareInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->UnsubscribeLocalHardwareInner(pdata, reply, option);
}

void SinkStubDAudioNotifyInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->DAudioNotifyInner(pdata, reply, option);
}

void SinkStubPauseDistributedHardwareInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->PauseDistributedHardwareInner(pdata, reply, option);
}

void SinkStubResumeDistributedHardwareInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->ResumeDistributedHardwareInner(pdata, reply, option);
}

void SinkStubStopDistributedHardwareInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);
    std::random_device rd;
    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    std::string devId = "1";
    std::string dhId = "2";
    std::string reqId = "3";
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    std::string resultData = fdp.ConsumeRandomLengthString();
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteInt32(status);
    pdata.WriteString(resultData);
    dAudioSinkService->StopDistributedHardwareInner(pdata, reply, option);
}

void SinkStubInitSinkInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);

    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;

    std::string param = fdp.ConsumeRandomLengthString(100);
    sptr<IRemoteObject> remoteObject = nullptr;
    pdata.WriteString(param);
    pdata.WriteRemoteObject(remoteObject);
    dAudioSinkService->InitSinkInner(pdata, reply, option);
}

void SinkStubReleaseSinkInnerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    int32_t saId = fdp.ConsumeIntegral<int32_t>();
    bool runOnCreate = fdp.ConsumeBool();
    auto dAudioSinkService = std::make_shared<DAudioSinkService>(saId, runOnCreate);

    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;

    std::string dummyData = ConsumeRandomString(fdp, 100);
    pdata.WriteString(dummyData);

    dAudioSinkService->ReleaseSinkInner(pdata, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkStubDaudioSinkStubFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubSubscribeLocalHardwareInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubUnsubscribeLocalHardwareInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubDAudioNotifyInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubPauseDistributedHardwareInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubResumeDistributedHardwareInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubStopDistributedHardwareInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubInitSinkInnerFuzzTest(data, size);
    OHOS::DistributedHardware::SinkStubReleaseSinkInnerFuzzTest(data, size);
    return 0;
}
