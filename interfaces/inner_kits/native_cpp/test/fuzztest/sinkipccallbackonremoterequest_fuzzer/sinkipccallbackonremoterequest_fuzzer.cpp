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

#include "sinkipccallbackonremoterequest_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_sink_ipc_callback.h"
#include "daudio_sink_ipc_callback_stub.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedHardware {
const uint32_t DC_RESOURCE_VALUE = 2;
const uint32_t DC_RESOURCE_SIZE = 3;
const ResourceEventType resourceEventType[DC_RESOURCE_SIZE] {
    ResourceEventType::EVENT_TYPE_QUERY_RESOURCE,
    ResourceEventType::EVENT_TYPE_PULL_UP_PAGE,
    ResourceEventType::EVENT_TYPE_CLOSE_PAGE
};

void SinkIpcCallbackOnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    int32_t resType = static_cast<int32_t>(resourceEventType[data[0] % DC_RESOURCE_SIZE]);
    std::string subtype(reinterpret_cast<const char*>(data), size);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    bool isSensitive = data[0] % DC_RESOURCE_VALUE;
    bool isSameAccout = data[0] % DC_RESOURCE_VALUE;
    pdata.WriteInt32(resType);
    pdata.WriteString(subtype);
    pdata.WriteString(networkId);
    pdata.ReadBool(isSensitive);
    pdata.ReadBool(isSameAccout);
    std::shared_ptr<DAudioSinkIpcCallback> callback = std::make_shared<DAudioSinkIpcCallback>();
    callback->memberFuncMap_[code] = &DAudioSinkIpcCallbackStub::OnNotifyResourceInfoInner;

    callback->OnRemoteRequest(code, pdata, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkIpcCallbackOnRemoteRequestFuzzTest(data, size);
    return 0;
}

