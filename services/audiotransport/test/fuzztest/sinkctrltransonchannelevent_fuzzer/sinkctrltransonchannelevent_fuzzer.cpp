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

#include <cstddef>
#include <cstdint>
 
#include "av_trans_message.h"
#include "av_trans_types.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "daudio_sink_ctrl_trans.h"
#include "sinkctrltransonchannelevent_fuzzer.h"
#include "transport/socket.h"
 
#include <dlfcn.h>
 
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

namespace OHOS {
namespace DistributedHardware {
void SinkCtrlTransOnChannelEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string devId = "devId";
    std::string sessionName = "sessionName";
    std::string peerSessName = "peerSessName";
    auto sinkCtrlTransCb = std::make_shared<SinkCtrlTransOnChannelEventFuzzer>();
    auto ctrlTrans = DaudioSinkCtrlTrans(devId, sessionName, peerSessName, sinkCtrlTransCb);
    FuzzedDataProvider fdp(data, size);
    AVTransEvent event;
    event.content = fdp.ConsumeRandomLengthString();
    event.peerDevId = fdp.ConsumeRandomLengthString();
    event.type = static_cast<EventType>(fdp.ConsumeIntegral<uint32_t>());
    ctrlTrans.OnChannelEvent(event);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SinkCtrlTransOnChannelEventFuzzTest(data, size);
    return 0;
}

