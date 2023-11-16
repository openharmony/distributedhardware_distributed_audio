/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_IDAUDIO_SINK_H
#define OHOS_IDAUDIO_SINK_H

#include "idaudio_sink_ipc_callback.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedHardware {
class IDAudioSink : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.distributedhardware.distributedaudiosink");

    ~IDAudioSink() override = default;
    virtual int32_t InitSink(const std::string &params, const sptr<IDAudioSinkIpcCallback> &sinkCallback) = 0;
    virtual int32_t ReleaseSink() = 0;
    virtual int32_t SubscribeLocalHardware(const std::string &dhId, const std::string &param) = 0;
    virtual int32_t UnsubscribeLocalHardware(const std::string &dhId) = 0;
    virtual void DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
        const std::string &eventContent) = 0;
    virtual int32_t PauseDistributedHardware(const std::string &networkId) = 0;
    virtual int32_t ResumeDistributedHardware(const std::string &networkId) = 0;
    virtual int32_t StopDistributedHardware(const std::string &networkId) = 0;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_IDAUDIO_SINK_H