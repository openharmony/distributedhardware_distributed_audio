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

#ifndef OHOS_DAUDIO_SINK_SERVICE_H
#define OHOS_DAUDIO_SINK_SERVICE_H

#include "system_ability.h"
#include "ipc_object_stub.h"

#include "daudio_sink_hidumper.h"
#include "daudio_sink_stub.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkService : public SystemAbility, public DAudioSinkStub {
DECLARE_SYSTEM_ABILITY(DAudioSinkService);

public:
    DAudioSinkService(int32_t saId, bool runOnCreate);
    ~DAudioSinkService() override = default;

    int32_t InitSink(const std::string &params, const sptr<IDAudioSinkIpcCallback> &sinkCallback) override;
    int32_t ReleaseSink() override;
    int32_t SubscribeLocalHardware(const std::string &dhId, const std::string &param) override;
    int32_t UnsubscribeLocalHardware(const std::string &dhId) override;
    void DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
        const std::string &eventContent) override;
    int Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    int32_t PauseDistributedHardware(const std::string &networkId) override;
    int32_t ResumeDistributedHardware(const std::string &networkId) override;
    int32_t StopDistributedHardware(const std::string &networkId) override;

protected:
    void OnStart() override;
    void OnStop() override;
    DISALLOW_COPY_AND_MOVE(DAudioSinkService);

private:
    bool Init();

private:
    bool isServiceStarted_ = false;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_SERVICE_H