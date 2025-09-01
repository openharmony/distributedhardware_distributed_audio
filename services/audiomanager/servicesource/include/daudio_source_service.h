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

#ifndef OHOS_DAUDIO_SOURCE_SERVICE_H
#define OHOS_DAUDIO_SOURCE_SERVICE_H

#include <vector>

#include "ipc_object_stub.h"
#include "system_ability.h"

#include "daudio_hidumper.h"
#include "daudio_source_stub.h"
#include "idaudio_ipc_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSourceService : public SystemAbility, public DAudioSourceStub {
    DECLARE_SYSTEM_ABILITY(DAudioSourceService);

public:
    DAudioSourceService(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate) {};
    ~DAudioSourceService() override = default;

    int32_t InitSource(const std::string &params, const sptr<IDAudioIpcCallback> &callback) override;
    int32_t ReleaseSource() override;
    int32_t RegisterDistributedHardware(const std::string &devId, const std::string &dhId, const EnableParam &param,
        const std::string &reqId) override;
    int32_t UnregisterDistributedHardware(const std::string &devId, const std::string &dhId,
        const std::string &reqId) override;
    int32_t ConfigDistributedHardware(const std::string &devId, const std::string &dhId, const std::string &key,
        const std::string &value) override;
    void DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
        const std::string &eventContent) override;
    int Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    int32_t UpdateDistributedHardwareWorkMode(const std::string &devId, const std::string &dhId,
        const WorkModeParam &param) override;

protected:
    void OnStart() override;
    void OnStop() override;
    DISALLOW_COPY_AND_MOVE(DAudioSourceService);

private:
    bool Init();

private:
    bool isServiceStarted_ = false;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SOURCE_SERVICE_H
