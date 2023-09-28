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

#include "sourceproxyregisterdistributedhardware_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_constants.h"
#include "daudio_source_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void SourceProxyRegisterDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    std::string dhId(reinterpret_cast<const char*>(data), size);
    std::string devId(reinterpret_cast<const char*>(data), size);
    std::string reqId(reinterpret_cast<const char*>(data), size);
    std::string version(reinterpret_cast<const char*>(data), size);
    std::string attrs(reinterpret_cast<const char*>(data), size);
    EnableParam param;
    param.sinkVersion = version;
    param.sinkAttrs = attrs;

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    std::shared_ptr<DAudioSourceProxy> dAudioProxy = std::make_shared<DAudioSourceProxy>(remoteObject);

    dAudioProxy->RegisterDistributedHardware(devId, dhId, param, reqId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SourceProxyRegisterDistributedHardwareFuzzTest(data, size);
    return 0;
}

