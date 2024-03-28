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

#ifndef OHOS_DAUDIO_MOCK_COMPONENT_ENABLE_H
#define OHOS_DAUDIO_MOCK_COMPONENT_ENABLE_H

#include "daudio_errorcode.h"
#include "idistributed_hardware_source.h"

namespace OHOS {
namespace DistributedHardware {
class MockComponentEnable : public std::enable_shared_from_this<MockComponentEnable>, public RegisterCallback {
public:
    explicit MockComponentEnable()
    {
    }

    virtual ~MockComponentEnable()
    {
    }

    int32_t Enable(const std::string &uuid, const std::string &dhId, const EnableParam &param,
        IDistributedHardwareSource *handler)
    {
        return DH_SUCCESS;
    }

    int32_t OnRegisterResult(const std::string &uuid, const std::string &dhId, int32_t status,
        const std::string &data) override
    {
        return DH_SUCCESS;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
