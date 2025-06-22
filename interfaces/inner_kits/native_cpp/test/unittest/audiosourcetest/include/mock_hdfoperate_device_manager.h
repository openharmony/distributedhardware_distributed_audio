/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_MOCK_HDFOPRATE_DEVICE_MANAGER_H
#define OHOS_DISTRIBUTED_HARDWARE_MOCK_HDFOPRATE_DEVICE_MANAGER_H

#include <gmock/gmock.h>

#include "idevmgr_hdi.h"

namespace OHOS {
namespace DistributedHardware {
using namespace HDI::DeviceManager::V1_0;
class MockDeviceManager : public IDeviceManager  {
public:
    MOCK_METHOD(int32_t, LoadDevice, (const std::string &));
    MOCK_METHOD(int32_t, UnloadDevice, (const std::string &));
    MOCK_METHOD(int32_t, ListAllDevice, (std::vector<HdiDevHostInfo> &));
    MOCK_METHOD(int32_t, ListAllHost, (std::vector<int> &));
    static sptr<MockDeviceManager> GetOrCreateInstance();
    static void ReleaseInstance();
private:
    static sptr<MockDeviceManager> deviceManagerInstance_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_HARDWARE_MOCK_DEVICE_MANAGER_H