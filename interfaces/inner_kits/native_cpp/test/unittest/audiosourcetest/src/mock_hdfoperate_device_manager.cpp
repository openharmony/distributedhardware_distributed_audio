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

#include "mock_hdfoperate_device_manager.h"

namespace OHOS {
namespace DistributedHardware {
sptr<MockDeviceManager> MockDeviceManager::deviceManagerInstance_;

sptr<MockDeviceManager> MockDeviceManager::GetOrCreateInstance()
{
    if (deviceManagerInstance_ == nullptr) {
        deviceManagerInstance_ = sptr<MockDeviceManager>(new MockDeviceManager());
    }
    return deviceManagerInstance_;
}

void MockDeviceManager::ReleaseInstance()
{
    deviceManagerInstance_ = nullptr;
}
} // namespace DistributedHardware

namespace HDI {
namespace DeviceManager {
namespace V1_0 {
using namespace OHOS::DistributedHardware;

sptr<IDeviceManager> IDeviceManager::Get()
{
    return MockDeviceManager::GetOrCreateInstance();
}
}
}
}
} // namespace OHOS