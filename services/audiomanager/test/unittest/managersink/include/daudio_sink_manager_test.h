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

#ifndef OHOS_DAUDIO_SINK_MANAGER_TEST_H
#define OHOS_DAUDIO_SINK_MANAGER_TEST_H

#include <gtest/gtest.h>

#define private public
#include "daudio_sink_manager.h"
#undef private
#include "iaccess_listener.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    DAudioSinkManager daudioSinkManager;
    sptr<IRemoteObject> remoteObject_ = nullptr;

    class TestAccessListener : public IAccessListener {
        sptr<IRemoteObject> AsObject()
        {
            return nullptr;
        }

        void OnRequestHardwareAccess(const std::string &requestId, AuthDeviceInfo info, const DHType dhType,
            const std::string &pkgName)
        {
            (void)requestId;
            (void)info;
            (void)dhType;
            (void)pkgName;
        }
    };
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SINK_DEV_TEST_H