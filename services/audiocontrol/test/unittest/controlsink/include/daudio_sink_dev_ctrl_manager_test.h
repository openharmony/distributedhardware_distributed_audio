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

#ifndef OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_TEST_H
#define OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_TEST_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "audio_event.h"
#include "daudio_errorcode.h"
#include "iaudio_event_callback.h"
#define private public
#include "daudio_sink_dev_ctrl_mgr.h"
#undef private

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkDevCtrlMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<DAudioSinkDevCtrlMgr> sinkDevCtrl_ = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_TEST_H
