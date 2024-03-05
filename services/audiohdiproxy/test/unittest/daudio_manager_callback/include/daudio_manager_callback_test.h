/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_MANAGER_CALLBACK_TEST_H
#define OHOS_DAUDIO_MANAGER_CALLBACK_TEST_H

#include <gtest/gtest.h>

#include "audio_test_utils.h"
#include "daudio_constants.h"
#define private public
#include "daudio_manager_callback.h"
#undef private

namespace OHOS {
namespace DistributedHardware {
class DAudioManagerCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::string adpName_;
    int32_t devId_ = PIN_OUT_DAUDIO_DEFAULT;
    int32_t streamId_ = 0;

    std::shared_ptr<IDAudioHdiCallback> hdiCallback_ = nullptr;
    std::shared_ptr<DAudioManagerCallback> manCallback_ = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_MANAGER_CALLBACK_TEST_H
