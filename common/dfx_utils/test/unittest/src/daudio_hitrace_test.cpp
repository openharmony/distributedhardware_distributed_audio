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

#include "daudio_hitrace_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioHitraceTest::SetUpTestCase(void) {}

void DAudioHitraceTest::TearDownTestCase(void) {}

void DAudioHitraceTest::SetUp()
{
    hitrace_ = std::make_shared<DAudioHitrace>("value", false, false);
    hitrace_ = std::make_shared<DAudioHitrace>("value", true, false);
}

void DAudioHitraceTest::TearDown()
{
    hitrace_ = nullptr;
}

/**
 * @tc.name: End_001
 * @tc.desc: Verify the End function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioHitraceTest, End_001, TestSize.Level1)
{
    std::string result = "123";
    hitrace_->isFinished_ = false;
    hitrace_->End();
    hitrace_->isShowLog_ = false;
    hitrace_->End();
    hitrace_->isFinished_ = true;
    hitrace_->End();
}
} // DistributedHardware
} // OHOS
