/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#include "audio_data_test.h"
#undef private

#include "daudio_constants.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioLatencyUnitTest::SetUpTestCase(void) {}

void DAudioLatencyUnitTest::TearDownTestCase(void) {}

void DAudioLatencyUnitTest::SetUp(void) {}

void DAudioLatencyUnitTest::TearDown(void) {}

/**
 * @tc.name: AddPlayRecordTime_001
 * @tc.desc: Verify the AddPlayTime & Add RecordTime function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioLatencyUnitTest, AddPlayRecordTime_001, TestSize.Level1)
{
    int64_t t = DAudioLatencyTest::GetInstance()->GetNowTimeUs();
    int ret = DAudioLatencyTest::GetInstance()->AddPlayTime(t);
    EXPECT_EQ(0, ret);
    t = DAudioLatencyTest::GetInstance()->GetNowTimeUs();
    ret = DAudioLatencyTest::GetInstance()->AddRecordTime(t);
    EXPECT_EQ(0, ret);
    int latency = DAudioLatencyTest::GetInstance()->ComputeLatency();
    EXPECT_LE(0, latency);
}
} // namespace DistributedHardware
} // namespace OHOS
