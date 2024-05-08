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

#include "daudio_hidumper_test.h"
#include "daudio_hitrace.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioHidumperTest::SetUpTestCase(void) {}

void DAudioHidumperTest::TearDownTestCase(void) {}

void DAudioHidumperTest::SetUp()
{
    hidumper_ = std::make_shared<DaudioHidumper>();
}

void DAudioHidumperTest::TearDown()
{
    hidumper_ = nullptr;
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify the OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioHidumperTest, Dump_001, TestSize.Level1)
{
    std::string result;
    std::vector<std::string> args;
    EXPECT_EQ(true, hidumper_->Dump(args, result));
    args = { "-h"};
    EXPECT_EQ(true, hidumper_->Dump(args, result));
    args = {"--sourceDevId"};
    EXPECT_NE(true, hidumper_->Dump(args, result));
    args = {"--sinkInfo"};
    hidumper_->Dump(args, result);
    args = {"--ability"};
    EXPECT_EQ(true, hidumper_->Dump(args, result));
    args = {"-h", "--ability"};
    EXPECT_EQ(true, hidumper_->Dump(args, result));
}

/**
 * @tc.name: GetSourceDevId_001
 * @tc.desc: Verify the GetSourceDevId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioHidumperTest, GetSourceDevId_001, TestSize.Level1)
{
    std::string result = "123";
    EXPECT_NE(HDF_SUCCESS, hidumper_->GetSourceDevId(result));
}

/**
 * @tc.name: GetSinkInfo_001
 * @tc.desc: Verify the GetSinkInfo function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioHidumperTest, GetSinkInfo_001, TestSize.Level1)
{
    std::string result = "123";
    EXPECT_NE(HDF_SUCCESS, hidumper_->GetSinkInfo(result));
}

/**
 * @tc.name: StartDumpData_001
 * @tc.desc: Verify the StartDumpData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHidumperTest, StartDumpData_001, TestSize.Level1)
{
    std::string result = "";
    EXPECT_EQ(HDF_SUCCESS, hidumper_->StartDumpData(result));
    EXPECT_EQ(true, hidumper_->QueryDumpDataFlag());
}
} // DistributedHardware
} // OHOS
