/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "daudio_handler_test.h"

#include <cstdint>
#include <memory>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioHandlerTest::SetUpTestCase(void) {}

void DAudioHandlerTest::TearDownTestCase(void) {}

void DAudioHandlerTest::SetUp(void) {}

void DAudioHandlerTest::TearDown(void) {}

/**
 * @tc.name: Initialize_001
 * @tc.desc: Verify the Initialize function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHandlerTest, Initialize_001, TestSize.Level0)
{
    int32_t actual = DAudioHandler::GetInstance().Initialize();
    EXPECT_EQ(DH_SUCCESS, actual);
}

/**
 * @tc.name: QueryAudioInfo_001
 * @tc.desc: Verify the QueryAudioInfo function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHandlerTest, QueryAudioInfo_001, TestSize.Level0)
{
    int32_t actual = DAudioHandler::GetInstance().QueryAudioInfo();
    EXPECT_EQ(DH_SUCCESS, actual);
}

/**
 * @tc.name: Query_001
 * @tc.desc: Verify the Query function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHandlerTest, Query_001, TestSize.Level0)
{
    int32_t actual = DAudioHandler::GetInstance().Query().size();
    EXPECT_LE(DH_SUCCESS, actual);
}

/**
 * @tc.name: IsMimeSupported_001
 * @tc.desc: Verify the IsMimeSupported function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHandlerTest, IsMimeSupported_001, TestSize.Level0)
{
    std::string coder = "AAAA";
    bool isSupport = DAudioHandler::GetInstance().IsMimeSupported(coder);
    EXPECT_EQ(false, isSupport);
}

/**
 * @tc.name: AddToVec_001
 * @tc.desc: Verify the AddToVec function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioHandlerTest, AddToVec_001, TestSize.Level0)
{
    std::vector<std::string> container;
    std::string coder = "AAAA";
    DAudioHandler::GetInstance().AddToVec(container, coder);
    EXPECT_EQ(container.size(), 1);
}
} // namespace DistributedHardware
} // namespace OHOS