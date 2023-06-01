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

#define private public
#include "audio_data_test.h"
#undef private

#include "daudio_constants.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AudioDataTest::SetUpTestCase(void) {}

void AudioDataTest::TearDownTestCase(void) {}

void AudioDataTest::SetUp(void)
{
    size_t capacity = 20;
    audioData = std::make_shared<AudioData>(capacity);
}

void AudioDataTest::TearDown(void) {}

/**
 * @tc.name: SetRange_001
 * @tc.desc: Verify the SetRange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, SetRange_001, TestSize.Level1)
{
    size_t offset = 100;
    size_t size = 100;
    int32_t ret = audioData->SetRange(offset, size);
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, ret);
}

/**
 * @tc.name: SetRange_002
 * @tc.desc: Verify the SetRange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, SetRange_002, TestSize.Level1)
{
    size_t offset = 5;
    size_t size = 5;
    int32_t ret = audioData->SetRange(offset, size);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: FindInt32_001
 * @tc.desc: Verify the FindInt32 function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindInt32_001, TestSize.Level1)
{
    const std::string name = "name";
    int32_t value = 1;
    audioData->int32Map_.insert(std::make_pair(name, value));
    EXPECT_EQ(true, audioData->FindInt32(name, value));
}

/**
 * @tc.name: FindInt32_002
 * @tc.desc: Verify the FindInt32 function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindInt32_002, TestSize.Level1)
{
    const std::string name = "name";
    int32_t value = 1;
    EXPECT_EQ(false, audioData->FindInt32(name, value));
}

/**
 * @tc.name: FindInt64_001
 * @tc.desc: Verify the FindInt64 function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindInt64_001, TestSize.Level1)
{
    const std::string name = "name";
    int64_t value = 1;
    audioData->SetInt64(name, value);
    EXPECT_EQ(true, audioData->FindInt64(name, value));
}

/**
 * @tc.name: FindInt64_002
 * @tc.desc: Verify the FindInt64 function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindInt64_002, TestSize.Level1)
{
    const std::string name = "name";
    int64_t value = 1;
    EXPECT_EQ(false, audioData->FindInt64(name, value));
}

/**
 * @tc.name: FindString_001
 * @tc.desc: Verify the FindString function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindString_001, TestSize.Level1)
{
    const std::string name = "name";
    string value = "value";
    audioData->stringMap_.insert(std::make_pair(name, value));
    EXPECT_EQ(true, audioData->FindString(name, value));
}

/**
 * @tc.name: FindString_002
 * @tc.desc: Verify the FindString function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataTest, FindString_002, TestSize.Level1)
{
    const std::string name = "name";
    string value = "value";
    EXPECT_EQ(false, audioData->FindString(name, value));
}
} // namespace DistributedHardware
} // namespace OHOS
