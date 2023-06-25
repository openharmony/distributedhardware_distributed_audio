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

#include <gtest/gtest.h>

#define private public
#include "audio_direct_processor.h"
#undef private

#include "daudio_errorcode.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class AudioDirectProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AudioDirectProcessor> processor_ = nullptr;
};

void AudioDirectProcessorTest::SetUpTestCase(void) {}

void AudioDirectProcessorTest::TearDownTestCase(void) {}

void AudioDirectProcessorTest::SetUp()
{
    processor_ = std::make_shared<AudioDirectProcessor>();
}

void AudioDirectProcessorTest::TearDown()
{
    processor_ = nullptr;
}

/**
 * @tc.name: ConfigureAudioProcessor_001
 * @tc.desc: Verify the ConfigureAudioProcessor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(AudioDirectProcessorTest, ConfigureAudioProcessor_001, TestSize.Level1)
{
    AudioCommonParam param;
    std::shared_ptr<IAudioProcessorCallback> procCallback = nullptr;
    EXPECT_NE(DH_SUCCESS, processor_->ConfigureAudioProcessor(param, param, procCallback));
}

/**
 * @tc.name: StartAudioProcessor_001
 * @tc.desc: Verify the StartAudioProcessor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(AudioDirectProcessorTest, StartAudioProcessor_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, processor_->StartAudioProcessor());
    EXPECT_EQ(DH_SUCCESS, processor_->StopAudioProcessor());
}

/**
 * @tc.name: FeedAudioProcessor_001
 * @tc.desc: Verify the FeedAudioProcessor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(AudioDirectProcessorTest, FeedAudioProcessor_001, TestSize.Level1)
{
    std::shared_ptr<AudioData> inputData = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, processor_->FeedAudioProcessor(inputData));
    inputData = std::make_shared<AudioData>(4096);
    EXPECT_NE(DH_SUCCESS, processor_->FeedAudioProcessor(inputData));
}
} // namespace DistributedHardware
} // namespace OHOS
