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

#include "dmic_client_test.h"

#include "audio_event.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DMicClientTest::SetUpTestCase(void) {}

void DMicClientTest::TearDownTestCase(void) {}

void DMicClientTest::SetUp()
{
    std::string devId = "hello";
    clientCallback_ = std::make_shared<MockIAudioEventCallback>();
    micClient_ = std::make_shared<DMicClient>(devId, clientCallback_);
    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();

    audioParam_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    audioParam_.comParam.sampleRate = AudioSampleRate::SAMPLE_RATE_48000;
    audioParam_.comParam.bitFormat = AudioSampleFormat::SAMPLE_S16LE;
    audioParam_.comParam.channelMask = AudioChannel::STEREO;
    audioParam_.captureOpts.sourceType = SourceType::SOURCE_TYPE_MIC;
}

void DMicClientTest::TearDown()
{
    clientCallback_ = nullptr;
    micClient_ = nullptr;
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify the OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, OnStateChange_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, micClient_->OnStateChange(AudioEventType::NOTIFY_OPEN_SPEAKER_RESULT));
}

/**
 * @tc.name: OnStateChange_002
 * @tc.desc: Verify the OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, OnStateChange_002, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, micClient_->OnStateChange(AudioEventType::DATA_CLOSED));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetUp_001, TestSize.Level1)
{
    AudioParam audioParam;
    EXPECT_NE(DH_SUCCESS, micClient_->SetUp(audioParam));
}

/**
 * @tc.name: StartCapture001
 * @tc.desc: Verify the StartCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StartCapture001, TestSize.Level1)
{
    micClient_->CaptureThreadRunning();
    EXPECT_NE(DH_SUCCESS, micClient_->StartCapture());
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
}

/**
 * @tc.name: StopCapture001
 * @tc.desc: Verify the StopCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StopCapture001, TestSize.Level1)
{
    std::shared_ptr<AudioData> audioData = nullptr;
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
    micClient_->clientStatus_ = STATUS_START;
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
    EXPECT_EQ(DH_SUCCESS, micClient_->OnDecodeTransDataDone(audioData));
}
} // DistributedHardware
} // OHOS
