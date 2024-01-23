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
    int32_t dhId = DEFAULT_CAPTURE_ID;
    clientCallback_ = std::make_shared<MockIAudioEventCallback>();
    micClient_ = std::make_shared<DMicClient>(devId, dhId, clientCallback_);
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
 * @tc.name: InitSenderEngine_001
 * @tc.desc: Verify the InitSenderEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, InitSenderEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    auto message = std::make_shared<AVTransMessage>();
    micClient_->OnEngineTransMessage(message);
    EXPECT_EQ(DH_SUCCESS, micClient_->InitSenderEngine(providerPtr));
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
    std::string devId = "testID";
    auto clientCallback = std::make_shared<MockIAudioEventCallback>();
    micClient_->SetAttrs(devId, clientCallback);
    AudioParam audioParam;
    EXPECT_NE(DH_SUCCESS, micClient_->SetUp(audioParam));
    EXPECT_EQ(DH_SUCCESS, micClient_->SetUp(audioParam_));
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

    AudioStandard::AudioCapturerOptions capturerOptions = {
        {
            static_cast<AudioStandard::AudioSamplingRate>(audioParam_.comParam.sampleRate),
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            static_cast<AudioStandard::AudioSampleFormat>(audioParam_.comParam.bitFormat),
            static_cast<AudioStandard::AudioChannel>(audioParam_.comParam.channelMask),
        },
        {
            static_cast<AudioStandard::SourceType>(audioParam_.captureOpts.sourceType),
            0,
        }
    };
    micClient_->audioCapturer_ = AudioStandard::AudioCapturer::Create(capturerOptions);
    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    micClient_->clientStatus_ = AudioStatus::STATUS_STOP;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->StartCapture());
    micClient_->clientStatus_ = AudioStatus::STATUS_READY;
    EXPECT_NE(nullptr, micClient_->audioCapturer_);
    EXPECT_EQ(DH_SUCCESS, micClient_->StartCapture());
    micClient_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->StartCapture());
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

/**
 * @tc.name: StopCapture002
 * @tc.desc: Verify the StopCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StopCapture002, TestSize.Level1)
{
    micClient_->clientStatus_ = STATUS_START;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, micClient_->StopCapture());
    micClient_->isCaptureReady_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->StopCapture());
    micClient_->SetUp(audioParam_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->StopCapture());
}

/**
 * @tc.name: Release001
 * @tc.desc: Verify the Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, Release001, TestSize.Level1)
{
    micClient_->clientStatus_ = AudioStatus::STATUS_START;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->Release());
    micClient_->clientStatus_ = AudioStatus::STATUS_STOP;
    micClient_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->Release());
    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();

    AudioStandard::AudioCapturerOptions capturerOptions = {
        {
            static_cast<AudioStandard::AudioSamplingRate>(audioParam_.comParam.sampleRate),
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            static_cast<AudioStandard::AudioSampleFormat>(audioParam_.comParam.bitFormat),
            static_cast<AudioStandard::AudioChannel>(audioParam_.comParam.channelMask),
        },
        {
            static_cast<AudioStandard::SourceType>(audioParam_.captureOpts.sourceType),
            0,
        }
    };
    micClient_->audioCapturer_ = AudioStandard::AudioCapturer::Create(capturerOptions);
    EXPECT_NE(nullptr, micClient_->audioCapturer_);
    EXPECT_EQ(DH_SUCCESS, micClient_->Release());
    micClient_->audioCapturer_ = nullptr;
    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    micClient_->clientStatus_ = AudioStatus::STATUS_STOP;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, micClient_->Release());
    micClient_->clientStatus_ = AudioStatus::STATUS_IDLE;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->Release());
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify the SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SendMessage_001, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, micClient_->SendMessage(EVENT_UNKNOWN, content, dstDevId));
    EXPECT_EQ(DH_SUCCESS, micClient_->SendMessage(NOTIFY_OPEN_MIC_RESULT, content, dstDevId));
    micClient_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, micClient_->SendMessage(NOTIFY_OPEN_MIC_RESULT, content, dstDevId));
}

/**
 * @tc.name: AudioFwkClientSetUp_001
 * @tc.desc: Verify the AudioFwkClientSetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, AudioFwkClientSetUp_001, TestSize.Level1)
{
    audioParam_.captureOpts.capturerFlags = MMAP_MODE;
    int32_t actual = micClient_->AudioFwkClientSetUp();
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_CAPTURER_CREATE_FAILED, actual);
    audioParam_.captureOpts.capturerFlags = NORMAL_MODE;
    actual = micClient_->AudioFwkClientSetUp();
    EXPECT_NE(DH_SUCCESS, actual);
}

/**
 * @tc.name: TransSetUp_001
 * @tc.desc: Verify the TransSetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, TransSetUp_001, TestSize.Level1)
{
    int32_t actual = micClient_->TransSetUp();
    EXPECT_EQ(DH_SUCCESS, actual);
    micClient_->micTrans_ = nullptr;
    actual = micClient_->TransSetUp();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, actual);
}
} // DistributedHardware
} // OHOS
