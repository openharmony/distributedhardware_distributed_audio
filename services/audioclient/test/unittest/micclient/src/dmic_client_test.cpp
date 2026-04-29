/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
HWTEST_F(DMicClientTest, InitSenderEngine_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
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
HWTEST_F(DMicClientTest, OnStateChange_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    EXPECT_NE(DH_SUCCESS, micClient_->OnStateChange(AudioEventType::NOTIFY_OPEN_SPEAKER_RESULT));
}

/**
 * @tc.name: OnStateChange_002
 * @tc.desc: Verify the OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, OnStateChange_002, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    EXPECT_EQ(DH_SUCCESS, micClient_->OnStateChange(AudioEventType::DATA_CLOSED));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetUp_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    std::string devId = "testID";
    auto clientCallback = std::make_shared<MockIAudioEventCallback>();
    micClient_->SetAttrs(devId, clientCallback);
    AudioParam audioParam;
    EXPECT_NE(DH_SUCCESS, micClient_->SetUp(audioParam));
}

/**
 * @tc.name: StartCapture001
 * @tc.desc: Verify the StartCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StartCapture001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    micClient_->CaptureThreadRunning();
    EXPECT_NE(DH_SUCCESS, micClient_->StartCapture());
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());

    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    micClient_->clientStatus_ = AudioStatus::STATUS_STOP;
    EXPECT_EQ(nullptr, micClient_->audioCapturer_);
    EXPECT_NE(DH_SUCCESS, micClient_->StartCapture());
    micClient_->micTrans_ = nullptr;
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
}

/**
 * @tc.name: StopCapture001
 * @tc.desc: Verify the StopCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StopCapture001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    std::shared_ptr<AudioData> audioData = nullptr;
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
    micClient_->clientStatus_ = STATUS_START;
    EXPECT_NE(DH_SUCCESS, micClient_->StopCapture());
    size_t length = 1;
    micClient_->OnReadData(length);
    EXPECT_EQ(DH_SUCCESS, micClient_->OnDecodeTransDataDone(audioData));
}

/**
 * @tc.name: StopCapture002
 * @tc.desc: Verify the StopCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, StopCapture002, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
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
HWTEST_F(DMicClientTest, Release001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    micClient_->clientStatus_ = AudioStatus::STATUS_START;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->Release());
    micClient_->clientStatus_ = AudioStatus::STATUS_STOP;
    micClient_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, micClient_->Release());
    micClient_->micTrans_ = std::make_shared<MockIAudioDataTransport>();

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
HWTEST_F(DMicClientTest, SendMessage_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, micClient_->SendMessage(EVENT_UNKNOWN, content, dstDevId));
    micClient_->InitCtrlTrans();
    EXPECT_EQ(DH_SUCCESS, micClient_->SendMessage(NOTIFY_OPEN_MIC_RESULT, content, dstDevId));
    micClient_->micCtrlTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, micClient_->SendMessage(NOTIFY_OPEN_MIC_RESULT, content, dstDevId));
}

/**
 * @tc.name: AudioFwkClientSetUp_001
 * @tc.desc: Verify the AudioFwkClientSetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, AudioFwkClientSetUp_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
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
HWTEST_F(DMicClientTest, TransSetUp_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    int32_t actual = micClient_->TransSetUp();
    EXPECT_EQ(DH_SUCCESS, actual);
    micClient_->micTrans_ = nullptr;
    actual = micClient_->TransSetUp();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, actual);
}

/**
 * @tc.name: CalcMicDataPts_001
 * @tc.desc: Verify the CalcMicDataPts function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, CalcMicDataPts_001, TestSize.Level0)
{
    micClient_->getAudioTimeCounter_ = 1;
    micClient_->CalcMicDataPts();
    EXPECT_NE(micClient_->getAudioTimeCounter_, 0);
}

/**
 * @tc.name: SetEnhanceParameter_001
 * @tc.desc: Verify the SetEnhanceParameter function when cJSON_Parse fails with invalid JSON.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_001, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE, "invalid_json");
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, micClient_->SetEnhanceParameter(event));
}

/**
 * @tc.name: SetEnhanceParameter_002
 * @tc.desc: Verify the SetEnhanceParameter function when cJSON_Parse fails with empty string.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_002, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE, "");
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, micClient_->SetEnhanceParameter(event));
}

/**
 * @tc.name: SetEnhanceParameter_003
 * @tc.desc: Verify the SetEnhanceParameter function when JSON is valid but missing audio_effect field.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_003, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE, "{\"other_key\":\"other_value\"}");
    int32_t ret = micClient_->SetEnhanceParameter(event);
    EXPECT_NE(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, ret);
    EXPECT_TRUE(ret == DH_SUCCESS || ret == ERR_DH_AUDIO_FAILED);
}

/**
 * @tc.name: SetEnhanceParameter_004
 * @tc.desc: Verify the SetEnhanceParameter function with correct audio_effect format containing SCENE string.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_004, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE,
        "{\"audio_effect\":{\"SCENE\":\"high-definition-record\"}}");
    int32_t ret = micClient_->SetEnhanceParameter(event);
    EXPECT_NE(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, ret);
    EXPECT_TRUE(ret == DH_SUCCESS || ret == ERR_DH_AUDIO_FAILED);
}

/**
 * @tc.name: SetEnhanceParameter_005
 * @tc.desc: Verify the SetEnhanceParameter function when audio_effect field type is string instead of object.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_005, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE, "{\"audio_effect\":\"string_value\"}");
    int32_t ret = micClient_->SetEnhanceParameter(event);
    EXPECT_NE(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, ret);
    EXPECT_TRUE(ret == DH_SUCCESS || ret == ERR_DH_AUDIO_FAILED);
}

/**
 * @tc.name: SetEnhanceParameter_006
 * @tc.desc: Verify the SetEnhanceParameter function when audio_effect is object but SCENE is not string.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_006, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE, "{\"audio_effect\":{\"SCENE\":123}}");
    int32_t ret = micClient_->SetEnhanceParameter(event);
    EXPECT_NE(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, ret);
    EXPECT_TRUE(ret == DH_SUCCESS || ret == ERR_DH_AUDIO_FAILED);
}

/**
 * @tc.name: SetEnhanceParameter_007
 * @tc.desc: Verify the SetEnhanceParameter function when audio_effect is object but missing SCENE field.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DMicClientTest, SetEnhanceParameter_007, TestSize.Level0)
{
    ASSERT_TRUE(micClient_ != nullptr);
    AudioEvent event(AudioEventType::ENHANCE_PARAM_CHANGE,
        "{\"audio_effect\":{\"OTHER_FIELD\":\"value\"}}");
    int32_t ret = micClient_->SetEnhanceParameter(event);
    EXPECT_NE(ERR_DH_AUDIO_CLIENT_PARAM_ERROR, ret);
    EXPECT_TRUE(ret == DH_SUCCESS || ret == ERR_DH_AUDIO_FAILED);
}
} // DistributedHardware
} // OHOS
