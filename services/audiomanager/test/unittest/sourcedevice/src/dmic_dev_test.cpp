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

#include "dmic_dev_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t DH_ID = 1;
constexpr int32_t DH_ID_MIC = 134217728;
const std::string DEV_ID = "Test_Dev_Id";
const std::string CAP = "Test_Capability";

void DMicDevTest::SetUpTestCase(void) {}

void DMicDevTest::TearDownTestCase(void) {}

void DMicDevTest::SetUp(void)
{
    eventCb_ = std::make_shared<MockIAudioEventCallback>();
    mic_ = std::make_shared<DMicDev>(DEV_ID, eventCb_);
}

void DMicDevTest::TearDown(void)
{
    eventCb_ = nullptr;
    mic_ = nullptr;
}

/**
 * @tc.name: InitReceiverEngine_001
 * @tc.desc: Verify InitReceiverEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, InitReceiverEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    mic_->OnEngineTransEvent(event);
    std::shared_ptr<AVTransMessage> message = nullptr;
    mic_->OnEngineTransMessage(message);
    size_t size = 4096;
    auto audioData = std::make_shared<AudioData>(size);
    mic_->OnEngineTransDataAvailable(audioData);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->InitReceiverEngine(providerPtr));
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->InitReceiverEngine(providerPtr));
}

/**
 * @tc.name: EnableDMic_001
 * @tc.desc: Verify EnableDMic and EnableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, EnableDMic_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID_MIC, CAP));
}

/**
 * @tc.name: DisableDMic_001
 * @tc.desc: Verify DisableDMic and DisableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, DisableDMic_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID));

    mic_->curPort_ = DH_ID_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID_MIC));
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: CreateStream_001
 * @tc.desc: Verify CreateStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, CreateStream_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, mic_->CreateStream(streamId_));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->CreateStream(streamId_));
}

/**
 * @tc.name: DestroyStream_001
 * @tc.desc: Verify DestroyStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, DestroyStream_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, mic_->DestroyStream(streamId_));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_001
 * @tc.desc: Verify SetParameters and GetAudioParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetParameters_001, TestSize.Level1)
{
    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    mic_->GetAudioParam();
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, NotifyEvent_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(OPEN_MIC, "OPEN_MIC");
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    event.type = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetUp_001, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Start_001, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Start());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    EXPECT_FALSE(mic_->IsOpened());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    mic_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    EXPECT_TRUE(mic_->IsOpened());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Start_002, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    EXPECT_NE(DH_SUCCESS, mic_->Start());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, mic_->Start());
    EXPECT_FALSE(mic_->IsOpened());

    mic_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    EXPECT_TRUE(mic_->IsOpened());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Stop_001, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Stop_002, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Release_001, TestSize.Level1)
{
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->Release());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Release());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->Release());
}


/**
 * @tc.name: ReadStreamData_001
 * @tc.desc: Verify ReadStreamData and WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, ReadStreamData_001, TestSize.Level1)
{
    mic_->curStatus_ = AudioStatus::STATUS_START;
    mic_->paramHDF_.period = 10;
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    EXPECT_EQ(DH_SUCCESS, mic_->WriteStreamData(streamId_, writeData));

    std::shared_ptr<AudioData> readData = nullptr;
    mic_->dataQueue_.push(writeData);
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData));
    for (size_t i = 0; i < 11; ++i) {
        auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        mic_->dataQueue_.push(data);
    }
    mic_->isEnqueueRunning_ = true;
    mic_->FillJitterQueue();

    std::shared_ptr<AudioData> readData1 = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData1));
}

/**
 * @tc.name: NotifyHdfAudioEvent_001
 * @tc.desc: Verify NotifyHdfAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, NotifyHdfAudioEvent_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(OPEN_MIC, "OPEN_MIC");
    int32_t dhId = 0;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyHdfAudioEvent(event, dhId));

    event.type = MIC_OPENED;
    dhId = DH_ID_MIC;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyHdfAudioEvent(event, dhId));
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnStateChange_001, TestSize.Level1)
{
    AudioEventType event = DATA_OPENED;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    event = DATA_CLOSED;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    event = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnStateChange(event));
}

/**
 * @tc.name: OnDecodeTransDataDone_001
 * @tc.desc: Verify OnDecodeTransDataDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnDecodeTransDataDone_001, TestSize.Level1)
{
    std::shared_ptr<AudioData> data = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));

    const size_t capacity = 1;
    data = std::make_shared<AudioData>(capacity);
    for (size_t i = 1; i <= mic_->DATA_QUEUE_MAX_SIZE + 1; i++) {
        EXPECT_EQ(DH_SUCCESS, mic_->OnDecodeTransDataDone(data));
    }
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SendMessage_001, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(MIC_OPENED, content, dstDevId));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(OPEN_MIC, content, dstDevId));
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SendMessage(OPEN_MIC, content, dstDevId));
}
} // namespace DistributedHardware
} // namespace OHOS
