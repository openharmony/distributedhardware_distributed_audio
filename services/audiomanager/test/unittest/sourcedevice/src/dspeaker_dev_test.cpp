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

#include "dspeaker_dev_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t DH_ID = 1;
constexpr int32_t DH_ID_SPK = 134217728;
const std::string DEV_ID = "Test_Dev_Id";
const std::string CAP = "Test_Capability";

void DSpeakerDevTest::SetUpTestCase(void) {}

void DSpeakerDevTest::TearDownTestCase(void) {}

void DSpeakerDevTest::SetUp(void)
{
    eventCb_ = std::make_shared<MockIAudioEventCallback>();
    spk_ = std::make_shared<DSpeakerDev>(DEV_ID, eventCb_);
}

void DSpeakerDevTest::TearDown(void)
{
    eventCb_ = nullptr;
    spk_ = nullptr;
}

/**
 * @tc.name: InitSenderEngine_001
 * @tc.desc: Verify InitSenderEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, InitSenderEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_STOP_SUCCESS;
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_START_FAIL;
    spk_->OnEngineTransEvent(event);
    std::shared_ptr<AVTransMessage> message = nullptr;
    spk_->OnEngineTransMessage(message);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->InitSenderEngine(providerPtr));
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->InitSenderEngine(providerPtr));
}

/**
 * @tc.name: EnableDSpeaker_001
 * @tc.desc: Verify EnableDSpeaker and EnableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, EnableDSpeaker_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID, CAP));

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID_SPK, CAP));
}

/**
 * @tc.name: DisableDSpeaker_001
 * @tc.desc: Verify DisableDSpeaker and DisableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, DisableDSpeaker_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(DH_ID));

    spk_->curPort_ = DH_ID_SPK;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(DH_ID_SPK));
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: CreateStream_001
 * @tc.desc: Verify CreateStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, CreateStream_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(streamId_));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->CreateStream(streamId_));
}

/**
 * @tc.name: DestroyStream_001
 * @tc.desc: Verify DestroyStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, DestroyStream_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(streamId_));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_001
 * @tc.desc: Verify SetParameters and GetAudioParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SetParameters_001, TestSize.Level1)
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
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    spk_->GetAudioParam();
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(OPEN_SPEAKER, "OPEN_SPEAKER");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    event.type = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SetUp_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->SetUp());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Start_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Start());

    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Start_002, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Start_003
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Start_003, TestSize.Level1)
{
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->SetUp());
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, spk_->Start());

    spk_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, spk_->Start());
    EXPECT_TRUE(spk_->IsOpened());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Stop_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Stop_002, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Pause_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Pause());

    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Pause());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Pause());
}

/**
 * @tc.name: Restart_001
 * @tc.desc: Verify Restart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Restart_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Restart());

    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Restart());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Restart());
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, Release_001, TestSize.Level1)
{
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    int32_t fd = 1;
    int32_t ashmemLength = 10;
    int32_t streamId = 1;
    int32_t lengthPerTrans = 10;
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
    spk_->param_.renderOpts.renderFlags = MMAP_MODE;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
}

/**
 * @tc.name: WriteStreamData_001
 * @tc.desc: Verify WriteStreamData and ReadStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, WriteStreamData_001, TestSize.Level1)
{
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(streamId_, writeData));

    std::shared_ptr<AudioData> readData = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadStreamData(streamId_, readData));

    std::shared_ptr<AudioData> data = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->OnDecodeTransDataDone(data));
}

/**
 * @tc.name: WriteStreamData_002
 * @tc.desc: Verify WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, WriteStreamData_002, TestSize.Level1)
{
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(streamId_, writeData));

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->WriteStreamData(streamId_, writeData));
}

/**
 * @tc.name: NotifyHdfAudioEvent_001
 * @tc.desc: Verify NotifyHdfAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, NotifyHdfAudioEvent_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(OPEN_SPEAKER, "OPEN_SPEAKER");
    int32_t dhId = 0;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, dhId));

    event.type = SPEAKER_OPENED;
    dhId = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, dhId));
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_001, TestSize.Level1)
{
    AudioEventType event = DATA_OPENED;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    event = DATA_CLOSED;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    event = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->OnStateChange(event));
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SendMessage_001, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SendMessage(MIC_OPENED, content, dstDevId));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SendMessage(OPEN_SPEAKER, content, dstDevId));
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(OPEN_SPEAKER, content, dstDevId));
}
} // namespace DistributedHardware
} // namespace OHOS
