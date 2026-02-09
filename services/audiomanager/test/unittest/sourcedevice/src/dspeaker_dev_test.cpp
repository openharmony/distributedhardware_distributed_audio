/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 * @tc.desc: Verify the InitSenderEngine interface under different engine transport states and null/valid transport
 *           pointers. Test engine events (START_SUCCESS/STOP_SUCCESS/CHANNEL_CLOSED/START_FAIL), null message,
 *           and null/valid provider.
 *           Expected: Null provider returns ERR_DH_AUDIO_NULLPTR; valid transport returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, InitSenderEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    
    // Test OnEngineTransEvent with different event types
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_STOP_SUCCESS;
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    spk_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_START_FAIL;
    spk_->OnEngineTransEvent(event);
    
    // Test OnEngineTransMessage with null message
    std::shared_ptr<AVTransMessage> message = nullptr;
    spk_->OnEngineTransMessage(message);
    
    // Test InitSenderEngine with null provider (no transport)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->InitSenderEngine(providerPtr));
    
    // Test InitSenderEngine with mock transport and null provider
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->InitSenderEngine(providerPtr));
}

/**
 * @tc.name: InitReceiverEngine_001
 * @tc.desc: Verify the InitReceiverEngine interface with null IAVEngineProvider pointer.
 *           Expected: Returns DH_SUCCESS even with null provider pointer.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, InitReceiverEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    // Test InitReceiverEngine with null provider pointer
    EXPECT_EQ(DH_SUCCESS, spk_->InitReceiverEngine(providerPtr));
}

/**
 * @tc.name: EnableDSpeaker_001
 * @tc.desc: Verify the EnableDevice interface with DH_ID and DH_ID_SPK (speaker device ID).
 *           Expected: All calls return ERR_DH_AUDIO_NULLPTR for invalid device handle IDs.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, EnableDSpeaker_001, TestSize.Level1)
{
    // Test EnableDevice with DH_ID (duplicate call)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID, CAP));

    // Test EnableDevice with DH_ID_SPK (speaker device ID)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(DH_ID_SPK, CAP));
}

/**
 * @tc.name: DisableDSpeaker_001
 * @tc.desc: Verify the DisableDevice interface with DH_ID and DH_ID_SPK, and check IsOpened status.
 *           Expected: Returns ERR_DH_AUDIO_NULLPTR; IsOpened returns false after disable.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, DisableDSpeaker_001, TestSize.Level1)
{
    // Test DisableDevice with DH_ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(DH_ID));

    // Test DisableDevice with DH_ID_SPK (set current port first)
    spk_->curPort_ = DH_ID_SPK;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(DH_ID_SPK));
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: CreateStream_001
 * @tc.desc: Verify the CreateStream interface with valid stream ID and null event callback.
 *           Expected: Valid call returns DH_SUCCESS; null callback returns ERR_DH_AUDIO_NULLPTR.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, CreateStream_001, TestSize.Level1)
{
    // Test CreateStream with valid stream ID
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(streamId_));

    // Test CreateStream with null event callback
    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->CreateStream(streamId_));
}

/**
 * @tc.name: DestroyStream_001
 * @tc.desc: Verify the DestroyStream interface with valid stream ID and null event callback.
 *           Expected: Valid call returns DH_SUCCESS; null callback returns ERR_DH_AUDIO_NULLPTR.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, DestroyStream_001, TestSize.Level1)
{
    // Test DestroyStream with valid stream ID
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(streamId_));

    // Test DestroyStream with null event callback
    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_001
 * @tc.desc: Verify the SetParameters interface with basic audio parameters and call GetAudioParam.
 *           Test parameters: 8000Hz, STEREO, SAMPLE_U8, unknown stream usage.
 *           Expected: SetParameters returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
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
    
    // Test SetParameters with basic audio parameters
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    // Call GetAudioParam to retrieve parameters (no assertion)
    spk_->GetAudioParam();
}

/**
 * @tc.name: SetParameters_002
 * @tc.desc: Verify SetParameters with voice communication stream usage and codec capability checks.
 *           Test AAC/OPUS codec caps, clear/restore codec container.
 *           Expected: SetParameters returns DH_SUCCESS after codec cap checks.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_002, TestSize.Level1)
{
    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_VOICE_COMMUNICATION,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    
    // Save original codec container, clear and add AAC/OPUS caps
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    
    // Test SetParameters with voice communication usage
    auto ret = spk_->SetParameters(streamId_, param);
    spk_->GetAudioParam();
    spk_->codec_ = container;
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify the NotifyEvent interface with OPEN_SPEAKER/UNKNOWN events and null callback.
 *           Expected: Valid events return DH_SUCCESS; null callback returns ERR_DH_AUDIO_NULLPTR.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_001, TestSize.Level1)
{
    // Test NotifyEvent with OPEN_SPEAKER event
    AudioEvent event = AudioEvent(OPEN_SPEAKER, "OPEN_SPEAKER");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Test NotifyEvent with EVENT_UNKNOWN
    event.type = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Test NotifyEvent with null event callback
    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp interface with null/valid speaker transport pointer.
 *           Expected: Null transport returns ERR_DH_AUDIO_NULLPTR; mock transport returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetUp_001, TestSize.Level1)
{
    // Test SetUp with null speaker transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());

    // Test SetUp with mock audio data transport
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->SetUp());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start interface with null/AVTransSenderTransport and check IsOpened status.
 *           Expected: Null transport returns ERR_DH_AUDIO_NULLPTR; AVTransSender returns non-DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Start_001, TestSize.Level1)
{
    // Test Start with null speaker transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Start());

    // Test Start with AVTransSenderTransport
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify Start interface after failed SetUp (null transport) and check IsOpened status.
 *           Expected: SetUp fails with null transport; Start returns non-DH_SUCCESS; IsOpened is false.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Start_002, TestSize.Level1)
{
    // Test SetUp and Start with null speaker transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Start_003
 * @tc.desc: Verify Start interface with mock transport (trans ready false/true) and check IsOpened.
 *           Expected: Trans not ready returns SA_WAIT_TIMEOUT; trans ready returns DH_SUCCESS (IsOpened=true).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Start_003, TestSize.Level1)
{
    // Test Start with mock transport (trans not ready)
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->SetUp());
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, spk_->Start());

    // Test Start with trans ready (IsOpened should be true)
    spk_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, spk_->Start());
    EXPECT_TRUE(spk_->IsOpened());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify the Stop interface with null/valid speaker transport and check IsOpened status.
 *           Expected: Stop returns DH_SUCCESS in all cases; IsOpened is false after stop.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Stop_001, TestSize.Level1)
{
    // Test Stop with null transport (before/after failed SetUp)
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());

    // Test Stop with mock transport (IsOpened should be false)
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify Stop interface after failed SetUp/Start and check IsOpened status.
 *           Expected: Stop returns DH_SUCCESS; IsOpened is false after stop.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Stop_002, TestSize.Level1)
{
    // Test SetUp/Start failure and Stop (IsOpened should be false)
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SetUp());
    EXPECT_NE(DH_SUCCESS, spk_->Start());
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify the Pause interface with null/AVTransSender/mock speaker transport.
 *           Expected: Null transport returns ERR_DH_AUDIO_NULLPTR; AVTransSender returns non-DH_SUCCESS;
 *           mock returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Pause_001, TestSize.Level1)
{
    // Test Pause with null transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Pause());

    // Test Pause with AVTransSenderTransport
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Pause());

    // Test Pause with mock transport
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Pause());
}

/**
 * @tc.name: Restart_001
 * @tc.desc: Verify the Restart interface with null/AVTransSender/mock transport and audio parameters.
 *           Expected: Null transport returns ERR_DH_AUDIO_NULLPTR; AVTransSender returns non-DH_SUCCESS;
 *           mock returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Restart_001, TestSize.Level1)
{
    // Test Restart with null transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->Restart());

    // Set basic audio parameters
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
    
    // Test Restart with AVTransSenderTransport
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_NE(DH_SUCCESS, spk_->Restart());

    // Test Restart with mock transport
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Restart());
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify the Release interface with null/AVTransSender/mock transport and RefreshAshmemInfo.
 *           Test RefreshAshmemInfo in normal/MMAP mode (MMAP returns ERR_DH_AUDIO_NULLPTR).
 *           Expected: Release returns DH_SUCCESS in all cases.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Release_001, TestSize.Level1)
{
    // Test Release with null transport
    spk_->speakerTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    // Test Release with AVTransSenderTransport
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    // Test Release with mock transport
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    // Test RefreshAshmemInfo (normal/MMAP mode)
    int32_t fd = 10;
    int32_t ashmemLength = 10;
    int32_t streamId = 1;
    int32_t lengthPerTrans = 10;
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
    
    spk_->param_.renderOpts.renderFlags = MMAP_MODE;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
}

/**
 * @tc.name: WriteStreamData_001
 * @tc.desc: Verify WriteStreamData/ReadStreamData/OnDecodeTransDataDone with valid audio data pointer.
 *           Expected: WriteStreamData returns ERR_DH_AUDIO_NULLPTR; others return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, WriteStreamData_001, TestSize.Level1)
{
    // Test WriteStreamData with valid audio data (returns null ptr error)
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(streamId_, writeData));

    // Test ReadStreamData with null data
    std::shared_ptr<AudioData> readData = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadStreamData(streamId_, readData));

    // Test OnDecodeTransDataDone with null data
    std::shared_ptr<AudioData> data = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->OnDecodeTransDataDone(data));
}

/**
 * @tc.name: WriteStreamData_002
 * @tc.desc: Verify WriteStreamData with AVTransSender/mock transport and valid audio data.
 *           Expected: AVTransSender returns ERR_DH_AUDIO_NULLPTR; mock transport returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, WriteStreamData_002, TestSize.Level1)
{
    // Create valid audio data
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    
    // Test WriteStreamData with AVTransSenderTransport
    spk_->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, spk_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(streamId_, writeData));

    // Test WriteStreamData with mock transport
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->WriteStreamData(streamId_, writeData));
}

/**
 * @tc.name: ReadMmapPosition_001
 * @tc.desc: Verify the ReadMmapPosition interface with default parameters (stream ID 0).
 *           Expected: Returns DH_SUCCESS with zero-initialized frames/time.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, ReadMmapPosition_001, TestSize.Level1)
{
    // Test ReadMmapPosition with default parameters
    int32_t streamId = 0;
    uint64_t frames = 0;
    CurrentTimeHDF time;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(streamId, frames, time));
}

/**
 * @tc.name: MmapStart_001
 * @tc.desc: Verify the MmapStart interface with null ashmem pointer.
 *           Expected: Returns ERR_DH_AUDIO_NULLPTR for null ashmem.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, MmapStart_001, TestSize.Level1)
{
    // Test MmapStart with null ashmem pointer
    spk_->ashmem_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->MmapStart());
}

/**
 * @tc.name: NotifyHdfAudioEvent_001
 * @tc.desc: Verify the NotifyHdfAudioEvent interface with OPEN_SPEAKER/SPEAKER_OPENED events and different DH IDs.
 *           Expected: All calls return DH_SUCCESS for valid events/DH IDs.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyHdfAudioEvent_001, TestSize.Level1)
{
    // Test NotifyHdfAudioEvent with OPEN_SPEAKER and DH ID 0
    AudioEvent event = AudioEvent(OPEN_SPEAKER, "OPEN_SPEAKER");
    int32_t dhId = 0;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, dhId));

    // Test NotifyHdfAudioEvent with SPEAKER_OPENED and DH_ID_SPK
    event.type = SPEAKER_OPENED;
    dhId = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, dhId));
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify the OnStateChange interface with DATA_OPENED/DATA_CLOSED/UNKNOWN events and null callback.
 *           Expected: Valid events return DH_SUCCESS; null callback returns ERR_DH_AUDIO_NULLPTR.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_001, TestSize.Level1)
{
    // Test OnStateChange with DATA_OPENED event
    AudioEventType event = DATA_OPENED;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    // Test OnStateChange with DATA_CLOSED event
    event = DATA_CLOSED;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    // Test OnStateChange with EVENT_UNKNOWN
    event = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(event));

    // Test OnStateChange with null event callback
    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->OnStateChange(event));
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify the SendMessage interface with MIC_OPENED/OPEN_SPEAKER and null/valid transport.
 *           Expected: Null transport returns ERR_DH_AUDIO_NULLPTR; valid transport returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SendMessage_001, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    
    // Test SendMessage with null transport (MIC_OPENED/OPEN_SPEAKER)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SendMessage(MIC_OPENED, content, dstDevId));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->SendMessage(OPEN_SPEAKER, content, dstDevId));
    
    // Test SendMessage with mock transport (init control transport first)
    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    spk_->InitCtrlTrans();
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(OPEN_SPEAKER, content, dstDevId));
}

/**
 * @tc.name: AddToVec_001
 * @tc.desc: Verify the AddToVec interface with AUDIO_CODEC_AAC codec type.
 *           Expected: Container size is 1 after adding AAC codec type.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, AddToVec_001, TestSize.Level1)
{
    std::vector<AudioCodecType> container;
    // Add AAC codec type to empty container
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
}

/**
 * @tc.name: GetCodecCaps_001
 * @tc.desc: Verify the GetCodecCaps interface with AAC/OPUS codec types (clear/restore container).
 *           Expected: Container size is 1 (AAC) then 2 (AAC+OPUS) after adding caps.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, GetCodecCaps_001, TestSize.Level1)
{
    // Save original codec container, clear and add AAC cap
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    auto num = spk_->codec_.size();
    EXPECT_EQ(1, num);
    
    // Add OPUS cap (total size should be 2)
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    num = spk_->codec_.size();
    spk_->codec_ = container;
    EXPECT_EQ(2, num);
}

/**
 * @tc.name: IsMimeSupported_001
 * @tc.desc: Verify the IsMimeSupported interface with AAC encoder/OPUS codec (clear/restore container).
 *           Expected: AAC_EN returns true; OPUS returns false (not added to container).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, IsMimeSupported_001, TestSize.Level1)
{
    // Save original codec container, clear and add AAC cap
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    
    // Test AAC encoder (supported) and OPUS (not supported)
    bool ret = spk_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_AAC_EN);
    EXPECT_EQ(ret, true);
    ret = spk_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_OPUS);
    
    // Restore container and verify OPUS is not supported
    spk_->codec_ = container;
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetCodecCaps_002
 * @tc.desc: Verify the GetCodecCaps interface with empty capability string ("EmptyCapability").
 *           Expected: Codec container size remains 0 after calling GetCodecCaps.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, GetCodecCaps_002, TestSize.Level1)
{
    // Save original codec container, clear and call GetCodecCaps with empty capability
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps("EmptyCapability");
    spk_->codec_ = container;
    
    // Verify container size is 0 (no codec caps added)
    EXPECT_EQ(0, spk_->codec_.size());
}

/**
 * @tc.name: AddToVec_002
 * @tc.desc: Verify the AddToVec interface with duplicate AUDIO_CODEC_AAC codec type.
 *           Expected: Container size remains 1 (no duplicate entries added).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, AddToVec_002, TestSize.Level1)
{
    std::vector<AudioCodecType> container;
    // Add AAC codec type (size = 1)
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
    
    // Add duplicate AAC codec type (size remains 1)
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
}

/**
 * @tc.name: OnCtrlTransEvent_001
 * @tc.desc: Verify the OnCtrlTransEvent interface with EVENT_START_SUCCESS event.
 *           Expected: isTransReady_ flag is set to true after handling the event.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_001, TestSize.Level1)
{
    // Test OnCtrlTransEvent with EVENT_START_SUCCESS (isTransReady_ = true)
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_TRUE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_002
 * @tc.desc: Verify the OnCtrlTransEvent interface with EVENT_STOP_SUCCESS event (isOpened_ = true).
 *           Expected: isOpened_ flag is set to false after handling the event.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_002, TestSize.Level1)
{
    // Set isOpened_ to true, test EVENT_STOP_SUCCESS (isOpened_ = false)
    spk_->isOpened_.store(true);
    AVTransEvent event = { EventType::EVENT_STOP_SUCCESS, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_003
 * @tc.desc: Verify the OnCtrlTransEvent interface with EVENT_CHANNEL_CLOSED event (isOpened_ = true).
 *           Expected: isOpened_ flag is set to false after handling the event.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_003, TestSize.Level1)
{
    // Set isOpened_ to true, test EVENT_CHANNEL_CLOSED (isOpened_ = false)
    spk_->isOpened_.store(true);
    AVTransEvent event = { EventType::EVENT_CHANNEL_CLOSED, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_004
 * @tc.desc: Verify the OnCtrlTransEvent interface with EVENT_START_FAIL event when device is opened.
 *           Test scenario: Set isOpened_ to true, trigger EVENT_START_FAIL, verify isOpened_ is set to false.
 *           Expected: isOpened_ flag is false after handling EVENT_START_FAIL event.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_004, TestSize.Level1)
{
    // Set device opened status to true
    spk_->isOpened_.store(true);
    // Create EVENT_START_FAIL control transport event
    AVTransEvent event = { EventType::EVENT_START_FAIL, "", "" };
    // Process the control transport event
    spk_->OnCtrlTransEvent(event);
    // Verify device opened status is false after start failure
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransMessage_001
 * @tc.desc: Verify the OnCtrlTransMessage interface with null AVTransMessage pointer.
 *           Test scenario: Pass nullptr message to OnCtrlTransMessage, verify message remains null.
 *           Expected: Message pointer remains nullptr after processing.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransMessage_001, TestSize.Level1)
{
    // Initialize null control transport message
    std::shared_ptr<AVTransMessage> message = nullptr;
    // Process null control transport message
    spk_->OnCtrlTransMessage(message);
    // Verify message remains null
    EXPECT_EQ(nullptr, message);
}

/**
 * @tc.name: OnCtrlTransMessage_002
 * @tc.desc: Verify the OnCtrlTransMessage interface with valid AVTransMessage (OPEN_SPEAKER type).
 *           Test scenario: Create valid message with OPEN_SPEAKER type, verify type remains unchanged.
 *           Expected: Message type remains OPEN_SPEAKER after processing.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransMessage_002, TestSize.Level1)
{
    // Create valid control transport message with OPEN_SPEAKER type
    auto message = std::make_shared<AVTransMessage>();
    message->type_ = OPEN_SPEAKER;
    message->content_ = "TestContent";
    message->dstDevId_ = DEV_ID;
    
    // Process the valid control transport message
    spk_->OnCtrlTransMessage(message);
    // Verify message type remains OPEN_SPEAKER
    EXPECT_EQ(OPEN_SPEAKER, message->type_);
}

/**
 * @tc.name: OnEngineTransEvent_001
 * @tc.desc: Verify the OnEngineTransEvent interface with different engine event types
 *           (START_SUCCESS/STOP_SUCCESS/CHANNEL_CLOSED/START_FAIL).
 *           Test scenario: Process each event type, verify isTransReady_ is true for START_SUCCESS and event type is
 *           START_FAIL at end.
 *           Expected: isTransReady_ = true after START_SUCCESS; final event type = EVENT_START_FAIL.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransEvent_001, TestSize.Level1)
{
    // Initialize engine transport event with EVENT_START_SUCCESS
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    
    // Process EVENT_START_SUCCESS (verify isTransReady_ = true)
    spk_->OnEngineTransEvent(event);
    EXPECT_TRUE(spk_->isTransReady_.load());

    // Process EVENT_STOP_SUCCESS
    event.type = EventType::EVENT_STOP_SUCCESS;
    spk_->OnEngineTransEvent(event);

    // Process EVENT_CHANNEL_CLOSED
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    spk_->OnEngineTransEvent(event);

    // Process EVENT_START_FAIL (verify final event type)
    event.type = EventType::EVENT_START_FAIL;
    spk_->OnEngineTransEvent(event);
    EXPECT_EQ(EventType::EVENT_START_FAIL, event.type);
}

/**
 * @tc.name: OnEngineTransMessage_001
 * @tc.desc: Verify the OnEngineTransMessage interface with null AVTransMessage pointer.
 *           Test scenario: Pass nullptr message to OnEngineTransMessage, verify message remains null.
 *           Expected: Message pointer remains nullptr after processing.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransMessage_001, TestSize.Level1)
{
    // Initialize null engine transport message
    std::shared_ptr<AVTransMessage> message = nullptr;
    // Process null engine transport message
    spk_->OnEngineTransMessage(message);
    // Verify message remains null
    EXPECT_EQ(nullptr, message);
}

/**
 * @tc.name: OnEngineTransMessage_002
 * @tc.desc: Verify the OnEngineTransMessage interface with valid AVTransMessage (CLOSE_SPEAKER type).
 *           Test scenario: Create valid message with CLOSE_SPEAKER type, verify type remains unchanged.
 *           Expected: Message type remains CLOSE_SPEAKER after processing.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransMessage_002, TestSize.Level1)
{
    // Create valid engine transport message with CLOSE_SPEAKER type
    auto message = std::make_shared<AVTransMessage>();
    message->type_ = CLOSE_SPEAKER;
    message->content_ = "TestContent";
    message->dstDevId_ = DEV_ID;
    
    // Process the valid engine transport message
    spk_->OnEngineTransMessage(message);
    // Verify message type remains CLOSE_SPEAKER
    EXPECT_EQ(CLOSE_SPEAKER, message->type_);
}

/**
 * @tc.name: CreateStream_002
 * @tc.desc: Verify the CreateStream interface success path with speaker DH ID (DH_ID_SPK).
 *           Test scenario: Set dhId_ to DH_ID_SPK, create stream, verify success and stream ID match.
 *           Expected: CreateStream returns DH_SUCCESS; streamId_ matches input stream ID.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, CreateStream_002, TestSize.Level1)
{
    // Set distributed hardware ID to speaker device ID
    spk_->dhId_ = DH_ID_SPK;
    // Create stream with target stream ID (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(streamId_));
    // Verify internal stream ID matches input stream ID
    EXPECT_EQ(streamId_, spk_->streamId_);
}

/**
 * @tc.name: DestroyStream_002
 * @tc.desc: Verify the DestroyStream interface success path with speaker DH ID (DH_ID_SPK).
 *           Test scenario: Set dhId_/curPort_ to DH_ID_SPK, destroy stream, verify success and curPort_ reset to 0.
 *           Expected: DestroyStream returns DH_SUCCESS; curPort_ is reset to 0.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, DestroyStream_002, TestSize.Level1)
{
    // Set distributed hardware ID and current port to speaker device ID
    spk_->dhId_ = DH_ID_SPK;
    spk_->curPort_ = DH_ID_SPK;
    
    // Destroy stream with target stream ID (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(streamId_));
    // Verify current port is reset to 0 after stream destruction
    EXPECT_EQ(0, spk_->curPort_);
}

/**
 * @tc.name: SetParameters_003
 * @tc.desc: Verify SetParameters with STREAM_USAGE_VOICE_COMMUNICATION and only AAC codec supported.
 *           Test scenario: Clear codec container, add only AAC caps, set voice communication parameters.
 *           Expected: SetParameters returns DH_SUCCESS; codecType is set to AUDIO_CODEC_AAC_EN.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_003, TestSize.Level1)
{
    // Define audio parameters for voice communication (8000Hz, STEREO, SAMPLE_U8)
    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_VOICE_COMMUNICATION,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    
    // Save original codec container, clear and add only AAC codec caps
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    
    // Set voice communication parameters (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    // Verify codec type is set to AAC encoder
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_AAC_EN, spk_->param_.comParam.codecType);
}

/**
 * @tc.name: SetParameters_004
 * @tc.desc: Verify SetParameters with STREAM_USAGE_VOICE_COMMUNICATION and only OPUS codec supported.
 *           Test scenario: Clear codec container, add only OPUS caps, set voice communication parameters.
 *           Expected: SetParameters returns DH_SUCCESS; codecType is set to AUDIO_CODEC_OPUS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_004, TestSize.Level1)
{
    // Define audio parameters for voice communication (8000Hz, STEREO, SAMPLE_U8)
    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_VOICE_COMMUNICATION,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    
    // Save original codec container, clear and add only OPUS codec caps
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    
    // Set voice communication parameters (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    // Verify codec type is set to OPUS
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_OPUS, spk_->param_.comParam.codecType);
}

/**
 * @tc.name: SendMessage_002
 * @tc.desc: Verify the SendMessage interface with valid message types
 *           (CLOSE_SPEAKER/CHANGE_PLAY_STATUS/VOLUME_SET/VOLUME_MUTE_SET).
 *           Test scenario: Initialize speaker control transport, send different message types to target device.
 *           Expected: All SendMessage calls return DH_SUCCESS for valid message types.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SendMessage_002, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    
    // Initialize speaker control transport with device ID and session names
    spk_->speakerCtrlTrans_ = std::make_shared<DaudioSourceCtrlTrans>(DEV_ID,
        SESSIONNAME_SPK_SOURCE, SESSIONNAME_SPK_SINK, spk_);
    
    // Send CLOSE_SPEAKER message (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(CLOSE_SPEAKER, content, dstDevId));
    // Send CHANGE_PLAY_STATUS message (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(CHANGE_PLAY_STATUS, content, dstDevId));
    // Send VOLUME_SET message (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(VOLUME_SET, content, dstDevId));
    // Send VOLUME_MUTE_SET message (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(VOLUME_MUTE_SET, content, dstDevId));
}

/**
 * @tc.name: OnStateChange_002
 * @tc.desc: Verify the OnStateChange interface with DATA_OPENED event and speaker DH ID (DH_ID_SPK).
 *           Test scenario: Set dhId_ to DH_ID_SPK, trigger DATA_OPENED event, verify success and isTransReady_ = true.
 *           Expected: OnStateChange returns DH_SUCCESS; isTransReady_ flag is true.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_002, TestSize.Level1)
{
    // Set distributed hardware ID to speaker device ID
    spk_->dhId_ = DH_ID_SPK;
    // Process DATA_OPENED state change event (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(DATA_OPENED));
    // Verify transport ready flag is set to true
    EXPECT_TRUE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnStateChange_003
 * @tc.desc: Verify the OnStateChange interface with DATA_CLOSED event and speaker DH ID (DH_ID_SPK).
 *           Test scenario:Set isOpened_ = true & dhId_ = DH_ID_SPK, trigger DATA_CLOSED event, verify flags are reset.
 *           Expected: OnStateChange returns DH_SUCCESS; isOpened_ and isTransReady_ are false.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_003, TestSize.Level1)
{
    // Set device opened status to true and DH ID to speaker device ID
    spk_->isOpened_.store(true);
    spk_->dhId_ = DH_ID_SPK;
    
    // Process DATA_CLOSED state change event (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(DATA_CLOSED));
    // Verify device opened status is reset to false
    EXPECT_FALSE(spk_->isOpened_.load());
    // Verify transport ready status is reset to false
    EXPECT_FALSE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnStateChange_004
 * @tc.desc: Verify the OnStateChange interface with EVENT_UNKNOWN event and speaker DH ID (DH_ID_SPK).
 *           Test scenario: Set dhId_ to DH_ID_SPK, trigger EVENT_UNKNOWN event, verify success.
 *           Expected: OnStateChange returns DH_SUCCESS for unknown event type.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_004, TestSize.Level1)
{
    // Set distributed hardware ID to speaker device ID
    spk_->dhId_ = DH_ID_SPK;
    // Process EVENT_UNKNOWN state change event (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(EVENT_UNKNOWN));
}

/**
 * @tc.name: UpdateWorkModeParam_001
 * @tc.desc: Verify the UpdateWorkModeParam interface with valid device ID, DH ID and default AudioAsyncParam.
 *           Test scenario: Pass valid string IDs and empty async parameter to UpdateWorkModeParam.
 *           Expected: UpdateWorkModeParam returns DH_SUCCESS for valid input parameters.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, UpdateWorkModeParam_001, TestSize.Level1)
{
    // Define valid device ID and distributed hardware ID
    std::string devId = "devId";
    std::string dhId = "dhId";
    // Initialize default audio async parameter
    AudioAsyncParam param;
    
    // Update work mode parameters (verify success)
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam(devId, dhId, param));
}
/**
 * @tc.name: OnStateChange_005
 * @tc.desc: Verify that the OnStateChange interface can correctly handle different speaker state change events,
 *           including opening/closing speaker, speaker opened/closed status, and control channel opened/closed status.
 *           The interface is expected to return DH_SUCCESS for all valid event types.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_005, TestSize.Level1)
{
    // Set the device handle ID to speaker device ID
    spk_->dhId_ = DH_ID_SPK;

    // Verify OnStateChange with OPEN_SPEAKER event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(OPEN_SPEAKER));
    // Verify OnStateChange with CLOSE_SPEAKER event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(CLOSE_SPEAKER));
    // Verify OnStateChange with SPEAKER_OPENED event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(SPEAKER_OPENED));
    // Verify OnStateChange with SPEAKER_CLOSED event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(SPEAKER_CLOSED));
    // Verify OnStateChange with CTRL_OPENED event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(CTRL_OPENED));
    // Verify OnStateChange with CTRL_CLOSED event
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(CTRL_CLOSED));
}

/**
 * @tc.name: EnableDevice_002
 * @tc.desc: Verify the EnableDevice interface behavior when passing different invalid DH (Device Handle) IDs.
 *           The interface is expected to return ERR_DH_AUDIO_NULLPTR for all tested invalid DH IDs (0,1,2,100,1000).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, EnableDevice_002, TestSize.Level1)
{
    // Verify EnableDevice with DH ID = 0 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(0, CAP));
    // Verify EnableDevice with DH ID = 1 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(1, CAP));
    // Verify EnableDevice with DH ID = 2 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(2, CAP));
    // Verify EnableDevice with DH ID = 100 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(100, CAP));
    // Verify EnableDevice with DH ID = 1000 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(1000, CAP));
}

/**
 * @tc.name: DisableDevice_002
 * @tc.desc: Verify the DisableDevice interface behavior when passing different invalid DH (Device Handle) IDs.
 *           The interface is expected to return ERR_DH_AUDIO_NULLPTR for all tested invalid DH IDs (0,1,2,100,1000).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, DisableDevice_002, TestSize.Level1)
{
    // Verify DisableDevice with DH ID = 0 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(0));
    // Verify DisableDevice with DH ID = 1 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(1));
    // Verify DisableDevice with DH ID = 2 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(2));
    // Verify DisableDevice with DH ID = 100 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(100));
    // Verify DisableDevice with DH ID = 1000 (invalid)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(1000));
}

/**
 * @tc.name: CreateStream_003
 * @tc.desc: Verify the CreateStream interface can correctly create audio streams with different valid stream IDs.
 *           The interface is expected to return DH_SUCCESS for all tested stream IDs (0,1,2,100,1000).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, CreateStream_003, TestSize.Level1)
{
    // Verify CreateStream with stream ID = 0 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(0));
    // Verify CreateStream with stream ID = 1 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(1));
    // Verify CreateStream with stream ID = 2 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(2));
    // Verify CreateStream with stream ID = 100 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(100));
    // Verify CreateStream with stream ID = 1000 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(1000));
}

/**
 * @tc.name: DestroyStream_002
 * @tc.desc: Verify the DestroyStream interface can correctly destroy audio streams with different valid stream IDs.
 *           The interface is expected to return DH_SUCCESS for all tested stream IDs (0,1,2,100,1000).
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, DestroyStream_003, TestSize.Level1)
{
    // Verify DestroyStream with stream ID = 0 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(0));
    // Verify DestroyStream with stream ID = 1 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(1));
    // Verify DestroyStream with stream ID = 2 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(2));
    // Verify DestroyStream with stream ID = 100 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(100));
    // Verify DestroyStream with stream ID = 1000 (valid)
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(1000));
}

/**
 * @tc.name: SetParameters_005
 * @tc.desc: Verify the SetParameters interface can correctly set audio parameters with different sample rates.
 *           Test sample rates include 8000/11025/12000/16000/22050 Hz, interface should return DH_SUCCESS for all.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_005, TestSize.Level1)
{
    // Initialize audio parameter structure with base configuration
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .renderFlags = NORMAL_MODE,
        .capturerFlags = NORMAL_MODE,
        .ext = ""
    };

    // Verify SetParameters with sample rate = 8000 Hz
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update sample rate to 11025 Hz and verify
    param.sampleRate = SAMPLE_RATE_11025;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update sample rate to 12000 Hz and verify
    param.sampleRate = SAMPLE_RATE_12000;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update sample rate to 16000 Hz and verify
    param.sampleRate = SAMPLE_RATE_16000;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update sample rate to 22050 Hz and verify
    param.sampleRate = SAMPLE_RATE_22050;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
}

/**
 * @tc.name: SetParameters_006
 * @tc.desc: Verify the SetParameters interface can correctly set audio parameters with different channel masks.
 *           Test channels include MONO (single channel) and STEREO (dual channel), interface returns DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_006, TestSize.Level1)
{
    // Initialize audio parameter structure with base configuration (48000 Hz sample rate)
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = MONO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .renderFlags = NORMAL_MODE,
        .capturerFlags = NORMAL_MODE,
        .ext = ""
    };

    // Verify SetParameters with MONO channel mask
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update channel mask to STEREO and verify
    param.channelMask = STEREO;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
}

/**
 * @tc.name: SetParameters_007
 * @tc.desc: Verify the SetParameters interface can correctly set audio parameters with different bit formats.
 *           Test bit formats: SAMPLE_U8/SAMPLE_S16LE/SAMPLE_S24LE/SAMPLE_S32LE/SAMPLE_F32LE, all return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Test level: basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_007, TestSize.Level1)
{
    // Initialize audio parameter structure with base configuration (48000 Hz, STEREO)
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .renderFlags = NORMAL_MODE,
        .capturerFlags = NORMAL_MODE,
        .ext = ""
    };

    // Verify SetParameters with 8-bit unsigned integer format
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update to 16-bit signed little-endian format and verify
    param.bitFormat = SAMPLE_S16LE;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update to 24-bit signed little-endian format and verify
    param.bitFormat = SAMPLE_S24LE;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update to 32-bit signed little-endian format and verify
    param.bitFormat = SAMPLE_S32LE;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update to 32-bit float little-endian format and verify
    param.bitFormat = SAMPLE_F32LE;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
}

/**
 * @tc.name: SetParameters_008
 * @tc.desc: Verify the SetParameters interface can correctly configure audio parameters with different
 *           stream usage types.
 *           Tested stream usage types include
 *           UNKNOWN/MEDIA/VOICE_COMMUNICATION/VOICE_ASSISTANT/MMAP/NOTIFICATION_RINGTONE.
 *           The interface is expected to return DH_SUCCESS for all valid stream usage configurations.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_008, TestSize.Level1)
{
    // Initialize audio parameter structure with base configuration (48000Hz, STEREO, SAMPLE_U8)
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .renderFlags = NORMAL_MODE,
        .capturerFlags = NORMAL_MODE,
        .ext = ""
    };

    // Verify SetParameters with STREAM_USAGE_UNKNOWN
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update stream usage to STREAM_USAGE_MEDIA and verify
    param.streamUsage = STREAM_USAGE_MEDIA;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update stream usage to STREAM_USAGE_VOICE_COMMUNICATION and verify
    param.streamUsage = STREAM_USAGE_VOICE_COMMUNICATION;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update stream usage to STREAM_USAGE_VOICE_ASSISTANT and verify
    param.streamUsage = STREAM_USAGE_VOICE_ASSISTANT;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update stream usage to STREAM_USAGE_MMAP and verify
    param.streamUsage = STREAM_USAGE_MMAP;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update stream usage to STREAM_USAGE_NOTIFICATION_RINGTONE and verify
    param.streamUsage = STREAM_USAGE_NOTIFICATION_RINGTONE;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
}

/**
 * @tc.name: SetParameters_009
 * @tc.desc: Verify the SetParameters interface can correctly configure audio parameters with different frame sizes.
 *           Tested frame sizes: 10/20/40/80/160 frames, all configurations should return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SetParameters_009, TestSize.Level1)
{
    // Initialize audio parameter structure with base configuration (48000Hz, STEREO, SAMPLE_U8)
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 10,
        .period = 0,
        .renderFlags = NORMAL_MODE,
        .capturerFlags = NORMAL_MODE,
        .ext = ""
    };

    // Verify SetParameters with frame size = 10
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update frame size to 20 and verify
    param.frameSize = 20;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update frame size to 40 and verify
    param.frameSize = 40;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update frame size to 80 and verify
    param.frameSize = 80;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));

    // Update frame size to 160 and verify
    param.frameSize = 160;
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
}

/**
 * @tc.name: NotifyEvent_002
 * @tc.desc: Verify the NotifyEvent interface can correctly handle different control channel related events.
 *           Tested events: OPEN_CTRL/CLOSE_CTRL/CTRL_OPENED/CTRL_CLOSED/NOTIFY_OPEN_CTRL_RESULT.
 *           The interface should return DH_SUCCESS for all valid control events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_002, TestSize.Level1)
{
    // Verify NotifyEvent with OPEN_CTRL event
    AudioEvent event(OPEN_CTRL, "OPEN_CTRL");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CLOSE_CTRL event
    event = AudioEvent(CLOSE_CTRL, "CLOSE_CTRL");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CTRL_OPENED event
    event = AudioEvent(CTRL_OPENED, "CTRL_OPENED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CTRL_CLOSED event
    event = AudioEvent(CTRL_CLOSED, "CTRL_CLOSED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with NOTIFY_OPEN_CTRL_RESULT event
    event = AudioEvent(NOTIFY_OPEN_CTRL_RESULT, "NOTIFY_OPEN_CTRL_RESULT");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_003
 * @tc.desc: Verify the NotifyEvent interface can correctly handle different speaker related events.
 *           Tested events: OPEN_SPEAKER/CLOSE_SPEAKER/SPEAKER_OPENED/SPEAKER_CLOSED/NOTIFY_OPEN_SPEAKER_RESULT.
 *           The interface should return DH_SUCCESS for all valid speaker events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_003, TestSize.Level1)
{
    // Verify NotifyEvent with OPEN_SPEAKER event
    AudioEvent event(OPEN_SPEAKER, "OPEN_SPEAKER");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CLOSE_SPEAKER event
    event = AudioEvent(CLOSE_SPEAKER, "CLOSE_SPEAKER");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with SPEAKER_OPENED event
    event = AudioEvent(SPEAKER_OPENED, "SPEAKER_OPENED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with SPEAKER_CLOSED event
    event = AudioEvent(SPEAKER_CLOSED, "SPEAKER_CLOSED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with NOTIFY_OPEN_SPEAKER_RESULT event
    event = AudioEvent(NOTIFY_OPEN_SPEAKER_RESULT, "NOTIFY_OPEN_SPEAKER_RESULT");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_004
 * @tc.desc: Verify the NotifyEvent interface can correctly handle different microphone related events.
 *           Tested events: OPEN_MIC/CLOSE_MIC/MIC_OPENED/MIC_CLOSED/NOTIFY_OPEN_MIC_RESULT.
 *           The interface should return DH_SUCCESS for all valid microphone events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_004, TestSize.Level1)
{
    // Verify NotifyEvent with OPEN_MIC event
    AudioEvent event(OPEN_MIC, "OPEN_MIC");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CLOSE_MIC event
    event = AudioEvent(CLOSE_MIC, "CLOSE_MIC");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with MIC_OPENED event
    event = AudioEvent(MIC_OPENED, "MIC_OPENED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with MIC_CLOSED event
    event = AudioEvent(MIC_CLOSED, "MIC_CLOSED");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with NOTIFY_OPEN_MIC_RESULT event
    event = AudioEvent(NOTIFY_OPEN_MIC_RESULT, "NOTIFY_OPEN_MIC_RESULT");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_005
 * @tc.desc: Verify the NotifyEvent interface can correctly handle different volume control related events.
 *           Tested events: VOLUME_SET/VOLUME_GET/VOLUME_CHANGE/VOLUME_MIN_GET/VOLUME_MAX_GET.
 *           The interface should return DH_SUCCESS for all valid volume events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_005, TestSize.Level1)
{
    // Verify NotifyEvent with VOLUME_SET event
    AudioEvent event(VOLUME_SET, "VOLUME_SET");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with VOLUME_GET event
    event = AudioEvent(VOLUME_GET, "VOLUME_GET");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with VOLUME_CHANGE event
    event = AudioEvent(VOLUME_CHANGE, "VOLUME_CHANGE");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with VOLUME_MIN_GET event
    event = AudioEvent(VOLUME_MIN_GET, "VOLUME_MIN_GET");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with VOLUME_MAX_GET event
    event = AudioEvent(VOLUME_MAX_GET, "VOLUME_MAX_GET");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_006
 * @tc.desc: Verify the NotifyEvent interface can correctly handle audio focus and render state change events.
 *           Tested events: AUDIO_FOCUS_CHANGE/AUDIO_RENDER_STATE_CHANGE/CHANGE_PLAY_STATUS.
 *           The interface should return DH_SUCCESS for all valid focus/render events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_006, TestSize.Level1)
{
    // Verify NotifyEvent with AUDIO_FOCUS_CHANGE event
    AudioEvent event(AUDIO_FOCUS_CHANGE, "AUDIO_FOCUS_CHANGE");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with AUDIO_RENDER_STATE_CHANGE event
    event = AudioEvent(AUDIO_RENDER_STATE_CHANGE, "AUDIO_RENDER_STATE_CHANGE");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with CHANGE_PLAY_STATUS event
    event = AudioEvent(CHANGE_PLAY_STATUS, "CHANGE_PLAY_STATUS");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_007
 * @tc.desc: Verify the NotifyEvent interface can correctly handle memory-mapped (mmap) audio stream events.
 *           Tested events: MMAP_SPK_START/MMAP_SPK_STOP/MMAP_MIC_START/MMAP_MIC_STOP.
 *           The interface should return DH_SUCCESS for all valid mmap events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_007, TestSize.Level1)
{
    // Verify NotifyEvent with MMAP_SPK_START event
    AudioEvent event(MMAP_SPK_START, "MMAP_SPK_START");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with MMAP_SPK_STOP event
    event = AudioEvent(MMAP_SPK_STOP, "MMAP_SPK_STOP");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with MMAP_MIC_START event
    event = AudioEvent(MMAP_MIC_START, "MMAP_MIC_START");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with MMAP_MIC_STOP event
    event = AudioEvent(MMAP_MIC_STOP, "MMAP_MIC_STOP");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_008
 * @tc.desc: Verify the NotifyEvent interface can correctly handle audio encoder/decoder error events.
 *           Tested events: AUDIO_ENCODER_ERR/AUDIO_DECODER_ERR.
 *           The interface should return DH_SUCCESS for both error notification events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_008, TestSize.Level1)
{
    // Verify NotifyEvent with AUDIO_ENCODER_ERR event
    AudioEvent event(AUDIO_ENCODER_ERR, "AUDIO_ENCODER_ERR");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with AUDIO_DECODER_ERR event
    event = AudioEvent(AUDIO_DECODER_ERR, "AUDIO_DECODER_ERR");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_009
 * @tc.desc: Verify the NotifyEvent interface can correctly handle audio parameter related events.
 *           Tested events: SET_PARAM/SEND_PARAM.
 *           The interface should return DH_SUCCESS for both parameter events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_009, TestSize.Level1)
{
    // Verify NotifyEvent with SET_PARAM event
    AudioEvent event(SET_PARAM, "SET_PARAM");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with SEND_PARAM event
    event = AudioEvent(SEND_PARAM, "SEND_PARAM");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_010
 * @tc.desc: Verify the NotifyEvent interface can correctly handle audio dump related events.
 *           Tested events: NOTIFY_HDF_SPK_DUMP/NOTIFY_HDF_MIC_DUMP.
 *           The interface should return DH_SUCCESS for both dump events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_010, TestSize.Level1)
{
    // Verify NotifyEvent with NOTIFY_HDF_SPK_DUMP event
    AudioEvent event(NOTIFY_HDF_SPK_DUMP, "NOTIFY_HDF_SPK_DUMP");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with NOTIFY_HDF_MIC_DUMP event
    event = AudioEvent(NOTIFY_HDF_MIC_DUMP, "NOTIFY_HDF_MIC_DUMP");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: NotifyEvent_011
 * @tc.desc: Verify the NotifyEvent interface can correctly handle audio start/stop control events.
 *           Tested events: AUDIO_START/AUDIO_STOP.
 *           The interface should return DH_SUCCESS for both start/stop events.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyEvent_011, TestSize.Level1)
{
    // Verify NotifyEvent with AUDIO_START event
    AudioEvent event(AUDIO_START, "AUDIO_START");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));

    // Verify NotifyEvent with AUDIO_STOP event
    event = AudioEvent(AUDIO_STOP, "AUDIO_STOP");
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: Stop_003
 * @tc.desc: Verify the Stop interface can be called multiple times consecutively and return DH_SUCCESS each time.
 *           Test scenario: Call Stop function three times in sequence to verify idempotency.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Stop_003, TestSize.Level1)
{
    // First call to Stop function
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    // Second call to Stop function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
    // Third call to Stop function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->Stop());
}

/**
 * @tc.name: Release_002
 * @tc.desc: Verify the Release interface can be called multiple times consecutively and return DH_SUCCESS each time.
 *           Test scenario: Call Release function three times in sequence to verify idempotency.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, Release_002, TestSize.Level1)
{
    // First call to Release function
    EXPECT_EQ(DH_SUCCESS, spk_->Release());
    // Second call to Release function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->Release());
    // Third call to Release function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->Release());
}

/**
 * @tc.name: IsOpened_002
 * @tc.desc: Verify the IsOpened interface returns false consistently when the speaker device is not opened.
 *           Test scenario: Call IsOpened three times to verify stable return value in closed state.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, IsOpened_002, TestSize.Level1)
{
    // First call to IsOpened (device closed)
    EXPECT_FALSE(spk_->IsOpened());
    // Second call to IsOpened (device closed)
    EXPECT_FALSE(spk_->IsOpened());
    // Third call to IsOpened (device closed)
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: MmapStop_002
 * @tc.desc: Verify the MmapStop interface can be called multiple times consecutively and return DH_SUCCESS each time.
 *           Test scenario: Call MmapStop function three times in sequence to verify idempotency.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, MmapStop_002, TestSize.Level1)
{
    // First call to MmapStop function
    EXPECT_EQ(DH_SUCCESS, spk_->MmapStop());
    // Second call to MmapStop function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->MmapStop());
    // Third call to MmapStop function (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->MmapStop());
}

/**
 * @tc.name: ReadMmapPosition_002
 * @tc.desc: Verify the ReadMmapPosition interface can correctly read mmap position with different stream IDs.
 *           Tested stream IDs: current stream ID/0/1/100, all should return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, ReadMmapPosition_002, TestSize.Level1)
{
    // Initialize mmap position parameters (frames count and timestamp)
    uint64_t frames = 0;
    CurrentTimeHDF time = {0, 0};

    // Verify ReadMmapPosition with current stream ID
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(streamId_, frames, time));
    // Verify ReadMmapPosition with stream ID = 0
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(0, frames, time));
    // Verify ReadMmapPosition with stream ID = 1
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(1, frames, time));
    // Verify ReadMmapPosition with stream ID = 100
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(100, frames, time));
}

/**
 * @tc.name: RefreshAshmemInfo_002
 * @tc.desc: Verify the RefreshAshmemInfo interface can correctly handle different sets of ashmem parameters.
 *           Tested parameters include (0,0,0), (1,100,10), (10,1000,100) with current stream ID,
 *           and (5,500,50)/(15,1500,150) with stream ID 0/1. All cases should return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, RefreshAshmemInfo_002, TestSize.Level1)
{
    // Verify RefreshAshmemInfo with (streamId_, 0, 0, 0)
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId_, 0, 0, 0));
    // Verify RefreshAshmemInfo with (streamId_, 1, 100, 10)
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId_, 1, 100, 10));
    // Verify RefreshAshmemInfo with (streamId_, 10, 1000, 100)
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId_, 10, 1000, 100));
    // Verify RefreshAshmemInfo with (0, 5, 500, 50)
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(0, 5, 500, 50));
    // Verify RefreshAshmemInfo with (1, 15, 1500, 150)
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(1, 15, 1500, 150));
}

/**
 * @tc.name: UpdateWorkModeParam_002
 * @tc.desc: Verify the UpdateWorkModeParam interface can correctly handle different device/DH ID combinations.
 *           Tested IDs: "dev1"/"dh1", "dev2"/"dh2", empty strings, long ID strings. All return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, UpdateWorkModeParam_002, TestSize.Level1)
{
    // Initialize audio async parameter structure
    AudioAsyncParam param;

    // Verify UpdateWorkModeParam with "dev1"/"dh1"
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam("dev1", "dh1", param));
    // Verify UpdateWorkModeParam with "dev2"/"dh2"
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam("dev2", "dh2", param));
    // Verify UpdateWorkModeParam with empty device/DH IDs
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam("", "", param));
    // Verify UpdateWorkModeParam with long device/DH IDs
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam("long_device_id", "long_dh_id", param));
}

/**
 * @tc.name: GetAudioParam_002
 * @tc.desc: Verify the GetAudioParam interface returns audio parameters with expected default values.
 *           Expected values: sample rate = 8000Hz, channel mask = MONO, bit format = SAMPLE_U8.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, GetAudioParam_002, TestSize.Level1)
{
    // Get audio parameters from speaker device
    AudioParam param = spk_->GetAudioParam();

    // Verify sample rate is 8000Hz
    EXPECT_EQ(param.comParam.sampleRate, SAMPLE_RATE_8000);
    // Verify channel mask is MONO
    EXPECT_EQ(param.comParam.channelMask, MONO);
    // Verify bit format is SAMPLE_U8
    EXPECT_EQ(param.comParam.bitFormat, SAMPLE_U8);
}

/**
 * @tc.name: NotifyHdfAudioEvent_002
 * @tc.desc: Verify the NotifyHdfAudioEvent interface can handle different integer parameters with unknown event.
 *           Tested parameters: 0/1/100/1000, all should return DH_SUCCESS for EVENT_UNKNOWN.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, NotifyHdfAudioEvent_002, TestSize.Level1)
{
    // Initialize audio event with EVENT_UNKNOWN type
    AudioEvent event(EVENT_UNKNOWN, "test");

    // Verify NotifyHdfAudioEvent with parameter = 0
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, 0));
    // Verify NotifyHdfAudioEvent with parameter = 1
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, 1));
    // Verify NotifyHdfAudioEvent with parameter = 100
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, 100));
    // Verify NotifyHdfAudioEvent with parameter = 1000
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event, 1000));
}

/**
 * @tc.name: OnDecodeTransDataDone_002
 * @tc.desc: Verify the OnDecodeTransDataDone interface returns DH_SUCCESS when passing null audio data pointer.
 *           Test scenario: Call three times consecutively to verify idempotency with null pointer.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, OnDecodeTransDataDone_002, TestSize.Level1)
{
    // Initialize null audio data shared pointer
    std::shared_ptr<AudioData> audioData = nullptr;

    // First call to OnDecodeTransDataDone with null data
    EXPECT_EQ(DH_SUCCESS, spk_->OnDecodeTransDataDone(audioData));
    // Second call (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->OnDecodeTransDataDone(audioData));
    // Third call (verify idempotency)
    EXPECT_EQ(DH_SUCCESS, spk_->OnDecodeTransDataDone(audioData));
}

/**
 * @tc.name: WriteStreamData_004
 * @tc.desc: Verify the WriteStreamData interface returns ERR_DH_AUDIO_NULLPTR when passing null audio data pointer.
 *           Tested stream IDs: current stream ID/0/1/100, all return null pointer error.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, WriteStreamData_004, TestSize.Level1)
{
    // Initialize null audio data shared pointer
    std::shared_ptr<AudioData> data = nullptr;

    // Verify WriteStreamData with current stream ID (null data)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(streamId_, data));
    // Verify WriteStreamData with stream ID = 0 (null data)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(0, data));
    // Verify WriteStreamData with stream ID = 1 (null data)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(1, data));
    // Verify WriteStreamData with stream ID = 100 (null data)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->WriteStreamData(100, data));
}

/**
 * @tc.name: SimpleParameterTests_001
 * @tc.desc: Verify CreateStream/DestroyStream interfaces with different valid stream IDs (0/1/10/100/1000).
 *           All CreateStream/DestroyStream calls should return DH_SUCCESS for valid IDs.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_001, TestSize.Level1)
{
    // Test CreateStream/DestroyStream with stream ID = 0
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(0));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(0));

    // Test CreateStream/DestroyStream with stream ID = 1
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(1));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(1));

    // Test CreateStream/DestroyStream with stream ID = 10
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(10));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(10));

    // Test CreateStream/DestroyStream with stream ID = 100
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(100));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(100));

    // Test CreateStream/DestroyStream with stream ID = 1000
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(1000));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(1000));
}

/**
 * @tc.name: SimpleParameterTests_002
 * @tc.desc: Verify EnableDevice/DisableDevice interfaces with different invalid DH IDs (0/1/10/100/1000).
 *           All calls should return ERR_DH_AUDIO_NULLPTR for invalid DH IDs.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_002, TestSize.Level1)
{
    // Test EnableDevice/DisableDevice with DH ID = 0
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(0, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(0));

    // Test EnableDevice/DisableDevice with DH ID = 1
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(1, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(1));

    // Test EnableDevice/DisableDevice with DH ID = 10
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(10, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(10));

    // Test EnableDevice/DisableDevice with DH ID = 100
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(100, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(100));

    // Test EnableDevice/DisableDevice with DH ID = 1000
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(1000, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(1000));
}

/**
 * @tc.name: SimpleParameterTests_003
 * @tc.desc: Verify RefreshAshmemInfo interface with incremental ashmem parameters (loop 20 times).
 *           Parameters: fd = i, ashmemLength = 100+100i, lengthPerTrans = 10+10i. All return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_003, TestSize.Level1)
{
    // Loop to test incremental ashmem parameters (20 iterations)
    for (int i = 0; i < 20; i++) {
        int fd = i;
        int ashmemLength = 100 + i * 100;
        int lengthPerTrans = 10 + i * 10;
        EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(streamId_, fd, ashmemLength, lengthPerTrans));
    }
}

/**
 * @tc.name: SimpleParameterTests_004
 * @tc.desc: Verify ReadMmapPosition interface with incremental mmap position parameters (loop 20 times).
 *           Parameters: frames = 100i, time = (10i, 100i). All return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_004, TestSize.Level1)
{
    // Loop to test incremental mmap position parameters (20 iterations)
    for (int i = 0; i < 20; i++) {
        uint64_t frames = i * 100;
        CurrentTimeHDF time = {i * 10, i * 100};
        EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(streamId_, frames, time));
    }
}

/**
 * @tc.name: SimpleParameterTests_016
 * @tc.desc: Verify audio interfaces with negative parameter values (-1).
 *           Enable/DisableDevice return ERR_DH_AUDIO_NULLPTR; others return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_016, TestSize.Level1)
{
    // Test EnableDevice/DisableDevice with DH ID = -1 (negative value)
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(-1, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(-1));

    // Test CreateStream/DestroyStream with stream ID = -1 (negative value)
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(-1));
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(-1));

    // Initialize time with negative values and test ReadMmapPosition
    CurrentTimeHDF time = {-1, -1};
    uint64_t frames = 0;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(-1, frames, time));

    // Test RefreshAshmemInfo with all negative parameters
    EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(-1, -1, -1, -1));
}

/**
 * @tc.name: SimpleParameterTests_017
 * @tc.desc: Verify audio interfaces with large integer parameter values (1000000+100000i, loop 10 times).
 *           Enable/DisableDevice return ERR_DH_AUDIO_NULLPTR; others return DH_SUCCESS.
 * @tc.type: FUNC (Functional Test)
 * @tc.require: AR000H0E5F (Dependency requirement ID)
 * @tc.level: Level1 (Basic function verification)
 */
HWTEST_F(DSpeakerDevTest, SimpleParameterTests_017, TestSize.Level1)
{
    // Loop to test large parameter values (10 iterations)
    for (int i = 0; i < 10; i++) {
        int largeValue = 1000000 + i * 100000;

        // Test EnableDevice/DisableDevice with large DH ID
        EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->EnableDevice(largeValue, CAP));
        EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->DisableDevice(largeValue));

        // Test CreateStream/DestroyStream with large stream ID
        EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(largeValue));
        EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(largeValue));

        // Test ReadMmapPosition with large parameters
        CurrentTimeHDF time = {largeValue, largeValue};
        uint64_t frames = largeValue;
        EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(largeValue, frames, time));

        // Test RefreshAshmemInfo with all large parameters
        EXPECT_EQ(DH_SUCCESS, spk_->RefreshAshmemInfo(largeValue, largeValue, largeValue, largeValue));
    }
}
} // namespace DistributedHardware
} // namespace OHOS
