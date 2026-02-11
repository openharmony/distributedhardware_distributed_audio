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
 * @tc.name: InitReceiverEngine_001
 * @tc.desc: Verify InitReceiverEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, InitReceiverEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->InitReceiverEngine(providerPtr));;
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
 * @tc.name: SetParameters_002
 * @tc.desc: Verify SetParameters and GetAudioParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
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
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    auto ret = spk_->SetParameters(streamId_, param);
    spk_->GetAudioParam();
    spk_->codec_ = container;
    EXPECT_EQ(DH_SUCCESS, ret);
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
HWTEST_F(DSpeakerDevTest, ReadMmapPosition_001, TestSize.Level1)
{
    int32_t streamId = 0;
    uint64_t frames = 0;
    CurrentTimeHDF time;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadMmapPosition(streamId, frames, time));
}

/**
 * @tc.name: MmapStart_001
 * @tc.desc: Verify MmapStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, MmapStart_001, TestSize.Level1)
{
    spk_->ashmem_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, spk_->MmapStart());
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
    spk_->InitCtrlTrans();
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(OPEN_SPEAKER, content, dstDevId));
}

/**
 * @tc.name: AddToVec_001
 * @tc.desc: Verify AddToVec function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, AddToVec_001, TestSize.Level1)
{
    std::vector<AudioCodecType> container;
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
}

/**
 * @tc.name: GetCodecCaps_001
 * @tc.desc: Verify GetCodecCaps function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, GetCodecCaps_001, TestSize.Level1)
{
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    auto num = spk_->codec_.size();
    EXPECT_EQ(1, num);
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    num = spk_->codec_.size();
    spk_->codec_ = container;
    EXPECT_EQ(2, num);
}

/**
 * @tc.name: IsMimeSupported_001
 * @tc.desc: Verify IsMimeSupported function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, IsMimeSupported_001, TestSize.Level1)
{
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    bool ret = spk_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_AAC_EN);
    EXPECT_EQ(ret, true);
    ret = spk_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_OPUS);
    spk_->codec_ = container;
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetCodecCaps_002
 * @tc.desc: Verify GetCodecCaps with empty capability.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, GetCodecCaps_002, TestSize.Level1)
{
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps("EmptyCapability");
    spk_->codec_ = container;
    EXPECT_EQ(0, spk_->codec_.size());
}

/**
 * @tc.name: AddToVec_002
 * @tc.desc: Verify AddToVec with duplicate value.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, AddToVec_002, TestSize.Level1)
{
    std::vector<AudioCodecType> container;
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
    spk_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    EXPECT_EQ(1, container.size());
}

/**
 * @tc.name: OnCtrlTransEvent_001
 * @tc.desc: Verify OnCtrlTransEvent with EVENT_START_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_001, TestSize.Level1)
{
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_TRUE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_002
 * @tc.desc: Verify OnCtrlTransEvent with EVENT_STOP_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_002, TestSize.Level1)
{
    spk_->isOpened_.store(true);
    AVTransEvent event = { EventType::EVENT_STOP_SUCCESS, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_003
 * @tc.desc: Verify OnCtrlTransEvent with EVENT_CHANNEL_CLOSED.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_003, TestSize.Level1)
{
    spk_->isOpened_.store(true);
    AVTransEvent event = { EventType::EVENT_CHANNEL_CLOSED, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransEvent_004
 * @tc.desc: Verify OnCtrlTransEvent with EVENT_START_FAIL.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransEvent_004, TestSize.Level1)
{
    spk_->isOpened_.store(true);
    AVTransEvent event = { EventType::EVENT_START_FAIL, "", "" };
    spk_->OnCtrlTransEvent(event);
    EXPECT_FALSE(spk_->isOpened_.load());
}

/**
 * @tc.name: OnCtrlTransMessage_001
 * @tc.desc: Verify OnCtrlTransMessage with nullptr message.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransMessage_001, TestSize.Level1)
{
    std::shared_ptr<AVTransMessage> message = nullptr;
    spk_->OnCtrlTransMessage(message);
    EXPECT_EQ(nullptr, message);
}

/**
 * @tc.name: OnCtrlTransMessage_002
 * @tc.desc: Verify OnCtrlTransMessage with valid message.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnCtrlTransMessage_002, TestSize.Level1)
{
    auto message = std::make_shared<AVTransMessage>();
    message->type_ = OPEN_SPEAKER;
    message->content_ = "TestContent";
    message->dstDevId_ = DEV_ID;
    spk_->OnCtrlTransMessage(message);
    EXPECT_EQ(OPEN_SPEAKER, message->type_);
}

/**
 * @tc.name: OnEngineTransEvent_001
 * @tc.desc: Verify OnEngineTransEvent with different event types.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransEvent_001, TestSize.Level1)
{
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    spk_->OnEngineTransEvent(event);
    EXPECT_TRUE(spk_->isTransReady_.load());

    event.type = EventType::EVENT_STOP_SUCCESS;
    spk_->OnEngineTransEvent(event);

    event.type = EventType::EVENT_CHANNEL_CLOSED;
    spk_->OnEngineTransEvent(event);

    event.type = EventType::EVENT_START_FAIL;
    spk_->OnEngineTransEvent(event);
    EXPECT_EQ(EventType::EVENT_START_FAIL, event.type);
}

/**
 * @tc.name: OnEngineTransMessage_001
 * @tc.desc: Verify OnEngineTransMessage with nullptr message.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransMessage_001, TestSize.Level1)
{
    std::shared_ptr<AVTransMessage> message = nullptr;
    spk_->OnEngineTransMessage(message);
    EXPECT_EQ(nullptr, message);
}

/**
 * @tc.name: OnEngineTransMessage_002
 * @tc.desc: Verify OnEngineTransMessage with valid message.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnEngineTransMessage_002, TestSize.Level1)
{
    auto message = std::make_shared<AVTransMessage>();
    message->type_ = CLOSE_SPEAKER;
    message->content_ = "TestContent";
    message->dstDevId_ = DEV_ID;
    spk_->OnEngineTransMessage(message);
    EXPECT_EQ(CLOSE_SPEAKER, message->type_);
}

/**
 * @tc.name: CreateStream_002
 * @tc.desc: Verify CreateStream success path.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, CreateStream_002, TestSize.Level1)
{
    spk_->dhId_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->CreateStream(streamId_));
    EXPECT_EQ(streamId_, spk_->streamId_);
}

/**
 * @tc.name: DestroyStream_002
 * @tc.desc: Verify DestroyStream success path.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, DestroyStream_002, TestSize.Level1)
{
    spk_->dhId_ = DH_ID_SPK;
    spk_->curPort_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->DestroyStream(streamId_));
    EXPECT_EQ(0, spk_->curPort_);
}

/**
 * @tc.name: SetParameters_003
 * @tc.desc: Verify SetParameters with STREAM_USAGE_VOICE_COMMUNICATION and OPUS not supported.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SetParameters_003, TestSize.Level1)
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
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::AAC);
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_AAC_EN, spk_->param_.comParam.codecType);
}

/**
 * @tc.name: SetParameters_004
 * @tc.desc: Verify SetParameters with STREAM_USAGE_VOICE_COMMUNICATION and OPUS supported.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SetParameters_004, TestSize.Level1)
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
    std::vector<AudioCodecType> container = spk_->codec_;
    spk_->codec_.clear();
    spk_->GetCodecCaps(OHOS::DistributedHardware::OPUS);
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(streamId_, param));
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_OPUS, spk_->param_.comParam.codecType);
}

/**
 * @tc.name: SendMessage_002
 * @tc.desc: Verify SendMessage with valid message types.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, SendMessage_002, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    spk_->speakerCtrlTrans_ = std::make_shared<DaudioSourceCtrlTrans>(DEV_ID,
        SESSIONNAME_SPK_SOURCE, SESSIONNAME_SPK_SINK, spk_);
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(CLOSE_SPEAKER, content, dstDevId));
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(CHANGE_PLAY_STATUS, content, dstDevId));
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(VOLUME_SET, content, dstDevId));
    EXPECT_EQ(DH_SUCCESS, spk_->SendMessage(VOLUME_MUTE_SET, content, dstDevId));
}

/**
 * @tc.name: OnStateChange_002
 * @tc.desc: Verify OnStateChange with DATA_OPENED.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_002, TestSize.Level1)
{
    spk_->dhId_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(DATA_OPENED));
    EXPECT_TRUE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnStateChange_003
 * @tc.desc: Verify OnStateChange with DATA_CLOSED.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_003, TestSize.Level1)
{
    spk_->isOpened_.store(true);
    spk_->dhId_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(DATA_CLOSED));
    EXPECT_FALSE(spk_->isOpened_.load());
    EXPECT_FALSE(spk_->isTransReady_.load());
}

/**
 * @tc.name: OnStateChange_004
 * @tc.desc: Verify OnStateChange with EVENT_UNKNOWN.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OnStateChange_004, TestSize.Level1)
{
    spk_->dhId_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->OnStateChange(EVENT_UNKNOWN));
}

/**
 * @tc.name: UpdateWorkModeParam_001
 * @tc.desc: Verify UpdateWorkModeParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, UpdateWorkModeParam_001, TestSize.Level1)
{
    std::string devId = "devId";
    std::string dhId = "dhId";
    AudioAsyncParam param;
    EXPECT_EQ(DH_SUCCESS, spk_->UpdateWorkModeParam(devId, dhId, param));
}
} // namespace DistributedHardware
} // namespace OHOS
