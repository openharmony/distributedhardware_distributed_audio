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

#include "dspeaker_dev_test.h"

#include "audio_encode_transport.h"

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
    std::shared_ptr<AVTransMessage> message = nullptr;
    spk_->OnEngineTransMessage(message);
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, spk_->InitSenderEngine(providerPtr));
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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, spk_->EnableDSpeaker(DH_ID, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_HDI_PROXY_NOT_INIT, spk_->EnableDevice(DH_ID, CAP));

    spk_->enabledPorts_.insert(DH_ID_SPK);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_PROXY_NOT_INIT, spk_->EnableDSpeaker(DH_ID_SPK, CAP));
}

/**
 * @tc.name: DisableDSpeaker_001
 * @tc.desc: Verify DisableDSpeaker and DisableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, DisableDSpeaker_001, TestSize.Level1)
{
    spk_->enabledPorts_.insert(DH_ID);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_PROXY_NOT_INIT, spk_->DisableDevice(DH_ID));

    EXPECT_EQ(ERR_DH_AUDIO_HDI_PROXY_NOT_INIT, spk_->DisableDSpeaker(DH_ID));

    spk_->curPort_ = DH_ID_SPK;
    EXPECT_EQ(ERR_DH_AUDIO_HDI_PROXY_NOT_INIT, spk_->DisableDSpeaker(DH_ID_SPK));
    EXPECT_FALSE(spk_->IsOpened());
}

/**
 * @tc.name: OpenDevice_001
 * @tc.desc: Verify OpenDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, OpenDevice_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, spk_->OpenDevice(DEV_ID, DH_ID));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL, spk_->OpenDevice(DEV_ID, DH_ID));
}

/**
 * @tc.name: CloseDevice_001
 * @tc.desc: Verify CloseDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DSpeakerDevTest, CloseDevice_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, spk_->CloseDevice(DEV_ID, DH_ID));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL, spk_->CloseDevice(DEV_ID, DH_ID));
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
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(DEV_ID, DH_ID, param));
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
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(DEV_ID, DH_ID, event));

    event.type = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyEvent(DEV_ID, DH_ID, event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL, spk_->NotifyEvent(DEV_ID, DH_ID, event));
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
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, spk_->SetUp());

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
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL, spk_->Start());

    spk_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);
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
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, spk_->SetUp());
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_CHANNEL_WAIT_TIMEOUT, spk_->Start());

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
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, spk_->SetUp());
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
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, spk_->SetUp());
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL, spk_->Pause());

    spk_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL, spk_->Restart());

    const AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    EXPECT_EQ(DH_SUCCESS, spk_->SetParameters(DEV_ID, DH_ID, param));
    spk_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);
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

    spk_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);
    EXPECT_EQ(DH_SUCCESS, spk_->Release());

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->Release());
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL, spk_->WriteStreamData(DEV_ID, DH_ID, writeData));

    std::shared_ptr<AudioData> readData = nullptr;
    EXPECT_EQ(DH_SUCCESS, spk_->ReadStreamData(DEV_ID, DH_ID, readData));

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
    spk_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, spk_->WriteStreamData(DEV_ID, DH_ID, writeData));

    spk_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, spk_->WriteStreamData(DEV_ID, DH_ID, writeData));
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
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event));

    event.type = SPEAKER_OPENED;
    spk_->curPort_ = DH_ID_SPK;
    EXPECT_EQ(DH_SUCCESS, spk_->NotifyHdfAudioEvent(event));
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL, spk_->OnStateChange(event));
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
