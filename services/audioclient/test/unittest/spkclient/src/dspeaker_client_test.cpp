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

#include "dspeaker_client_test.h"

#include <thread>
#include <chrono>

#include "av_trans_types.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DSpeakerClientTest::SetUpTestCase(void) {}

void DSpeakerClientTest::TearDownTestCase(void) {}

void DSpeakerClientTest::SetUp()
{
    std::string devId = "hello";
    const int32_t dhId = 1;
    clientCallback_ = std::make_shared<MockIAudioEventCallback>();
    speakerClient_ = std::make_shared<DSpeakerClient>(devId, dhId, clientCallback_);
    speakerClient_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();

    audioParam_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    audioParam_.comParam.sampleRate = AudioSampleRate::SAMPLE_RATE_48000;
    audioParam_.comParam.bitFormat = AudioSampleFormat::SAMPLE_S16LE;
    audioParam_.comParam.channelMask = AudioChannel::STEREO;
    audioParam_.renderOpts.contentType = ContentType::CONTENT_TYPE_MUSIC;
    audioParam_.renderOpts.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
}

void DSpeakerClientTest::TearDown()
{
    speakerClient_ = nullptr;
    clientCallback_ = nullptr;
}

/**
 * @tc.name: InitReceiverEngine_001
 * @tc.desc: Verify the InitReceiverEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, InitReceiverEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;

    AVTransEvent event1 = { EventType::EVENT_START_SUCCESS, "", ""};
    speakerClient_->OnEngineTransEvent(event1);
    AVTransEvent event2 = { EventType::EVENT_STOP_SUCCESS, "", ""};
    speakerClient_->OnEngineTransEvent(event2);
    auto message = std::make_shared<AVTransMessage>();
    speakerClient_->OnEngineTransMessage(message);
    auto data = std::make_shared<AudioData>(4096);
    speakerClient_->OnEngineTransDataAvailable(data);
    EXPECT_EQ(DH_SUCCESS, speakerClient_->InitReceiverEngine(providerPtr));
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify the OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, OnStateChange_001, TestSize.Level1)
{
    AudioStandard::VolumeEvent event;
    event.volume = 1;
    event.updateUi = 1;
    event.volumeGroupId = 1;

    speakerClient_->OnVolumeKeyEvent(event);
    EXPECT_EQ(DH_SUCCESS, speakerClient_->OnStateChange(AudioEventType::DATA_OPENED));
    EXPECT_EQ(DH_SUCCESS, speakerClient_->OnStateChange(AudioEventType::DATA_CLOSED));
    EXPECT_NE(DH_SUCCESS, speakerClient_->OnStateChange(AudioEventType::SPEAKER_OPENED));
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, speakerClient_->OnStateChange(AudioEventType::EVENT_UNKNOWN));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, SetUp_001, TestSize.Level1)
{
    AudioParam audioParam;
    EXPECT_EQ(DH_SUCCESS, speakerClient_->SetUp(audioParam));
    EXPECT_EQ(DH_SUCCESS, speakerClient_->SetUp(audioParam_));
    speakerClient_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->SetUp(audioParam));
    EXPECT_EQ(DH_SUCCESS, speakerClient_->Release());
    speakerClient_->clientStatus_ = AudioStatus::STATUS_READY;
    EXPECT_EQ(DH_SUCCESS, speakerClient_->Release());
}

/**
 * @tc.name: StartRender_001
 * @tc.desc: Verify the StartRender and StopRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, StartRender001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, speakerClient_->StartRender());
    EXPECT_NE(DH_SUCCESS, speakerClient_->StopRender());

    speakerClient_->clientStatus_ = STATUS_START;
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, speakerClient_->StartRender());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->StopRender());
    speakerClient_->isRenderReady_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->StopRender());
    speakerClient_->CreateAudioRenderer(audioParam_);
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_RENDER_STOP_FAILED, speakerClient_->StopRender());
}

/**
 * @tc.name: StopRender_001
 * @tc.desc: Verify the StopRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, StopRender001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, speakerClient_->StopRender());
    std::string args = "args";
    AudioEvent event;
    speakerClient_->isRenderReady_ = true;
    speakerClient_->FlushJitterQueue();
    speakerClient_->PlayStatusChange(args);
    speakerClient_->SetAudioParameters(event);
    speakerClient_->SetMute(event);
    for (size_t i = 0; i < 10; i++) {
        std::shared_ptr<AudioData> data = std::make_shared<AudioData>(4096);
        speakerClient_->dataQueue_.push(data);
    }
    args = "restart";
    speakerClient_->PlayStatusChange(args);

    if (speakerClient_->renderDataThread_.joinable()) {
        speakerClient_->isRenderReady_.store(false);
        speakerClient_->renderDataThread_.join();
    }
    event.content = "AUDIO_VOLUME_TYPE=2;";
    auto ret = speakerClient_->SetAudioParameters(event);
    EXPECT_NE(DH_SUCCESS, ret);
}

/**
 * @tc.name: OnDecodeTransDataDone_001
 * @tc.desc: Verify the OnDecodeTransDataDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, OnDecodeTransDataDone001, TestSize.Level1)
{
    std::shared_ptr<AudioData> audioData = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->OnDecodeTransDataDone(audioData));
    for (size_t i = 0; i < 11; i++) {
        std::shared_ptr<AudioData> data = std::make_shared<AudioData>(4096);
        speakerClient_->dataQueue_.push(data);
    }
    audioData = std::make_shared<AudioData>(4096);
    EXPECT_EQ(DH_SUCCESS, speakerClient_->OnDecodeTransDataDone(audioData));
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify the Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, Release001, TestSize.Level1)
{
    speakerClient_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    std::string args = "{\"ChangeType\":\"restart\"}";
    speakerClient_->PlayStatusChange(args);
    args = "{\"ChangeType\":\"pause\"}";
    speakerClient_->PlayStatusChange(args);
    speakerClient_->Pause();
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, speakerClient_->Release());
}

/**
 * @tc.name: GetVolumeLevel_001
 * @tc.desc: Verify the GetVolumeLevel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, GetVolumeLevel_001, TestSize.Level1)
{
    AudioStandard::InterruptEvent eventType = {static_cast<AudioStandard::InterruptType>(1),
        static_cast<AudioStandard::InterruptForceType>(0), static_cast<AudioStandard::InterruptHint>(0)};
    speakerClient_->OnInterrupt(eventType);

    std::string volEvent = speakerClient_->GetVolumeLevel();
    EXPECT_NE("", volEvent);
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify the SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DSpeakerClientTest, SendMessage_001, TestSize.Level1)
{
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    audioParam_.renderOpts.renderFlags = MMAP_MODE;
    speakerClient_->speakerTrans_ = std::make_shared<MockIAudioDataTransport>();
    speakerClient_->Pause();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->SendMessage(EVENT_UNKNOWN, content, dstDevId));
    EXPECT_EQ(DH_SUCCESS, speakerClient_->SendMessage(NOTIFY_OPEN_SPEAKER_RESULT, content, dstDevId));
    speakerClient_->speakerTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, speakerClient_->SendMessage(NOTIFY_OPEN_SPEAKER_RESULT, content, dstDevId));
}
} // DistributedHardware
} // OHOS
