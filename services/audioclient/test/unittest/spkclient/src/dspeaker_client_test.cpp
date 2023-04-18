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

#include <thread>
#include <chrono>
#include "dspeaker_client_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DSpeakerClientTest::SetUpTestCase(void) {}

void DSpeakerClientTest::TearDownTestCase(void) {}

void DSpeakerClientTest::SetUp()
{
    std::string devId = "hello";
    clientCallback_ = std::make_shared<MockIAudioEventCallback>();
    speakerClient_ = std::make_shared<DSpeakerClient>(devId, clientCallback_);
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
    EXPECT_EQ(DH_SUCCESS, speakerClient_->OnStateChange(AudioEventType::DATA_CLOSED));
    EXPECT_NE(DH_SUCCESS, speakerClient_->OnStateChange(AudioEventType::SPEAKER_OPENED));
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_STATE_IS_INVALID, speakerClient_->OnStateChange(AudioEventType::EVENT_UNKNOWN));
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
    EXPECT_NE(DH_SUCCESS, speakerClient_->SetUp(audioParam));
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, speakerClient_->Release());
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, speakerClient_->StopRender());
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
    EXPECT_EQ(ERR_DH_AUDIO_CLIENT_PARAM_IS_NULL, speakerClient_->OnDecodeTransDataDone(audioData));
    for (size_t i = 0; i < 10; i++) {
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
    speakerClient_->Pause();
    EXPECT_EQ(ERR_DH_AUDIO_SA_STATUS_ERR, speakerClient_->Release());
}
} // DistributedHardware
} // OHOS
