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

#include "audio_transport_pause_status_test.h"

#include "audio_transport_context.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "mock_audio_data_channel.h"
#include "mock_audio_processor.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

void AudioTransportPauseStatusTest::SetUpTestCase(void)
{
}

void AudioTransportPauseStatusTest::TearDownTestCase(void)
{
}

void AudioTransportPauseStatusTest::SetUp(void)
{
    stateContext_ = std::shared_ptr<AudioTransportContext>();
    audioStatus_ = std::make_shared<AudioTransportPauseStatus>(stateContext_);
}

void AudioTransportPauseStatusTest::TearDown(void)
{
    stateContext_ = nullptr;
    audioStatus_ = nullptr;
}

/**
 * @tc.name: transport_pause_test_001
 * @tc.desc: Verify start action when status is pause.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportPauseStatusTest, transport_pause_test_001, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::shared_ptr<IAudioChannel> audioChannel_ = std::make_shared<MockAudioDataChannel>(peerDevId);
    std::shared_ptr<IAudioProcessor> processor_ = std::make_shared<MockIAudioProcessor>();
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ILLEGAL_OPERATION, audioStatus_->Start(audioChannel_, processor_));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, audioStatus_->Stop(nullptr, processor_));
}

/**
 * @tc.name: transport_pause_test_002
 * @tc.desc: Verify stop action when status is pause.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportPauseStatusTest, transport_pause_test_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::shared_ptr<IAudioChannel> audioChannel_ = std::make_shared<MockAudioDataChannel>(peerDevId);
    std::shared_ptr<IAudioProcessor> processor_ = std::make_shared<MockIAudioProcessor>();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, audioStatus_->Stop(audioChannel_, processor_));
}

/**
 * @tc.name: transport_pause_test_003
 * @tc.desc: Verify pause action when status is pause.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportPauseStatusTest, transport_pause_test_003, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::shared_ptr<IAudioChannel> audioChannel_ = std::make_shared<MockAudioDataChannel>(peerDevId);
    std::shared_ptr<IAudioProcessor> processor_ = std::make_shared<MockIAudioProcessor>();
    EXPECT_EQ(DH_SUCCESS, audioStatus_->Pause(processor_));
}

/**
 * @tc.name: transport_pause_test_004
 * @tc.desc: Verify reStart action when status is pause.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportPauseStatusTest, transport_pause_test_004, TestSize.Level1)
{
    AudioParam testLocalParaEnc = {
        {
            SAMPLE_RATE_48000,
            STEREO,
            SAMPLE_S16LE,
            AUDIO_CODEC_FLAC
        },
        {
            SOURCE_TYPE_INVALID,
            NORMAL_MODE
        },
        {
            CONTENT_TYPE_UNKNOWN,
            STREAM_USAGE_UNKNOWN,
            NORMAL_MODE
        }
    };
    AudioParam testRemoteParaEnc = {
        {
            SAMPLE_RATE_48000,
            STEREO,
            SAMPLE_S16LE,
            AUDIO_CODEC_FLAC
        },
        {
            SOURCE_TYPE_INVALID,
            NORMAL_MODE
        },
        {
            CONTENT_TYPE_UNKNOWN,
            STREAM_USAGE_UNKNOWN,
            NORMAL_MODE
        }
    };
    std::string peerDevId = "peerDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, audioStatus_->Restart(testLocalParaEnc, testRemoteParaEnc, nullptr));

    std::shared_ptr<IAudioChannel> audioChannel_ = std::make_shared<MockAudioDataChannel>(peerDevId);
    std::shared_ptr<IAudioProcessor> processor_ = std::make_shared<MockIAudioProcessor>();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, audioStatus_->Restart(testLocalParaEnc, testRemoteParaEnc, processor_));
}

/**
 * @tc.name: transport_getstatetype_test_001
 * @tc.desc: Verify pause action when status is start.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportPauseStatusTest, transport_getstatetype_test_001, TestSize.Level1)
{
    EXPECT_EQ(TRANSPORT_STATE_PAUSE, audioStatus_->GetStateType());
}
} // namespace DistributedHardware
} // namespace OHOS
