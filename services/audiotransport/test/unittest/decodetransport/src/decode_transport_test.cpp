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

#include "decode_transport_test.h"

#include <memory>

#include "audio_data.h"
#include "audio_event.h"
#include "audio_param.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "mock_audio_data_channel.h"
#include "mock_audio_processor.h"
#include "mock_audio_transport_callback.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string RMT_DEV_ID_TEST = "RemoteTest";
const PortCapType ROLE_TEST = CAP_SPK;

void DecodeTransportTest::SetUpTestCase(void)
{
}

void DecodeTransportTest::TearDownTestCase(void)
{
}

void DecodeTransportTest::SetUp(void)
{
    transCallback_ = std::make_shared<MockAudioTransportCallback>();
    decodeTrans_ = std::make_shared<AudioDecodeTransport>(RMT_DEV_ID_TEST);
}

void DecodeTransportTest::TearDown(void)
{
    transCallback_ = nullptr;
    decodeTrans_ = nullptr;
}

/**
 * @tc.name: decode_transport_test_001
 * @tc.desc: Verify the configure processor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecodeTransportTest, decode_transport_test_001, TestSize.Level1)
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
    EXPECT_NE(DH_SUCCESS, decodeTrans_->SetUp(testLocalParaEnc, testRemoteParaEnc, transCallback_, ROLE_TEST));
    std::shared_ptr<IAudioDataTransCallback> callback = nullptr;
    EXPECT_NE(DH_SUCCESS, decodeTrans_->SetUp(testLocalParaEnc, testRemoteParaEnc, callback, ROLE_TEST));
    EXPECT_EQ(DH_SUCCESS, decodeTrans_->Release());
}

/**
 * @tc.name: decode_transport_test_002
 * @tc.desc: Verify the start processor without configure processor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecodeTransportTest, decode_transport_test_002, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, decodeTrans_->Start());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, decodeTrans_->Stop());
    EXPECT_EQ(DH_SUCCESS, decodeTrans_->Release());

    decodeTrans_->audioChannel_ = std::make_shared<MockIAudioChannel>();
    decodeTrans_->context_ = std::make_shared<AudioTransportContext>();
    decodeTrans_->capType_ = CAP_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_SESSION_NOT_OPEN, decodeTrans_->Start());
    EXPECT_NE(DH_SUCCESS, decodeTrans_->Release());
}

/**
 * @tc.name: decode_transport_test_003
 * @tc.desc: Verify the pause and  processor without configure processor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecodeTransportTest, decode_transport_test_003, TestSize.Level1)
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
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, decodeTrans_->RegisterProcessorListener(testLocalParaEnc, testRemoteParaEnc));
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR,
        decodeTrans_->InitAudioDecodeTransport(testLocalParaEnc, testRemoteParaEnc, ROLE_TEST));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, decodeTrans_->Pause());
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, decodeTrans_->Restart(testLocalParaEnc, testRemoteParaEnc));
}

/**
 * @tc.name: decode_transport_test_004
 * @tc.desc: Verify the FeedAudioData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecodeTransportTest, decode_transport_test_004, TestSize.Level1)
{
    std::shared_ptr<AudioData> audioData = nullptr;
    AudioEvent event;
    decodeTrans_->OnSessionOpened();
    decodeTrans_->OnSessionClosed();
    decodeTrans_->OnDataReceived(audioData);
    decodeTrans_->OnEventReceived(event);
    decodeTrans_->OnStateNotify(event);
    decodeTrans_->OnAudioDataDone(audioData);
    decodeTrans_->dataTransCallback_ = std::make_shared<MockAudioTransportCallback>();
    decodeTrans_->OnSessionOpened();
    decodeTrans_->OnSessionClosed();
    decodeTrans_->OnAudioDataDone(audioData);

    EXPECT_EQ(DH_SUCCESS, decodeTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: decode_transport_test_005
 * @tc.desc: Verify the RegisterChannelListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecodeTransportTest, decode_transport_test_005, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    uint32_t type = 0;
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, decodeTrans_->RegisterChannelListener(ROLE_TEST));
    EXPECT_EQ(DH_SUCCESS, decodeTrans_->CreateCtrl());
    EXPECT_EQ(DH_SUCCESS, decodeTrans_->InitEngine(providerPtr));
    EXPECT_EQ(DH_SUCCESS, decodeTrans_->SendMessage(type, content, dstDevId));
}
} // namespace DistributedHardware
} // namespace OHOS
