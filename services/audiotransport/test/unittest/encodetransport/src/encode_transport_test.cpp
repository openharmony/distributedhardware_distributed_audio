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

#include "encode_transport_test.h"

#include <memory>

#include "audio_data.h"
#include "audio_event.h"
#include "audio_transport_status.h"
#include "audio_transport_status_factory.h"
#include "audio_param.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "audio_transport_context.h"
#include "mock_audio_data_channel.h"
#include "mock_audio_transport_callback.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string RMT_DEV_ID_TEST = "RemoteDevIdTest";
const PortCapType ROLE_TEST = CAP_SPK;

void EncodeTransportTest::SetUpTestCase(void)
{
}

void EncodeTransportTest::TearDownTestCase(void)
{
}

void EncodeTransportTest::SetUp(void)
{
    transCallback_ = std::make_shared<MockAudioTransportCallback>();
    encodeTrans_ = std::make_shared<AudioEncodeTransport>(RMT_DEV_ID_TEST);
}

void EncodeTransportTest::TearDown(void)
{
    transCallback_ = nullptr;
    encodeTrans_ = nullptr;
}

/**
 * @tc.name: encode_transport_test_001
 * @tc.desc: Verify the configure transport function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncodeTransportTest, encode_transport_test_001, TestSize.Level1)
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
    EXPECT_NE(DH_SUCCESS, encodeTrans_->SetUp(testLocalParaEnc, testRemoteParaEnc, transCallback_, ROLE_TEST));
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->Release());
}

/**
 * @tc.name: encode_transport_test_002
 * @tc.desc: Verify the start transport without configure transport function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncodeTransportTest, encode_transport_test_002, TestSize.Level1)
{
    encodeTrans_->audioChannel_ = std::make_shared<MockAudioDataChannel>(RMT_DEV_ID_TEST);
    encodeTrans_->context_ = std::make_shared<AudioTransportContext>();
    auto stateContext = std::shared_ptr<AudioTransportContext>(encodeTrans_->context_);
    encodeTrans_->context_->currentState_ =
        AudioTransportStatusFactory::GetInstance().CreateState(TRANSPORT_STATE_START, stateContext);
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->Start());
    encodeTrans_->context_->currentState_ =
        AudioTransportStatusFactory::GetInstance().CreateState(TRANSPORT_STATE_STOP, stateContext);
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->Stop());
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->Release());
}

/**
 * @tc.name: encode_transport_test_003
 * @tc.desc: Verify the pasue and restart transport without configure transport function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncodeTransportTest, encode_transport_test_003, TestSize.Level1)
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

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, encodeTrans_->RegisterProcessorListener(testLocalParaEnc, testRemoteParaEnc));
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR,
        encodeTrans_->InitAudioEncodeTrans(testLocalParaEnc, testRemoteParaEnc, ROLE_TEST));
    encodeTrans_->context_ = std::make_shared<AudioTransportContext>();
    auto stateContext = std::shared_ptr<AudioTransportContext>(encodeTrans_->context_);
    encodeTrans_->context_->currentState_ =
        AudioTransportStatusFactory::GetInstance().CreateState(TRANSPORT_STATE_PAUSE, stateContext);
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->Pause());
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, encodeTrans_->Restart(testLocalParaEnc, testRemoteParaEnc));
}

/**
 * @tc.name: encode_transport_test_004
 * @tc.desc: Verify encode_transport_test function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncodeTransportTest, encode_transport_test_004, TestSize.Level1)
{
    std::shared_ptr<AudioData> audioData = nullptr;
    AudioEvent event;
    encodeTrans_->OnSessionOpened();
    encodeTrans_->OnSessionClosed();
    encodeTrans_->OnDataReceived(audioData);
    encodeTrans_->OnEventReceived(event);
    encodeTrans_->OnStateNotify(event);
    encodeTrans_->OnAudioDataDone(audioData);

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, encodeTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: encode_transport_test_005
 * @tc.desc: Verify RegisterChannelListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncodeTransportTest, encode_transport_test_005, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    uint32_t type = 0;
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, encodeTrans_->RegisterChannelListener(ROLE_TEST));
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->CreateCtrl());
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->InitEngine(providerPtr));
    EXPECT_EQ(DH_SUCCESS, encodeTrans_->SendMessage(type, content, dstDevId));
}
} // namespace DistributedHardware
} // namespace OHOS
