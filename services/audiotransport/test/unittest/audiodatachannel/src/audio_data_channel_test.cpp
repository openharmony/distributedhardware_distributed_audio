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

#include "audio_data_channel_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AudioDataChannelTest::SetUpTestCase(void) {}

void AudioDataChannelTest::TearDownTestCase(void) {}

void AudioDataChannelTest::SetUp(void)
{
    std::string peerDevId = "peerDevId";
    dataChannel_ = std::make_shared<AudioDataChannel>(peerDevId);
}

void AudioDataChannelTest::TearDown(void)
{
    dataChannel_ = nullptr;
}

/**
 * @tc.name: CreateSession_001
 * @tc.desc: Verify the CreateSession and ReleaseSession function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataChannelTest, CreateSession_001, TestSize.Level1)
{
    std::shared_ptr<IAudioChannelListener> listener = nullptr;
    dataChannel_->channelListener_ = listener;
    int32_t sessionId = 0;

    dataChannel_->OnSessionClosed(sessionId);

    EXPECT_NE(DH_SUCCESS, dataChannel_->CreateSession(listener, DATA_SPEAKER_SESSION_NAME));
    EXPECT_EQ(DH_SUCCESS, dataChannel_->ReleaseSession());
}

/**
 * @tc.name: OpenSession_002
 * @tc.desc: Verify the OpenSession and CloseSession function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataChannelTest, OpenSession_002, TestSize.Level1)
{
    std::shared_ptr<IAudioChannelListener> listener = nullptr;
    dataChannel_->channelListener_ = listener;
    int32_t sessionId = 0;
    int32_t result = 0;

    dataChannel_->OnSessionOpened(sessionId, result);

    std::shared_ptr<IAudioChannelListener> channelListener = std::make_shared<MockIAudioChannelListener>();
    dataChannel_->channelListener_ = channelListener;

    StreamData *ext = nullptr;
    StreamFrameInfo *param = nullptr;

    int32_t sessionIdTmp = 0;
    StreamData data;
    data.buf = new char[DATA_LEN];
    data.bufLen = DATA_LEN;

    dataChannel_->OnStreamReceived(sessionIdTmp, &data, ext, param);
    delete[] data.buf;

    EXPECT_NE(DH_SUCCESS, dataChannel_->CreateSession(channelListener, DATA_SPEAKER_SESSION_NAME));
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, dataChannel_->OpenSession());
    EXPECT_EQ(DH_SUCCESS, dataChannel_->CloseSession());
}

/**
 * @tc.name: SendData_001
 * @tc.desc: Verify the SendData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataChannelTest, SendData_001, TestSize.Level1)
{
    std::shared_ptr<IAudioChannelListener> listener = std::make_shared<MockIAudioChannelListener>();
    dataChannel_->channelListener_ = listener;
    int32_t sessionId = -1;
    int32_t result = -1;

    dataChannel_->OnSessionOpened(sessionId, result);

    std::shared_ptr<AudioData> data = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, dataChannel_->SendData(data));
}

/**
 * @tc.name: SendData_002
 * @tc.desc: Verify the SendData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioDataChannelTest, SendData_002, TestSize.Level1)
{
    std::shared_ptr<IAudioChannelListener> listener = std::make_shared<MockIAudioChannelListener>();
    dataChannel_->channelListener_ = listener;
    int32_t sessionId = 0;
    int32_t result = 0;

    dataChannel_->OnSessionOpened(sessionId, result);

    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
    EXPECT_EQ(DH_SUCCESS, dataChannel_->SendData(audioData));
}
} // namespace DistributedHardware
} // namespace OHOS
