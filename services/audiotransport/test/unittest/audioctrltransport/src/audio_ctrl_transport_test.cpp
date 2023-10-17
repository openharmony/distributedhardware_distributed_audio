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

#include "audio_ctrl_transport_test.h"
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AudioCtrlTransportTest::SetUpTestCase(void) {}

void AudioCtrlTransportTest::TearDownTestCase(void) {}

void AudioCtrlTransportTest::SetUp(void)
{
    std::string peerDevId = "peerDevId";
    trans = std::make_shared<AudioCtrlTransport>(peerDevId);
}

void AudioCtrlTransportTest::TearDown(void) {}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, SetUp_001, TestSize.Level1)
{
    std::shared_ptr<IAudioCtrlTransCallback> callback = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, trans->SetUp(callback));
}

/**
 * @tc.name: SetUp_002
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, SetUp_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::shared_ptr<IAudioCtrlTransCallback> callback = std::make_shared<MockIAudioCtrlTransCallback>();
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    EXPECT_EQ(DH_SUCCESS, trans->SetUp(callback));
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify the Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Release_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, trans->Release());
}

/**
 * @tc.name: Release_002
 * @tc.desc: Verify the Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Release_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    EXPECT_EQ(DH_SUCCESS, trans->Release());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Start_001, TestSize.Level1)
{
    trans->OnSessionOpened();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, trans->Start());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Start_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    EXPECT_EQ(DH_SUCCESS, trans->Start());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Stop_001, TestSize.Level1)
{
    AudioEvent event;
    trans->OnEventReceived(event);
    trans->OnSessionClosed();
    EXPECT_EQ(DH_SUCCESS, trans->Stop());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, Stop_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    EXPECT_EQ(DH_SUCCESS, trans->Stop());
}

/**
 * @tc.name: SendAudioEvent_001
 * @tc.desc: Verify the SendAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, SendAudioEvent_001, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    AudioEvent event ;
    EXPECT_EQ(DH_SUCCESS, trans->SendAudioEvent(event));
}

/**
 * @tc.name: SendAudioEvent_002
 * @tc.desc: Verify the SendAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, SendAudioEvent_002, TestSize.Level1)
{
    AudioEvent event ;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, trans->SendAudioEvent(event));
}

/**
 * @tc.name: RegisterChannelListener_001
 * @tc.desc: Verify the RegisterChannelListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, RegisterChannelListener_001, TestSize.Level1)
{
    std::shared_ptr<IAudioChannelListener> listener = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, trans->RegisterChannelListener());
}

/**
 * @tc.name: RegisterChannelListener_002
 * @tc.desc: Verify the RegisterChannelListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, RegisterChannelListener_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    std::shared_ptr<IAudioChannelListener> listener = std::make_shared<MockIAudioChannelListener>();
    EXPECT_EQ(DH_SUCCESS, trans->RegisterChannelListener());
}

/**
 * @tc.name: InitAudioCtrlTrans_002
 * @tc.desc: Verify the InitAudioCtrlTrans function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioCtrlTransportTest, InitAudioCtrlTrans_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    const std::string netWorkId = "netWorkId";
    trans->audioChannel_ = std::make_shared<MockAudioCtrlChannel>(peerDevId);
    EXPECT_EQ(DH_SUCCESS, trans->InitAudioCtrlTrans(netWorkId));
}
} // namespace DistributedHardware
} // namespace OHOS
