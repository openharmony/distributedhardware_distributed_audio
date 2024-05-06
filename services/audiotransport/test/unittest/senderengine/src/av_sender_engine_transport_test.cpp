/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "av_sender_engine_transport_test.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "engine_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AVSenderEngineTransportTest::SetUpTestCase(void) {}

void AVSenderEngineTransportTest::TearDownTestCase(void) {}

void AVSenderEngineTransportTest::SetUp(void)
{
    std::string devId = "devId";
    auto callback = std::make_shared<MockAVSenderTransportCallback>();
    senderTrans_ = std::make_shared<AVTransSenderTransport>(devId, callback);
}

void AVSenderEngineTransportTest::TearDown(void)
{
    senderTrans_ = nullptr;
}

/**
 * @tc.name: Setup_001
 * @tc.desc: Verify the Setup function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, SetUp_001, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    std::shared_ptr<IAudioDataTransCallback> callback = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->SetUp(localParam, remoteParam, callback, CAP_SPK));
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->SetUp(localParam, remoteParam, callback, CAP_SPK));
}

/**
 * @tc.name: InitEngine_001
 * @tc.desc: Verify the InitEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, InitEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->InitEngine(providerPtr));
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->InitEngine(providerPtr));
    EXPECT_EQ(DH_SUCCESS, senderTrans_->Release());
}

/**
 * @tc.name: CreateCtrl_001
 * @tc.desc: Verify the CreateCtrl function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, CreateCtrl_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->CreateCtrl());
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->chnCreateSuccess_ = true;
    EXPECT_EQ(DH_SUCCESS, senderTrans_->CreateCtrl());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start and Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, Start_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->Start());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->Stop());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->Release());
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->Start());
    EXPECT_EQ(DH_SUCCESS, senderTrans_->Stop());
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify the Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, Pause_001, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->Restart(localParam, remoteParam));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->Pause());
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: Pause_002
 * @tc.desc: Verify the Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, Pause_002, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    size_t bufLen = 4096;
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(DH_SUCCESS, senderTrans_->Restart(localParam, remoteParam));
    EXPECT_EQ(DH_SUCCESS, senderTrans_->Pause());
    EXPECT_EQ(DH_SUCCESS, senderTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify the SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, SendMessage_001, TestSize.Level1)
{
    uint32_t type = 0;
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->SendMessage(type, content, dstDevId));
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->SendMessage(type, content, dstDevId));
}

/**
 * @tc.name: FeedAudioData_001
 * @tc.desc: Verify the FeedAudioData function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, FeedAudioData_001, TestSize.Level1)
{
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->FeedAudioData(audioData));
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    senderTrans_->senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: Verify the SetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVSenderEngineTransportTest, SetParameter_001, TestSize.Level1)
{
    AVTransEvent event;
    std::shared_ptr<AVTransMessage> message = nullptr;
    senderTrans_->OnEngineEvent(event);
    senderTrans_->OnEngineMessage(message);
    message = std::make_shared<AVTransMessage>();
    senderTrans_->OnEngineMessage(message);
    AudioParam audioParam;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, senderTrans_->SetParameter(audioParam));
    senderTrans_->senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
    EXPECT_EQ(DH_SUCCESS, senderTrans_->SetParameter(audioParam));
}
} // namespace DistributedHardware
} // namespace OHOS
