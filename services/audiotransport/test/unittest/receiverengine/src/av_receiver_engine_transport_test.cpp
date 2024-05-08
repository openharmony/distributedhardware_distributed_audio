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

#include "av_receiver_engine_transport_test.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "engine_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AVReceiverEngineTransportTest::SetUpTestCase(void) {}

void AVReceiverEngineTransportTest::TearDownTestCase(void) {}

void AVReceiverEngineTransportTest::SetUp(void)
{
    std::string devId = "devId";
    auto callback = std::make_shared<MockAVReceiverTransportCallback>();
    receiverTrans_ = std::make_shared<AVTransReceiverTransport>(devId, callback);
}

void AVReceiverEngineTransportTest::TearDown(void)
{
    receiverTrans_ = nullptr;
}

/**
 * @tc.name: Setup_001
 * @tc.desc: Verify the Setup function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, SetUp_001, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    std::shared_ptr<IAudioDataTransCallback> callback = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->SetUp(localParam, remoteParam, callback, CAP_SPK));
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->SetUp(localParam, remoteParam, callback, CAP_SPK));
}

/**
 * @tc.name: InitEngine_001
 * @tc.desc: Verify the InitEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, InitEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->InitEngine(providerPtr));
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->InitEngine(providerPtr));
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->Release());
}

/**
 * @tc.name: CreateCtrl_001
 * @tc.desc: Verify the CreateCtrl function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, CreateCtrl_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->CreateCtrl());
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    receiverTrans_->receiverAdapter_->chnCreateSuccess_ = true;
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->CreateCtrl());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start and Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, Start_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->Start());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->Stop());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->Release());
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    receiverTrans_->receiverAdapter_->receiverEngine_ = std::make_shared<MockIAVReceiverEngine>();
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->Start());
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->Stop());
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify the Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, Pause_001, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->Restart(localParam, remoteParam));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->Pause());
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: Pause_002
 * @tc.desc: Verify the Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, Pause_002, TestSize.Level1)
{
    AudioParam localParam;
    AudioParam remoteParam;
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    receiverTrans_->receiverAdapter_->receiverEngine_ = std::make_shared<MockIAVReceiverEngine>();
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->Restart(localParam, remoteParam));
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->Pause());
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->FeedAudioData(audioData));
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify the SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, SendMessage_001, TestSize.Level1)
{
    uint32_t type = 0;
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->SendMessage(type, content, dstDevId));
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    receiverTrans_->receiverAdapter_->receiverEngine_ = std::make_shared<MockIAVReceiverEngine>();
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->SendMessage(type, content, dstDevId));
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: Verify the SetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVReceiverEngineTransportTest, SetParameter_001, TestSize.Level1)
{
    AVTransEvent event;
    std::shared_ptr<AVTransMessage> message = nullptr;
    std::shared_ptr<AVTransBuffer> buffer = nullptr;
    receiverTrans_->OnEngineEvent(event);
    receiverTrans_->OnEngineMessage(message);
    receiverTrans_->OnEngineDataAvailable(buffer);
    AudioParam audioParam;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, receiverTrans_->SetParameter(audioParam));
    receiverTrans_->receiverAdapter_ = std::make_shared<AVTransReceiverAdapter>();
    EXPECT_EQ(DH_SUCCESS, receiverTrans_->SetParameter(audioParam));
}
} // namespace DistributedHardware
} // namespace OHOS
