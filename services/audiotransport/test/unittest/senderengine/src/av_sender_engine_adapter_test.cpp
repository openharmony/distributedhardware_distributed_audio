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

#include "av_sender_engine_adapter_test.h"

#include "audio_data.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "engine_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AVTransSenderAdapterTest::SetUpTestCase(void) {}

void AVTransSenderAdapterTest::TearDownTestCase(void) {}

void AVTransSenderAdapterTest::SetUp(void)
{
    senderAdapter_ = std::make_shared<AVTransSenderAdapter>();
}

void AVTransSenderAdapterTest::TearDown(void)
{
    senderAdapter_ = nullptr;
}

/**
 * @tc.name: Initialize_001
 * @tc.desc: Verify the Initialize function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, Initialize_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    std::string peerDevId = "peerDevId";
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->Initialize(providerPtr, peerDevId));
    senderAdapter_->initialized_ = true;
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->Initialize(providerPtr, peerDevId));
}

/**
 * @tc.name: Initialize_002
 * @tc.desc: Verify the Initialize function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, Initialize_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->Start());
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->Stop());
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->Release());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start and Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, Start_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->Start());
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->Stop());
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: Verify the SetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, SetParameter_001, TestSize.Level1)
{
    std::string param = "param";
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_RATE, param));
}

/**
 * @tc.name: SetParameter_002
 * @tc.desc: Verify the SetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, SetParameter_002, TestSize.Level1)
{
    std::string param = "param";
    senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->SetParameter(AVTransTag::AUDIO_SAMPLE_RATE, param));
}

/**
 * @tc.name: PushData_001
 * @tc.desc: Verify the PushData function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, PushData_001, TestSize.Level1)
{
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->PushData(audioData));
    senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->PushData(audioData));
}

/**
 * @tc.name: CreateControlChannel_001
 * @tc.desc: Verify the CreateControlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, CreateControlChannel_001, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->CreateControlChannel(peerDevId));
    senderAdapter_->chnCreateSuccess_ = true;
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->CreateControlChannel(peerDevId));
}

/**
 * @tc.name: CreateControlChannel_002
 * @tc.desc: Verify the CreateControlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, CreateControlChannel_002, TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->CreateControlChannel(peerDevId));
    senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED, senderAdapter_->CreateControlChannel(peerDevId));
}

/**
 * @tc.name: SendMessageToRemote_001
 * @tc.desc: Verify the SendMessageToRemote function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, SendMessageToRemote_001, TestSize.Level1)
{
    uint32_t type = 0;
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->SendMessageToRemote(message));
    senderAdapter_->senderEngine_ = std::make_shared<MockIAVSenderEngine>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->SendMessageToRemote(message));
}

/**
 * @tc.name: RegisterAdapterCallback_001
 * @tc.desc: Verify the RegisterAdapterCallback function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, RegisterAdapterCallback_001, TestSize.Level1)
{
    std::shared_ptr<AVSenderAdapterCallback> callback = nullptr;
    EXPECT_EQ(ERR_DH_AV_TRANS_NULL_VALUE, senderAdapter_->RegisterAdapterCallback(callback));
    callback = std::make_shared<MockAVSenderAdapterCallback>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->RegisterAdapterCallback(callback));
}

/**
 * @tc.name: OnSenderEvent_001
 * @tc.desc: Verify the OnSenderEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(AVTransSenderAdapterTest, OnSenderEvent_001, TestSize.Level1)
{
    AVTransEvent event;
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->OnSenderEvent(event));
    std::shared_ptr<AVTransMessage> message = nullptr;
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->OnMessageReceived(message));
    senderAdapter_->adapterCallback_ = std::make_shared<MockAVSenderAdapterCallback>();
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->OnSenderEvent(event));
    EXPECT_EQ(DH_SUCCESS, senderAdapter_->OnMessageReceived(message));
}
} // namespace DistributedHardware
} // namespace OHOS
