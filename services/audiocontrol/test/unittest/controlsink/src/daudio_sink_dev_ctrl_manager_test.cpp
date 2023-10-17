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

#include "daudio_sink_dev_ctrl_manager_test.h"
#include "audiocontrol_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkDevCtrlMgrTest::SetUpTestCase(void) {}

void DAudioSinkDevCtrlMgrTest::TearDownTestCase(void) {}

void DAudioSinkDevCtrlMgrTest::SetUp(void)
{
    std::string networkId = "devId";
    std::shared_ptr<IAudioEventCallback> audioEventCallback = nullptr;
    sinkDevCtrl_ = std::make_shared<DAudioSinkDevCtrlMgr>(networkId, audioEventCallback);
}

void DAudioSinkDevCtrlMgrTest::TearDown(void)
{
    sinkDevCtrl_ = nullptr;
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify the SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */

HWTEST_F(DAudioSinkDevCtrlMgrTest, SetUp_001, TestSize.Level1)
{
    int32_t type = static_cast<int32_t>(AudioEventType::CTRL_OPENED);
    sinkDevCtrl_->OnStateChange(type);

    std::string devId = "devId";
    sinkDevCtrl_->audioCtrlTrans_ = std::make_shared<MockIAudioCtrlTransport>(devId);
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->SetUp());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, Start_001, TestSize.Level1)
{
    std::string devId = "devId";
    sinkDevCtrl_->audioCtrlTrans_ = std::make_shared<MockIAudioCtrlTransport>(devId);
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->Start());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, Stop_001, TestSize.Level1)
{
    sinkDevCtrl_->audioCtrlTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->Stop());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, Stop_002, TestSize.Level1)
{
    std::string devId = "devId";
    sinkDevCtrl_->audioCtrlTrans_ = std::make_shared<MockIAudioCtrlTransport>(devId);
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->Stop());
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify the Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, Release_001, TestSize.Level1)
{
    std::string devId = "devId";
    sinkDevCtrl_->audioCtrlTrans_ = std::make_shared<MockIAudioCtrlTransport>(devId);
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->Release());
}

/**
 * @tc.name: IsOpened_001
 * @tc.desc: Verify the IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, IsOpened_001, TestSize.Level1)
{
    AudioEvent event;
    sinkDevCtrl_->audioEventCallback_ = std::make_shared<MockIAudioEventCallback>();
    sinkDevCtrl_->OnEventReceived(event);

    sinkDevCtrl_->isOpened_ = true;
    EXPECT_EQ(true, sinkDevCtrl_->IsOpened());
}

/**
 * @tc.name: SendAudioEvent_001
 * @tc.desc: Verify the SendAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, SendAudioEvent_001, TestSize.Level1)
{
    AudioEvent event;
    sinkDevCtrl_->audioCtrlTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDevCtrl_->SendAudioEvent(event));
}

/**
 * @tc.name: SendAudioEvent_002
 * @tc.desc: Verify the SendAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevCtrlMgrTest, SendAudioEvent_002, TestSize.Level1)
{
    std::string devId = "devId";
    AudioEvent event;
    sinkDevCtrl_->audioCtrlTrans_ = std::make_shared<MockIAudioCtrlTransport>(devId);
    EXPECT_EQ(DH_SUCCESS, sinkDevCtrl_->SendAudioEvent(event));
}
} // namespace DistributedHardware
} // namespace OHOS
