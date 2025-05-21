/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "daudio_echo_cannel_manager_test.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioEchoCannelManagerTest"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

void DAudioEchoCannelManagerTest::SetUpTestCase(void) {}

void DAudioEchoCannelManagerTest::TearDownTestCase(void) {}

void DAudioEchoCannelManagerTest::SetUp(void)
{
    echoCannelManager_ = std::make_shared<DAudioEchoCannelManager>();
}

void DAudioEchoCannelManagerTest::TearDown(void)
{
    echoCannelManager_ = nullptr;
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, SetUp_001, TestSize.Level1)
{
    AudioCommonParam param;
    std::shared_ptr<IAudioDataTransCallback> callback = nullptr;
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->SetUp(param, callback));
}

/**
 * @tc.name: OnMicDataReceived_001
 * @tc.desc: Verify OnMicDataReceived function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, OnMicDataReceived_001, TestSize.Level1)
{
    int32_t bufLen = 4096;
    std::shared_ptr<AudioData> pipeInData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, echoCannelManager_->OnMicDataReceived(pipeInData));
    echoCannelManager_->AecProcessData();
    std::shared_ptr<AudioData> micOutData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, echoCannelManager_->ProcessMicData(pipeInData, micOutData));
}

/**
 * @tc.name: AudioCaptureSetUp_001
 * @tc.desc: Verify AudioCaptureSetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, AudioCaptureSetUp_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, echoCannelManager_->AudioCaptureSetUp());
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, echoCannelManager_->AudioCaptureStart());
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, echoCannelManager_->AudioCaptureStop());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->AudioCaptureRelease());
}

/**
 * @tc.name: AudioCaptureSetUp_002
 * @tc.desc: Verify AudioCaptureSetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, AudioCaptureSetUp_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, echoCannelManager_->AudioCaptureStart());
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, echoCannelManager_->AudioCaptureStop());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->AudioCaptureRelease());
}

/**
 * @tc.name: LoadAecProcessor_001
 * @tc.desc: Verify LoadAecProcessor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, LoadAecProcessor_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->LoadAecProcessor());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->InitAecProcessor());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->StartAecProcessor());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->StopAecProcessor());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->ReleaseAecProcessor());
    echoCannelManager_->UnLoadAecProcessor();
}

/**
 * @tc.name: LoadAecProcessor_002
 * @tc.desc: Verify LoadAecProcessor function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioEchoCannelManagerTest, LoadAecProcessor_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, echoCannelManager_->InitAecProcessor());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, echoCannelManager_->StartAecProcessor());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, echoCannelManager_->StopAecProcessor());
    EXPECT_EQ(DH_SUCCESS, echoCannelManager_->ReleaseAecProcessor());
}
} // namespace DistributedHardware
} // namespace OHOS
