/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "daudio_hdi_handler_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioHdiHandlerTest::SetUpTestCase(void) {}

void DAudioHdiHandlerTest::TearDownTestCase(void) {}

void DAudioHdiHandlerTest::SetUp()
{
    hdiHandler_ = std::make_shared<DAudioHdiHandler>();
}

void DAudioHdiHandlerTest::TearDown()
{
    hdiHandler_ = nullptr;
}

/**
 * @tc.name: InitHdiHandler_001
 * @tc.desc: Verify the InitHdiHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, InitHdiHandler_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler());
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler()); // test repeated initialization
}

/**
 * @tc.name: RegisterAudioDevice_001
 * @tc.desc: Verify the RegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, RegisterAudioDevice_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler());
    hdiHandler_->audioSrvHdf_ = nullptr;
    std::shared_ptr<IDAudioHdiCallback> callbackObjParam = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->RegisterAudioDevice(devId_,
        PIN_OUT_DAUDIO_DEFAULT, capability_, callbackObjParam));
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->RegisterAudioDevice(devId_,
        PIN_IN_DAUDIO_DEFAULT, capability_, callbackObjParam));
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->RegisterAudioDevice(devId_, -1, capability_, callbackObjParam));
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->UnRegisterAudioDevice(devId_, PIN_OUT_DAUDIO_DEFAULT));
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->UnRegisterAudioDevice(devId_, PIN_IN_DAUDIO_DEFAULT));
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->UnRegisterAudioDevice("errorId", PIN_IN_DAUDIO_DEFAULT));
}

/**
 * @tc.name: RegisterAudioDevice_002
 * @tc.desc: Verify the RegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, RegisterAudioDevice_002, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler());
    std::shared_ptr<IDAudioHdiCallback> callbackObjParam = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(ERR_DH_AUDIO_HDI_CALL_FAILED,
        hdiHandler_->RegisterAudioDevice(devId_, dhId_, capability_, callbackObjParam));
    EXPECT_EQ(ERR_DH_AUDIO_HDI_CALL_FAILED, hdiHandler_->UnRegisterAudioDevice(devId_, dhId_));
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, NotifyEvent_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler());
    hdiHandler_->audioSrvHdf_ = nullptr;
    AudioEvent audioEvent;
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent));
}

/**
 * @tc.name: NotifyEvent_002
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, NotifyEvent_002, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->InitHdiHandler());
    hdiHandler_->audioSrvHdf_ = new MockIDAudioManager();
    AudioEvent audioEvent1(AudioEventType::NOTIFY_OPEN_SPEAKER_RESULT, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent1));
    AudioEvent audioEvent2(AudioEventType::NOTIFY_CLOSE_SPEAKER_RESULT, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent2));
    AudioEvent audioEvent3(AudioEventType::NOTIFY_OPEN_MIC_RESULT, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent3));
    AudioEvent audioEvent4(AudioEventType::NOTIFY_CLOSE_MIC_RESULT, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent4));
    AudioEvent audioEvent5(AudioEventType::VOLUME_CHANGE, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent5));
    AudioEvent audioEvent6(AudioEventType::SPEAKER_CLOSED, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent6));
    AudioEvent audioEvent7(AudioEventType::MIC_CLOSED, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent7));
    AudioEvent audioEvent8(AudioEventType::AUDIO_FOCUS_CHANGE, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent8));
    AudioEvent audioEvent9(AudioEventType::AUDIO_RENDER_STATE_CHANGE, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent9));
    AudioEvent audioEvent(-1, "");
    EXPECT_EQ(HDF_SUCCESS, hdiHandler_->NotifyEvent(devId_, dhId_, streamId_, audioEvent));
}

/**
 * @tc.name: UnRegisterAudioDevice_001
 * @tc.desc: Verify the UnRegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, UnRegisterAudioDevice_001, TestSize.Level1)
{
    hdiHandler_->audioSrvHdf_ = nullptr;
    EXPECT_NE(HDF_SUCCESS, hdiHandler_->UnRegisterAudioDevice(devId_, dhId_));
}

/**
 * @tc.name: UnInitHdiHandler_001
 * @tc.desc: Verify the UnInitHdiHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioHdiHandlerTest, UnInitHdiHandler_001, TestSize.Level1)
{
    hdiHandler_->audioSrvHdf_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, hdiHandler_->UninitHdiHandler());
}
} // DistributedHardware
} // OHOS
