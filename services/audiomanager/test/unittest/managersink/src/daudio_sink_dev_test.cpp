/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use sinkDev_ file except in compliance with the License.
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

#include "daudio_sink_dev_test.h"

#include "audio_event.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkDevTest::SetUpTestCase(void) {}

void DAudioSinkDevTest::TearDownTestCase(void) {}

void DAudioSinkDevTest::SetUp()
{
    std::string networkId = "networkId";
    sinkDev_ = std::make_shared<DAudioSinkDev>(networkId);
}

void DAudioSinkDevTest::TearDown()
{
    sinkDev_ = nullptr;
}

/**
 * @tc.name: InitAVTransEngines_001
 * @tc.desc: Verify the InitAVTransEngines function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, InitAVTransEngines_001, TestSize.Level1)
{
    IAVEngineProvider *senderPtr = nullptr;
    IAVEngineProvider *receiverPtr = nullptr;
    sinkDev_->engineFlag_ = true;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->InitAVTransEngines(senderPtr, receiverPtr));
}

/**
 * @tc.name: NotifyOpenCtrlChannel_001
 * @tc.desc: Verify the NotifyOpenCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyOpenCtrlChannel_001, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyOpenCtrlChannel(event));
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyOpenCtrlChannel(event));
    event.type = OPEN_CTRL;
    sinkDev_->NotifyEvent(event);

    event.type = EVENT_UNKNOWN;
    sinkDev_->NotifyEvent(event);
}

/**
 * @tc.name: NotifyCloseCtrlChannel_001
 * @tc.desc: Verify the NotifyCloseCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCloseCtrlChannel_001, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyCloseCtrlChannel(event));
    sinkDev_->NotifyEvent(event);
}

/**
 * @tc.name: NotifyCtrlOpened_001
 * @tc.desc: Verify the NotifyCtrlOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCtrlOpened_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyCtrlOpened(event));
    sinkDev_->NotifyEvent(event);
}

/**
 * @tc.name: NotifyCtrlClosed_001
 * @tc.desc: Verify the NotifyCtrlClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCtrlClosed_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyCtrlClosed(event));
}

/**
 * @tc.name: NotifyCtrlClosed_002
 * @tc.desc: Verify the NotifyCtrlClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCtrlClosed_002, TestSize.Level1)
{
    AudioEvent event;
    uint32_t maxSize = 10;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(maxSize);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyCtrlClosed(event));
}

/**
 * @tc.name: NotifySpeakerOpened_001
 * @tc.desc: Verify the NotifySpeakerOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySpeakerOpened_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_NE(DH_SUCCESS, sinkDev_->NotifySpeakerOpened(event));
}

/**
 * @tc.name: NotifyOpenSpeaker_001
 * @tc.desc: Verify the NotifyOpenSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyOpenSpeaker_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyOpenSpeaker(event));
}

/**
 * @tc.name: NotifyOpenSpeaker_002
 * @tc.desc: Verify the NotifyOpenSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyOpenSpeaker_002, TestSize.Level1)
{
    AudioEvent event;
    uint32_t maxSize = 10;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(maxSize);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyOpenSpeaker(event));
}

/**
 * @tc.name: NotifyCloseSpeaker_001
 * @tc.desc: Verify the NotifyCloseSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCloseSpeaker_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyCloseSpeaker(event));
}

/**
 * @tc.name: NotifyCloseSpeaker_002
 * @tc.desc: Verify the NotifyCloseSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCloseSpeaker_002, TestSize.Level1)
{
    AudioEvent event;
    uint32_t maxSize = 10;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(maxSize);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyCloseSpeaker(event));
}

/**
 * @tc.name: NotifySpeakerOpened_002
 * @tc.desc: Verify the NotifySpeakerOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySpeakerOpened_002, TestSize.Level1)
{
    AudioEvent event;
    std::string devId = "devid";
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->NotifySpeakerOpened(event));
}

/**
 * @tc.name: NotifySpeakerOpened_003
 * @tc.desc: Verify the NotifySpeakerOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySpeakerOpened_003, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    std::string devId = "devid";
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->NotifySpeakerOpened(event));
}

/**
 * @tc.name: NotifySpeakerClosed_001
 * @tc.desc: Verify the NotifySpeakerClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySpeakerClosed_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySpeakerClosed(event));
}

/**
 * @tc.name: NotifySpeakerClosed_002
 * @tc.desc: Verify the NotifySpeakerClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySpeakerClosed_002, TestSize.Level1)
{
    AudioEvent event;
    uint32_t maxSize = 10;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(maxSize);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifySpeakerClosed(event));
}

/**
 * @tc.name: NotifyMicOpened_001
 * @tc.desc: Verify the NotifyMicOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyMicOpened_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyMicOpened(event));
}

/**
 * @tc.name: NotifyMicClosed_001
 * @tc.desc: Verify the NotifyMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyMicClosed_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyMicClosed(event));
}

/**
 * @tc.name: NotifyMicClosed_002
 * @tc.desc: Verify the NotifyMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyMicClosed_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyMicClosed(event));
}

/**
 * @tc.name: NotifyOpenMic_001
 * @tc.desc: Verify the NotifyOpenMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyOpenMic_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyOpenMic(event));
}

/**
 * @tc.name: NotifyOpenMic_002
 * @tc.desc: Verify the NotifyOpenMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyOpenMic_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyOpenMic(event));
}

/**
 * @tc.name: NotifyCloseMic_001
 * @tc.desc: Verify the NotifyCloseMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCloseMic_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyCloseMic(event));
}

/**
 * @tc.name: NotifyCloseMic_002
 * @tc.desc: Verify the NotifyCloseMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCloseMic_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyCloseMic(event));
}

/**
 * @tc.name: NotifySetParam_001
 * @tc.desc: Verify the NotifySetParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetParam_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetParam(event));
}

/**
 * @tc.name: NotifySetParam_002
 * @tc.desc: Verify the NotifySetParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetParam_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetParam(event));
}

/**
 * @tc.name: NotifySetVolume_001
 * @tc.desc: Verify the NotifySetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetVolume_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetVolume(event));
}

/**
 * @tc.name: NotifySetVolume_002
 * @tc.desc: Verify the NotifySetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetVolume_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetVolume(event));
}

/**
 * @tc.name: NotifySetMute_001
 * @tc.desc: Verify the NotifySetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetMute_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetMute(event));
}

/**
 * @tc.name: NotifySetMute_002
 * @tc.desc: Verify the NotifySetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifySetMute_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifySetMute(event));
}

/**
 * @tc.name: NotifyVolumeChange_001
 * @tc.desc: Verify the NotifyVolumeChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyVolumeChange_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyVolumeChange(event));
}

/**
 * @tc.name: NotifyVolumeChange_002
 * @tc.desc: Verify the NotifyVolumeChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyVolumeChange_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyVolumeChange(event));
}

/**
 * @tc.name: NotifyFocusChange_001
 * @tc.desc: Verify the NotifyFocusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyFocusChange_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyFocusChange(event));
}

/**
 * @tc.name: NotifyFocusChange_002
 * @tc.desc: Verify the NotifyFocusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyFocusChange_002, TestSize.Level1)
{
    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyFocusChange(event));
}

/**
 * @tc.name: NotifyRenderStateChange_001
 * @tc.desc: Verify the NotifyRenderStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyRenderStateChange_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyRenderStateChange(event));
}

/**
 * @tc.name: NotifyRenderStateChange_002
 * @tc.desc: Verify the NotifyRenderStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyRenderStateChange_002, TestSize.Level1)
{
    sinkDev_->SleepAudioDev();

    constexpr size_t capacity = 20;
    sinkDev_->taskQueue_ = std::make_shared<TaskQueue>(capacity);
    AudioEvent event;
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyRenderStateChange(event));
}

/**
 * @tc.name: NotifyPlayStatusChange_001
 * @tc.desc: Verify the NotifyPlayStatusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyPlayStatusChange_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->NotifyPlayStatusChange(event));

    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    EXPECT_EQ(DH_SUCCESS, sinkDev_->NotifyPlayStatusChange(event));
    sinkDev_->SleepAudioDev();
}

/**
 * @tc.name: TaskPlayStatusChange_001
 * @tc.desc: Verify the TaskPlayStatusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskPlayStatusChange_001, TestSize.Level1)
{
    sinkDev_->speakerClient_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskPlayStatusChange(""));

    std::string devId = "devid";
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskPlayStatusChange(AUDIO_EVENT_PAUSE));
}

/**
 * @tc.name: TaskOpenCtrlChannel_001
 * @tc.desc: Verify the TaskOpenCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenCtrlChannel_001, TestSize.Level1)
{
    std::string args;
    sinkDev_->engineFlag_ = true;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskOpenCtrlChannel(args));
}

/**
 * @tc.name: TaskOpenCtrlChannel_002
 * @tc.desc: Verify the TaskOpenCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenCtrlChannel_002, TestSize.Level1)
{
    std::string args = "args";
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenCtrlChannel(args));
    sinkDev_->engineFlag_ = true;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskOpenCtrlChannel(args));
}

/**
 * @tc.name: TaskCloseCtrlChannel_001
 * @tc.desc: Verify the TaskCloseCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseCtrlChannel_001, TestSize.Level1)
{
    std::string args;
    sinkDev_->audioCtrlMgr_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseCtrlChannel(args));
}

/**
 * @tc.name: TaskCloseCtrlChannel_002
 * @tc.desc: Verify the TaskCloseCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseCtrlChannel_002, TestSize.Level1)
{
    std::string args;
    std::string devId = "devId";
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseCtrlChannel(args));
    sinkDev_->engineFlag_ = true;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseCtrlChannel(args));
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseCtrlChannel(args));
}

/**
 * @tc.name: TaskOpenDSpeaker_001
 * @tc.desc: Verify the TaskOpenDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDSpeaker_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDSpeaker(args));
}

/**
 * @tc.name: TaskOpenDSpeaker_002
 * @tc.desc: Verify the TaskOpenDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDSpeaker_002, TestSize.Level1)
{
    std::string args = "args";
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDSpeaker(args));
}

/**
 * @tc.name: TaskCloseDSpeaker_001
 * @tc.desc: Verify the TaskCloseDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseDSpeaker_001, TestSize.Level1)
{
    std::string args;
    sinkDev_->speakerClient_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDSpeaker(args));
}

/**
 * @tc.name: TaskCloseDSpeaker_002
 * @tc.desc: Verify the TaskCloseDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseDSpeaker_002, TestSize.Level1)
{
    std::string args;
    std::string devId = "devId";
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDSpeaker(args));
    sinkDev_->engineFlag_ = false;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDSpeaker(args));
}

/**
 * @tc.name: TaskOpenDMic_001
 * @tc.desc: Verify the TaskOpenDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDMic_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDMic(args));
}

/**
 * @tc.name: TaskOpenDMic_002
 * @tc.desc: Verify the TaskOpenDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDMic_002, TestSize.Level1)
{
    std::string args = "args";
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDMic(args));
}

/**
 * @tc.name: TaskCloseDMic_001
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseDMic_001, TestSize.Level1)
{
    std::string args;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDMic(args));
    sinkDev_->engineFlag_ = false;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDMic(args));
}

/**
 * @tc.name: TaskCloseDMic_002
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseDMic_002, TestSize.Level1)
{
    std::string args;
    std::string devId;
    sinkDev_->micClient_ = std::make_shared<DMicClient>(devId, sinkDev_);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDMic(args));
    sinkDev_->engineFlag_ = false;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDMic(args));
}

/**
 * @tc.name: TaskSetParameter_001
 * @tc.desc: Verify the TaskSetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetParameter_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetParameter(args));
}

/**
 * @tc.name: TaskSetParameter_002
 * @tc.desc: Verify the TaskSetParameter function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetParameter_002, TestSize.Level1)
{
    std::string args;
    std::string devId;
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetParameter(args));
}

/**
 * @tc.name: TaskSetVolume_001
 * @tc.desc: Verify the TaskSetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetVolume_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetVolume(args));
}

/**
 * @tc.name: TaskSetVolume_002
 * @tc.desc: Verify the TaskSetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetVolume_002, TestSize.Level1)
{
    std::string args;
    std::string devId;
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetVolume(args));
}

/**
 * @tc.name: TaskSetMute_001
 * @tc.desc: Verify the TaskSetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetMute_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetMute(args));
}

/**
 * @tc.name: TaskSetMute_002
 * @tc.desc: Verify the TaskSetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetMute_002, TestSize.Level1)
{
    std::string args;
    std::string devId;
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetMute(args));
}

/**
 * @tc.name: TaskVolumeChange_001
 * @tc.desc: Verify the TaskVolumeChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskVolumeChange_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskVolumeChange(args));
}

/**
 * @tc.name: TaskVolumeChange_002
 * @tc.desc: Verify the TaskVolumeChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskVolumeChange_002, TestSize.Level1)
{
    std::string args;
    std::string devId = "devId";
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskVolumeChange(args));
}

/**
 * @tc.name: TaskFocusChange_001
 * @tc.desc: Verify the TaskFocusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskFocusChange_001, TestSize.Level1)
{
    std::string args;
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskFocusChange(args));
}

/**
 * @tc.name: TaskFocusChange_002
 * @tc.desc: Verify the TaskFocusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskFocusChange_002, TestSize.Level1)
{
    std::string args;
    std::string devId = "devId";
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskFocusChange(args));
}

/**
 * @tc.name: TaskRenderStateChange_001
 * @tc.desc: Verify the TaskRenderStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskRenderStateChange_001, TestSize.Level1)
{
    std::string args;
    std::string dhId = "dhId";
    int32_t result = 0;
    sinkDev_->engineFlag_ = false;
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
    sinkDev_->engineFlag_ = true;
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
    sinkDev_->NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, dhId, result);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskRenderStateChange(args));
}

/**
 * @tc.name: TaskRenderStateChange_002
 * @tc.desc: Verify the TaskRenderStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskRenderStateChange_002, TestSize.Level1)
{
    std::string args;
    std::string devId = "devId";
    json j;
    AudioParam audioParam;
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskRenderStateChange(args));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->from_json(j, audioParam));
}

/**
 * @tc.name: SendAudioEventToRemote_001
 * @tc.desc: Verify the SendAudioEventToRemote function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SendAudioEventToRemote_001, TestSize.Level1)
{
    sinkDev_->engineFlag_ = false;
    AudioEvent event;
    std::string args;
    std::string devId = "devId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
}

/**
 * @tc.name: SendAudioEventToRemote_002
 * @tc.desc: Verify the SendAudioEventToRemote function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SendAudioEventToRemote_002, TestSize.Level1)
{
    std::string devId = "devId";
    AudioEvent event;
    sinkDev_->engineFlag_ = true;
    sinkDev_->speakerClient_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
}
} // DistributedHardware
} // OHOS
