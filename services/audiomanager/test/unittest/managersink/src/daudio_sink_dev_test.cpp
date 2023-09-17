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
    std::shared_ptr<IAVEngineProvider> senderPtr = std::make_shared<IAVEngineProvider>();
    std::shared_ptr<IAVEngineProvider> receiverPtr = std::make_shared<IAVEngineProvider>();
    ChannelState type = ChannelState::UNKNOWN;

    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->InitAVTransEngines(type, receiverPtr.get()));
    type = ChannelState::MIC_CONTROL_OPENED;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->InitAVTransEngines(type, senderPtr.get()));
    type = ChannelState::SPK_CONTROL_OPENED;
    EXPECT_EQ(DH_SUCCESS, sinkDev_->InitAVTransEngines(type, receiverPtr.get()));
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
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskOpenCtrlChannel(args));
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
}

/**
 * @tc.name: TaskStartRender_001
 * @tc.desc: Verify the TaskStartRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskStartRender_001, TestSize.Level1)
{
    std::string devId = "devId";
    sinkDev_->speakerClient_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskStartRender());
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskStartRender());
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
 * @tc.name: SendAudioEventToRemote_002
 * @tc.desc: Verify the SendAudioEventToRemote function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SendAudioEventToRemote_002, TestSize.Level1)
{
    std::string devId = "devId";
    AudioEvent event;
    sinkDev_->speakerClient_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
    sinkDev_->speakerClient_ = std::make_shared<DSpeakerClient>(devId, sinkDev_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
}
} // DistributedHardware
} // OHOS
