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
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "daudio_sink_ipc_callback_proxy.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkDevTest::SetUpTestCase(void) {}

void DAudioSinkDevTest::TearDownTestCase(void) {}

void DAudioSinkDevTest::SetUp()
{
    std::string networkId = "networkId";
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    sinkDev_ = std::make_shared<DAudioSinkDev>(networkId, dAudioSinkIpcCallbackProxy);
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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskPlayStatusChange(""));

    std::string devId = "devid";
    int32_t dhId = 1;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskPlayStatusChange("{\"dhId\":\"1\"}"));
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
    std::string args = "{\"dhId\":\"1\"}";
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
    std::string args = "{\"dhId\":\"1\"}";
    std::string devId = "devId";
    int32_t dhId = 1;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
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
    int32_t dhId = 1;
    std::string args = "{\"dhId\":\"1\"}";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskStartRender(args));
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskStartRender(args));
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
    std::string args = "{\"dhId\":\"1\"}";
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
    std::string args = "{\"dhId\":\"123\"}";
    std::string devId;
    int32_t dhId = 1 << 27 | 1 << 0;
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
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
    int32_t dhId = 1;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
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
    int32_t dhId = 1;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
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
    int32_t dhId = 1;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
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
    std::string args = "{\"dhId\":\"123\"}";
    std::string dhId = "123";
    int32_t result = 0;
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
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
    int32_t dhId = 1;
    AudioEvent event;
    event.content = "{\"dhId\":\"123\"}";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
}
} // DistributedHardware
} // OHOS
