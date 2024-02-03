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
#include "daudio_log.h"
#include "iservice_registry.h"
#include "daudio_sink_ipc_callback_proxy.h"
#include "daudio_sink_load_callback.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkDevTest"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkDevTest::SetUpTestCase(void) {}

void DAudioSinkDevTest::TearDownTestCase(void) {}

void DAudioSinkDevTest::SetUp()
{
    std::string networkId = "networkId";
    std::string params = "params";
    samgr_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr_ == nullptr) {
        return;
    }
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr_->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr_->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    sinkDev_ = std::make_shared<DAudioSinkDev>(networkId, dAudioSinkIpcCallbackProxy);
}

void DAudioSinkDevTest::TearDown()
{
    if (samgr_ != nullptr) {
        samgr_->UnloadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    }
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
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskPlayStatusChange("{\"dhId\":\"1\"}"));
}

/**
 * @tc.name: TaskDisableDevice_001
 * @tc.desc: Verify the TaskDisableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskDisableDevice_001, TestSize.Level1)
{
    std::string spkName = "ohos.dhardware.daudio.dspeaker.ohos.dhardware.daudio.dmic";
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskDisableDevice(spkName));
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
 * @tc.name: ParseDhidFromEvent_001
 * @tc.desc: Verify the ParseDhidFromEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, ParseDhidFromEvent_001, TestSize.Level1)
{
    std::string args = "{\"devId\":\"1\"}";
    EXPECT_NE(DH_SUCCESS, sinkDev_->ParseDhidFromEvent(args));
    std::string dhIdArgs = "{\"dhId\": 1 }";
    EXPECT_NE(DH_SUCCESS, sinkDev_->ParseDhidFromEvent(dhIdArgs));
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
    std::string devIdArgs = "{\"devId\":\"1\"}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskStartRender(devIdArgs));
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
    std::string dhIdArgs = "{\"dhId\":1}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskCloseDMic(dhIdArgs));
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
    int32_t dhId = 1;
    std::string devId = "devId";
    args += "{\"dhId\":\"1\"}";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskSetParameter(args));
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
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
    std::string args = "{\"dhId\":\"1\"}";
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
    std::string args = "{\"dhId\":\"1\", \"eventType\":\"setMute\"}";
    std::string devId = "devId";
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
    int32_t dhIdSpk = 1;
    int32_t dhIdMic = 1 << 27 | 1 << 0;
    std::string args = "{\"dhId\":\"123\"}";
    std::string dhId = "123";
    std::string devId = "devId";
    int32_t result = 0;
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhIdSpk, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    auto micClient = std::make_shared<DMicClient>(devId, dhIdMic, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
    sinkDev_->NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, dhId, result);
    sinkDev_->NotifySourceDev(AUDIO_START, devId, result);
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
    cJSON *j = cJSON_CreateObject();
    CHECK_NULL_VOID(j);
    AudioParam audioParam;
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskRenderStateChange(args));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->from_json(j, audioParam));
    cJSON_Delete(j);
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

/**
 * @tc.name: PauseDistributedHardware_001
 * @tc.desc: Verify the PauseDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, PauseDistributedHardware_001, TestSize.Level1)
{
    std::string networkId = "networkId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->PauseDistributedHardware(networkId));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->ResumeDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, sinkDev_->StopDistributedHardware(networkId));
}

/**
 * @tc.name: JudgeDeviceStatus_001
 * @tc.desc: Verify the JudgeDeviceStatus function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, JudgeDeviceStatus_001, TestSize.Level1)
{
    sinkDev_->isSpkInUse_.store(true);
    sinkDev_->JudgeDeviceStatus();
    sinkDev_->isSpkInUse_.store(false);
    sinkDev_->isMicInUse_.store(false);
    sinkDev_->JudgeDeviceStatus();
    std::string args = "one";
    EXPECT_NE(DH_SUCCESS, sinkDev_->ConvertString2Int(args));
}

/**
 * @tc.name: SinkEventHandler_001
 * @tc.desc: Verify the SinkEventHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SinkEventHandler_001, TestSize.Level1)
{
    int32_t eventType = 2500;
    std::string eventContent = "eventContent";
    AudioEvent audioEvent(eventType, eventContent);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    sinkDev_->handler_->ProcessEvent(msgEvent);
    eventType = CTRL_OPENED;
    std::string content = "content";
    AudioEvent event(eventType, content);
    auto Param = std::make_shared<AudioEvent>(event);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(event.type), Param, 0);
    sinkDev_->handler_->ProcessEvent(msg);
    sinkDev_->handler_->NotifyCtrlOpened(msg);
    std::string networkId = "networkId";
    std::string devId;
    int32_t dhId = 134217729;
    sinkDev_->micDhId_ = "134217729";
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    EXPECT_EQ(DH_SUCCESS, sinkDev_->PauseDistributedHardware(networkId));
}

/**
 * @tc.name: SinkEventHandler_002
 * @tc.desc: Verify the SinkEventHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SinkEventHandler_002, TestSize.Level1)
{
    int32_t dhId = 1;
    int32_t eventType = CTRL_CLOSED;
    std::string eventContent = "{\"dhId\":\"1\"}";
    std::string devId = "devId";
    AudioEvent audioEvent(eventType, eventContent);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    sinkDev_->spkClientMap_[dhId] = nullptr;
    sinkDev_->micClientMap_[dhId] = nullptr;
    sinkDev_->handler_->NotifyCtrlClosed(msgEvent);
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    micClient->micTrans_ =nullptr;
    sinkDev_->handler_->NotifyCtrlClosed(msgEvent);
    std::string content = "content";
    AudioEvent event(eventType, content);
    auto Param = std::make_shared<AudioEvent>(event);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(event.type), Param, 0);
    sinkDev_->handler_->NotifyCtrlClosed(msg);
    std::string networkId = "networkId";
    dhId = 134217729;
    sinkDev_->micDhId_ = "134217729";
    micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    EXPECT_EQ(DH_SUCCESS, sinkDev_->ResumeDistributedHardware(networkId));
}

/**
 * @tc.name: SinkEventHandler_003
 * @tc.desc: Verify the SinkEventHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SinkEventHandler_003, TestSize.Level1)
{
    int32_t eventType = OPEN_SPEAKER;
    std::string eventContent = "{\"dhId\":\"dhId\",\"audioParam\":\"audioParam\"}";
    std::string devId = "devId";
    std::string networkId = "networkId";
    AudioEvent audioEvent(eventType, devId);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    sinkDev_->handler_->NotifyOpenSpeaker(msgEvent);
    sinkDev_->handler_->NotifyOpenMic(msgEvent);
    AudioEvent event(eventType, eventContent);
    auto Param = std::make_shared<AudioEvent>(event);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(event.type), Param, 0);
    sinkDev_->handler_->NotifyOpenSpeaker(msg);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->StopDistributedHardware(networkId));
}

/**
 * @tc.name: SinkEventHandler_004
 * @tc.desc: Verify the SinkEventHandler function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, SinkEventHandler_004, TestSize.Level1)
{
    int32_t eventType = OPEN_SPEAKER;
    std::shared_ptr<AudioEvent> nullForFail = nullptr;
    auto msgEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(eventType), nullForFail, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    sinkDev_->handler_->NotifyCtrlOpened(msgEvent);
    sinkDev_->handler_->NotifyCtrlClosed(msgEvent);
    sinkDev_->handler_->NotifyOpenSpeaker(msgEvent);
    sinkDev_->handler_->NotifyCloseSpeaker(msgEvent);
    sinkDev_->handler_->NotifySpeakerOpened(msgEvent);
    sinkDev_->handler_->NotifySpeakerClosed(msgEvent);
    sinkDev_->handler_->NotifyOpenMic(msgEvent);
    sinkDev_->handler_->NotifyCloseMic(msgEvent);
    sinkDev_->handler_->NotifyMicOpened(msgEvent);
    sinkDev_->handler_->NotifyMicClosed(msgEvent);
    sinkDev_->handler_->NotifySetVolume(msgEvent);
    sinkDev_->handler_->NotifyVolumeChange(msgEvent);
    sinkDev_->handler_->NotifySetParam(msgEvent);
    sinkDev_->handler_->NotifySetMute(msgEvent);
    sinkDev_->handler_->NotifyFocusChange(msgEvent);
    sinkDev_->handler_->NotifyRenderStateChange(msgEvent);
    sinkDev_->handler_->NotifyPlayStatusChange(msgEvent);
    std::string eventContent = "{\"dhId\":\"1\"}";
    std::string paramResult;
    AudioEvent audioEvent(eventType, eventContent);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->handler_->GetEventParam(msg, paramResult));
}
} // DistributedHardware
} // OHOS
