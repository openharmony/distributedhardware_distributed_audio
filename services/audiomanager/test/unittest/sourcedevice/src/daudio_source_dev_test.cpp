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

#include "daudio_source_dev_test.h"
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string DH_ID = "Test_Dh_Id";
const std::string ATTRS = "attrs";
const std::string DEV_ID = "devId";
const std::string FUNC_NAME = "funcName";
const std::string ARGS = "args";
const std::string DH_ID_MIC = "134217728";
const std::string DH_ID_SPK = "1";
const std::string DH_ID_UNKNOWN = "0";

void DAudioSourceDevTest::SetUpTestCase(void) {}

void DAudioSourceDevTest::TearDownTestCase(void) {}

void DAudioSourceDevTest::SetUp(void)
{
    auto daudioMgrCallback = std::make_shared<DAudioSourceMgrCallback>();
    sourceDev_ = std::make_shared<DAudioSourceDev>(DEV_ID, daudioMgrCallback);
}

void DAudioSourceDevTest::TearDown(void)
{
    sourceDev_ = nullptr;
}

/**
 * @tc.name: CreatTasks_001
 * @tc.desc: Verify AwakeAudioDev function and creat tasks to process.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CreatTasks_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->AwakeAudioDev());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID, ATTRS));

    AudioEvent event = AudioEvent(OPEN_SPEAKER, "");
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDMic(event));
    event.type = MIC_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicOpened(event));
    event.type = CLOSE_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseDMic(event));
    event.type = MIC_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicClosed(event));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_->isOpened_ = true;
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->mic_->isOpened_ = true;
    event.type = CTRL_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    event.type = VOLUME_SET;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleVolumeSet(event));
    event.type = VOLUME_MUTE_SET;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleVolumeSet(event));
    event.type = VOLUME_CHANGE;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleVolumeChange(event));

    event.type = AUDIO_FOCUS_CHANGE;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleFocusChange(event));
    event.type = AUDIO_RENDER_STATE_CHANGE;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleRenderStateChange(event));

    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDAudio(DH_ID));
    sourceDev_->SleepAudioDev();
}

/**
 * @tc.name: CreatTasks_002
 * @tc.desc: Verify creat tasks to process, without AwakeAudioDev function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CreatTasks_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->EnableDAudio(DH_ID, ATTRS));

    AudioEvent event = AudioEvent(OPEN_SPEAKER, "");
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleOpenDMic(event));
    event.type = MIC_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicOpened(event));
    event.type = CLOSE_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseDMic(event));
    event.type = MIC_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicClosed(event));

    event.type = CTRL_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    event.type = VOLUME_SET;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleVolumeSet(event));
    event.type = VOLUME_MUTE_SET;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleVolumeSet(event));
    event.type = VOLUME_CHANGE;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleVolumeChange(event));

    event.type = AUDIO_FOCUS_CHANGE;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleFocusChange(event));
    event.type = AUDIO_RENDER_STATE_CHANGE;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleRenderStateChange(event));

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDAudio(DH_ID));
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify NotifyEvent function with VOLUME_SET event, after AwakeAudioDev function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifyEvent_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->AwakeAudioDev());
    AudioEvent event = AudioEvent(EVENT_UNKNOWN, "");
    sourceDev_->NotifyEvent(event);

    event.type = VOLUME_SET;
    sourceDev_->NotifyEvent(event);
    sourceDev_->SleepAudioDev();
}

/**
 * @tc.name: HandlePlayStatusChange_001
 * @tc.desc: Verify the HandlePlayStatusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandlePlayStatusChange_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(CHANGE_PLAY_STATUS, "");
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandlePlayStatusChange(event));

    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    sourceDev_->taskQueue_ = std::make_shared<TaskQueue>(20);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandlePlayStatusChange(event));
}

/**
 * @tc.name: WaitForRPC_001
 * @tc.desc: Verify the WaitForRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, WaitForRPC_001, TestSize.Level1)
{
    AudioEventType type = NOTIFY_OPEN_SPEAKER_RESULT;
    EXPECT_EQ(ERR_DH_AUDIO_SA_RPC_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));
}

/**
 * @tc.name: HandleDMicClosed_001
 * @tc.desc: Verify the HandleDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleDMicClosed_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicClosed(event));
    sourceDev_->SleepAudioDev();
}

/**
 * @tc.name: HandleDMicClosed_002
 * @tc.desc: Verify the HandleDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleDMicClosed_002, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicClosed(event));
}

/**
 * @tc.name: OpenCtrlTrans_001
 * @tc.desc: Verify the OpenCtrlTrans function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, OpenCtrlTrans_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_SA_OPEN_CTRL_FAILED, sourceDev_->OpenCtrlTrans(event));
}

/**
 * @tc.name: CloseCtrlTrans_001
 * @tc.desc: Verify the CloseCtrlTrans function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CloseCtrlTrans_001, TestSize.Level1)
{
    AudioEvent event;
    bool isSpk = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));
}

/**
 * @tc.name: HandleOpenCtrlTrans_001
 * @tc.desc: Verify the HandleOpenCtrlTrans function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleOpenCtrlTrans_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleOpenCtrlTrans(event));
}

/**
 * @tc.name: HandleCloseCtrlTrans_001
 * @tc.desc: Verify the HandleCloseCtrlTrans function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleCloseCtrlTrans_001, TestSize.Level1)
{
    AudioEvent event;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseCtrlTrans(event));
}

/**
 * @tc.name: HandleNotifyRPC_001
 * @tc.desc: Verify the HandleNotifyRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleNotifyRPC_001, TestSize.Level1)
{
    AudioEvent event(NOTIFY_OPEN_SPEAKER_RESULT, "");
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->HandleNotifyRPC(event));
}


/**
 * @tc.name: HandleNotifyRPC_002
 * @tc.desc: Verify the HandleNotifyRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleNotifyRPC_002, TestSize.Level1)
{
    AudioEvent event(NOTIFY_OPEN_SPEAKER_RESULT, "result");
    EXPECT_NE(DH_SUCCESS, sourceDev_->HandleNotifyRPC(event));
}

/**
 * @tc.name: HandleNotifyRPC_003
 * @tc.desc: Verify the HandleNotifyRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleNotifyRPC_003, TestSize.Level1)
{
    json jParam = { { KEY_RESULT, DH_SUCCESS } };
    AudioEvent event(NOTIFY_OPEN_SPEAKER_RESULT, jParam.dump());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleNotifyRPC(event));
}

/**
 * @tc.name: HandleSpkMmapStart_001
 * @tc.desc: Verify the HandleSpkMmapStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleSpkMmapStart_001, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->taskQueue_ = std::make_shared<TaskQueue>(20);
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleSpkMmapStart(event));
}

/**
 * @tc.name: HandleSpkMmapStop_001
 * @tc.desc: Verify the HandleSpkMmapStop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleSpkMmapStop_001, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->taskQueue_ = std::make_shared<TaskQueue>(20);
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleSpkMmapStop(event));
}

/**
 * @tc.name: HandleMicMmapStart_001
 * @tc.desc: Verify the HandleMicMmapStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleMicMmapStart_001, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->taskQueue_ = std::make_shared<TaskQueue>(20);
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleMicMmapStart(event));
}

/**
 * @tc.name: HandleMicMmapStop_001
 * @tc.desc: Verify the HandleMicMmapStop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleMicMmapStop_001, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->taskQueue_ = std::make_shared<TaskQueue>(20);
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleMicMmapStop(event));
}

/**
 * @tc.name: TaskEnableDAudio_001
 * @tc.desc: Verify the TaskEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskEnableDAudio_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(""));
    json jParam = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_SPK } };
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, jParam.dump(), FUNC_NAME);
    sourceDev_->OnEnableTaskResult(ERR_DH_AUDIO_NULLPTR, jParam.dump(), FUNC_NAME);
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, "", FUNC_NAME);

    sourceDev_->mgrCallback_ = nullptr;
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, jParam.dump(), FUNC_NAME);

    auto mgrCb = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_NE(DH_SUCCESS, mgrCb->OnEnableAudioResult(DEV_ID, DH_ID_SPK, DH_SUCCESS));
}

/**
 * @tc.name: TaskEnableDAudio_002
 * @tc.desc: Verify the TaskEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskEnableDAudio_002, TestSize.Level1)
{
    json jParam = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_UNKNOWN }, { KEY_ATTRS, "" } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(jParam.dump()));

    json jParam_spk = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_SPK }, { KEY_ATTRS, "" } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(jParam_spk.dump()));

    json jParam_mic = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_MIC }, { KEY_ATTRS, "" } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(jParam_mic.dump()));
}

/**
 * @tc.name: TaskDisableDAudio_001
 * @tc.desc: Verify the TaskDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDisableDAudio_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskDisableDAudio(""));
    json jParam = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_SPK } };
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, jParam.dump(), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(ERR_DH_AUDIO_NULLPTR, jParam.dump(), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, "", FUNC_NAME);

    sourceDev_->mgrCallback_ = nullptr;
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, jParam.dump(), FUNC_NAME);

    auto mgrCb = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_NE(DH_SUCCESS, mgrCb->OnDisableAudioResult(DEV_ID, DH_ID_SPK, DH_SUCCESS));
}

/**
 * @tc.name: TaskDisableDAudio_002
 * @tc.desc: Verify the TaskDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDisableDAudio_002, TestSize.Level1)
{
    json jParam = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_UNKNOWN } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskDisableDAudio(jParam.dump()));

    json jParam_spk = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_SPK } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskDisableDAudio(jParam_spk.dump()));

    json jParam_mic = { { KEY_DEV_ID, DEV_ID }, { KEY_DH_ID, DH_ID_MIC } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskDisableDAudio(jParam_mic.dump()));
}

/**
 * @tc.name: EnableDSpeaker_001
 * @tc.desc: Verify the EnableDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDSpeaker_001, TestSize.Level1)
{
    int32_t dhId = 0;
    EXPECT_NE(DH_SUCCESS, sourceDev_->EnableDSpeaker(dhId, ATTRS));
}

/**
 * @tc.name: EnableDMic_001
 * @tc.desc: Verify the EnableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDMic_001, TestSize.Level1)
{
    int32_t dhId = 0;
    EXPECT_NE(DH_SUCCESS, sourceDev_->EnableDMic(dhId, ATTRS));
}

/**
 * @tc.name: DisableDSpeaker_001
 * @tc.desc: Verify the DisableDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, DisableDSpeaker_001, TestSize.Level1)
{
    int32_t dhId = 0;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDSpeaker(dhId));
}

/**
 * @tc.name: DisableDSpeaker_002
 * @tc.desc: Verify the DisableDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, DisableDSpeaker_002, TestSize.Level1)
{
    int32_t dhId = 0;
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));
}

/**
 * @tc.name: DisableDMic_001
 * @tc.desc: Verify the DisableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, DisableDMic_001, TestSize.Level1)
{
    int32_t dhId = 0;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDMic(dhId));
}

/**
 * @tc.name: DisableDMic_002
 * @tc.desc: Verify the DisableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, DisableDMic_002, TestSize.Level1)
{
    int32_t dhId = 0;
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->DisableDMic(dhId));
}

/**
 * @tc.name: TaskOpenDSpeaker_001
 * @tc.desc: Verify the TaskOpenDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskOpenDSpeaker_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_SPEAKER_DEVICE_NOT_INIT, sourceDev_->TaskOpenDSpeaker(""));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDSpeaker(""));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskOpenDSpeaker(ARGS));

    json jParam_spk = { { KEY_DH_ID, DH_ID_SPK } };
    EXPECT_EQ(ERR_DH_AUDIO_SA_RPC_WAIT_TIMEOUT, sourceDev_->TaskOpenDSpeaker(jParam_spk.dump()));
}

/**
 * @tc.name: TaskCloseDSpeaker_001
 * @tc.desc: Verify the TaskCloseDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDSpeaker_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(ARGS));
}

/**
 * @tc.name: TaskCloseDSpeaker_002
 * @tc.desc: Verify the TaskCloseDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDSpeaker_002, TestSize.Level1)
{
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDSpeaker(""));

    json jParam_spk = { { KEY_DH_ID, DH_ID_SPK } };
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(jParam_spk.dump()));
}

/**
 * @tc.name: TaskOpenDMic_001
 * @tc.desc: Verify the TaskOpenDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskOpenDMic_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_MIC_DEVICE_NOT_INIT, sourceDev_->TaskOpenDMic(""));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDMic(""));
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, sourceDev_->TaskOpenDMic(ARGS));

    json jParam_mic = { { KEY_DH_ID, DH_ID_MIC } };
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, sourceDev_->TaskOpenDMic(jParam_mic.dump()));
}

/**
 * @tc.name: TaskCloseDMic_001
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDMic_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(ARGS));
}

/**
 * @tc.name: TaskCloseDMic_002
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDMic_002, TestSize.Level1)
{
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDMic(""));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDMic(ARGS));

    json jParam_mic = { { KEY_DH_ID, DH_ID_MIC } };
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(jParam_mic.dump()));
}

/**
 * @tc.name: TaskOpenCtrlChannel_001
 * @tc.desc: Verify the TaskOpenCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskOpenCtrlChannel_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskOpenCtrlChannel(""));

    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenCtrlChannel(""));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskOpenCtrlChannel(ARGS));

    json jParam = { { KEY_DH_ID, DH_ID_SPK } };
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(jParam.dump()));
}

/**
 * @tc.name: TaskCloseCtrlChannel_001
 * @tc.desc: Verify the TaskCloseCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseCtrlChannel_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseCtrlChannel(ARGS));

    sourceDev_->OnTaskResult(DH_SUCCESS, "", FUNC_NAME);
}

/**
 * @tc.name: TaskCloseCtrlChannel_002
 * @tc.desc: Verify the TaskCloseCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseCtrlChannel_002, TestSize.Level1)
{
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseCtrlChannel(ARGS));

    sourceDev_->OnTaskResult(DH_SUCCESS, "", FUNC_NAME);
}

/**
 * @tc.name: TaskSetVolume_001
 * @tc.desc: Verify the TaskSetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskSetVolume_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSetVolume(ARGS));
}

/**
 * @tc.name: TaskSetVolume_002
 * @tc.desc: Verify the TaskSetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskSetVolume_002, TestSize.Level1)
{
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskSetVolume(ARGS));

    sourceDev_->OnTaskResult(ERR_DH_AUDIO_NULLPTR, "", FUNC_NAME);
}

/**
 * @tc.name: TaskChangeVolume_001
 * @tc.desc: Verify the TaskChangeVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskChangeVolume_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskChangeVolume(ARGS));
}

/**
 * @tc.name: TaskChangeFocus_001
 * @tc.desc: Verify the TaskChangeFocus function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskChangeFocus_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskChangeFocus(ARGS));
}

/**
 * @tc.name: TaskChangeRenderState_001
 * @tc.desc: Verify the TaskChangeRenderState function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskChangeRenderState_001, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskChangeRenderState(ARGS));
}

/**
 * @tc.name: TaskPlayStatusChange
 * @tc.desc: Verify the TaskPlayStatusChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskPlayStatusChange_001, TestSize.Level1)
{
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_PAUSE));
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_RESTART));
}

/**
 * @tc.name: TaskSpkMmapStart
 * @tc.desc: Verify the TaskSpkMmapStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskSpkMmapStart_001, TestSize.Level1)
{
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    sourceDev_->speaker_->ashmem_ = new Ashmem(1, 20);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskSpkMmapStart(ARGS));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->speaker_->MmapStop());
}

/**
 * @tc.name: TaskSpkMmapStop
 * @tc.desc: Verify the TaskSpkMmapStop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskSpkMmapStop_001, TestSize.Level1)
{
    sourceDev_->mic_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskSpkMmapStop(ARGS));
}

/**
 * @tc.name: TaskMicMmapStart
 * @tc.desc: Verify the TaskMicMmapStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskMicMmapStart_001, TestSize.Level1)
{
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, nullptr);
    sourceDev_->mic_->ashmem_ = new Ashmem(1, 20);
    const size_t capacity = 1;
    std::shared_ptr<AudioData> data = std::make_shared<AudioData>(capacity);
    for (size_t i = 0; i < 20; i++) {
        sourceDev_->mic_->dataQueue_.push(data);
    }
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskMicMmapStart(ARGS));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->mic_->MmapStop());
}

/**
 * @tc.name: TaskMicMmapStop
 * @tc.desc: Verify the TaskMicMmapStop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskMicMmapStop_001, TestSize.Level1)
{
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, nullptr);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskMicMmapStop(ARGS));
}


/**
 * @tc.name: NotifyHDF_001
 * @tc.desc: Verify the NotifyHDF function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifyHDF_001, TestSize.Level1)
{
    AudioEventType type = NOTIFY_CLOSE_MIC_RESULT;
    std::string result = "result";
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->NotifyHDF(type, result));
}

/**
 * @tc.name: NotifyHDF_002
 * @tc.desc: Verify the NotifyHDF function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifyHDF_002, TestSize.Level1)
{
    AudioEventType type = AUDIO_FOCUS_CHANGE;
    std::string result = "result";
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->NotifyHDF(type, result));
}

/**
 * @tc.name: NotifyHDF_003
 * @tc.desc: Verify the NotifyHDF function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifyHDF_003, TestSize.Level1)
{
    AudioEventType type = EVENT_UNKNOWN;
    std::string result = "result";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->NotifyHDF(type, result));
}

/**
 * @tc.name: NotifySinkDev_001
 * @tc.desc: Verify the NotifySinkDev function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifySinkDev_001, TestSize.Level1)
{
    json jAudioParam;
    EXPECT_EQ(ERR_DH_AUDIO_SA_RPC_WAIT_TIMEOUT, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));
}
} // namespace DistributedHardware
} // namespace OHOS
