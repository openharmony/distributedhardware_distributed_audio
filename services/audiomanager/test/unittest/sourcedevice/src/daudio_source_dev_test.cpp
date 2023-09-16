/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "audio_encode_transport.h"
#include "audio_decode_transport.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string ATTRS = "attrs";
const std::string DEV_ID = "devId";
const std::string FUNC_NAME = "funcName";
const std::string ARGS = "args";
const std::string DH_ID_MIC = "134217728";
const std::string DH_ID_SPK = "1";
const std::string DH_ID_UNKNOWN = "0";
const int32_t TASK_QUEUE_LEN = 20;
const size_t AUDIO_DATA_CAP = 1;

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
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID_SPK, ATTRS));

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

    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDAudio(DH_ID_SPK));
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->EnableDAudio(DH_ID_SPK, ATTRS));

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

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDAudio(DH_ID_SPK));
}

/**
 * @tc.name: CreatTasks_003
 * @tc.desc: Verify HandleOpenDSpeaker, HandleOpenDMic and HandleOpenCtrlTrans function produce task fail.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CreatTasks_003, TestSize.Level1)
{
    sourceDev_->AwakeAudioDev();
    AudioEvent event = AudioEvent(OPEN_SPEAKER, "");
    EXPECT_NE(ERR_DH_AUDIO_SA_OPEN_CTRL_FAILED, sourceDev_->HandleOpenDSpeaker(event));

    event.type = OPEN_MIC;
    EXPECT_NE(ERR_DH_AUDIO_SA_OPEN_CTRL_FAILED, sourceDev_->HandleOpenDMic(event));
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

    sourceDev_->AwakeAudioDev();
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

    type = CHANGE_PLAY_STATUS;
    EXPECT_EQ(ERR_DH_AUDIO_SA_RPC_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = false;
    type = NOTIFY_OPEN_SPEAKER_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->WaitForRPC(type));
}

/**
 * @tc.name: WaitForRPC_002
 * @tc.desc: Verify the WaitForRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, WaitForRPC_002, TestSize.Level1)
{
    sourceDev_->rpcResult_ = true;
    AudioEventType type = NOTIFY_OPEN_SPEAKER_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = true;
    type = NOTIFY_CLOSE_SPEAKER_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_SPK;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = true;
    type = NOTIFY_OPEN_MIC_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = true;
    type = NOTIFY_CLOSE_MIC_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = true;
    type = NOTIFY_OPEN_CTRL_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_CTRL;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = true;
    type = NOTIFY_CLOSE_CTRL_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_CTRL;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));
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
    EXPECT_NE(ERR_DH_AUDIO_SA_OPEN_CTRL_FAILED, sourceDev_->OpenCtrlTrans(event));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->OpenCtrlTrans(event));
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    sourceDev_->audioCtrlMgr_->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->OpenCtrlTrans(event));

    sourceDev_->audioCtrlMgr_->isOpened_ = false;
    sourceDev_->AwakeAudioDev();
    EXPECT_EQ(DH_SUCCESS, sourceDev_->OpenCtrlTrans(event));
    sourceDev_->audioCtrlMgr_ = nullptr;
}

/**
 * @tc.name: CloseCtrlTrans_001
 * @tc.desc: Verify the CloseCtrlTrans function without task queue.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CloseCtrlTrans_001, TestSize.Level1)
{
    AudioEvent event;
    bool isSpk = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    EXPECT_NE(ERR_DH_AUDIO_NULLPTR, sourceDev_->CloseCtrlTrans(event, isSpk));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));
}

/**
 * @tc.name: CloseCtrlTrans_002
 * @tc.desc: Verify the CloseCtrlTrans function with task queue run.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, CloseCtrlTrans_002, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->AwakeAudioDev();

    bool isSpk = false;
    sourceDev_->mic_ = nullptr;
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));

    sourceDev_->speaker_->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));

    isSpk = true;
    sourceDev_->speaker_ = nullptr;
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->mic_->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->CloseCtrlTrans(event, isSpk));

    sourceDev_->mic_->isOpened_ = true;
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

    sourceDev_->AwakeAudioDev();
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenCtrlTrans(event));
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

    sourceDev_->AwakeAudioDev();
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseCtrlTrans(event));
}

/**
 * @tc.name: HandleCtrlTransClosed_001
 * @tc.desc: Verify the HandleCtrlTransClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleCtrlTransClosed_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(CTRL_CLOSED, "");
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    sourceDev_->speaker_->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    sourceDev_->speaker_->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
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

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    event.content = tempLongStr;
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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleNotifyRPC(event));
}

/**
 * @tc.name: HandleNotifyRPC_003
 * @tc.desc: Verify the HandleNotifyRPC function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleNotifyRPC_003, TestSize.Level1)
{
    cJSON *jParam = cJSON_CreateObject();
    EXPECT_NE(NULL, cJSON_AddNumberToObject(jParam, KEY_RESULT, DH_SUCCESS));
    AudioEvent event(CHANGE_PLAY_STATUS, std::string(cJSON_PrintUnformatted(jParam)));
    EXPECT_EQ(ERR_DH_AUDIO_NOT_FOUND_KEY, sourceDev_->HandleNotifyRPC(event));
    cJSON_Delete(jParam);

    event.type = NOTIFY_OPEN_SPEAKER_RESULT;
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleSpkMmapStart(event));

    sourceDev_->AwakeAudioDev();
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleSpkMmapStop(event));

    sourceDev_->AwakeAudioDev();
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleMicMmapStart(event));

    sourceDev_->AwakeAudioDev();
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleMicMmapStop(event));

    sourceDev_->AwakeAudioDev();
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(tempLongStr));

    cJSON *jParam1 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam1, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam1, KEY_RESULT, "test_result");
    EXPECT_EQ(ERR_DH_AUDIO_SA_ENABLE_PARAM_INVALID,
              sourceDev_->TaskEnableDAudio(std::string(cJSON_PrintUnformatted(jParam1))));
    cJSON_Delete(jParam1);

    cJSON *jParam2 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam2, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam2, KEY_DH_ID, "testDhId");
    cJSON_AddStringToObject(jParam2, KEY_ATTRS, "");
    EXPECT_EQ(ERR_DH_AUDIO_SA_ENABLE_PARAM_INVALID,
              sourceDev_->TaskEnableDAudio(std::string(cJSON_PrintUnformatted(jParam2))));
    cJSON_Delete(jParam2);

    cJSON *jParam3 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam3, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam3, KEY_DH_ID, DH_ID_UNKNOWN.c_str());
    cJSON_AddStringToObject(jParam3, KEY_ATTRS, "");
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT,
              sourceDev_->TaskEnableDAudio(std::string(cJSON_PrintUnformatted(jParam3))));
    cJSON_Delete(jParam3);

    cJSON *jParamSpk = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamSpk, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParamSpk, KEY_DH_ID, DH_ID_SPK.c_str());
    cJSON_AddStringToObject(jParamSpk, KEY_ATTRS, "");
    EXPECT_EQ(ERR_DH_AUDIO_FAILED,
              sourceDev_->TaskEnableDAudio(std::string(cJSON_PrintUnformatted(jParamSpk))));
    cJSON_Delete(jParamSpk);

    cJSON *jParamMic = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamMic, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParamMic, KEY_DH_ID, DH_ID_MIC.c_str());
    cJSON_AddStringToObject(jParamMic, KEY_ATTRS, "");
    EXPECT_EQ(ERR_DH_AUDIO_FAILED,
              sourceDev_->TaskEnableDAudio(std::string(cJSON_PrintUnformatted(jParamMic))));
    cJSON_Delete(jParamMic);
}

/**
 * @tc.name: TaskDisableDAudio_001
 * @tc.desc: Verify the TaskDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDisableDAudio_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDisableDAudio(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDisableDAudio(tempLongStr));

    cJSON *jParam1 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam1, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam1, KEY_RESULT, "test_result");
    EXPECT_EQ(ERR_DH_AUDIO_SA_DISABLE_PARAM_INVALID,
              sourceDev_->TaskDisableDAudio(std::string(cJSON_PrintUnformatted(jParam1))));
    cJSON_Delete(jParam1);

    cJSON *jParam2 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam2, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam2, KEY_DH_ID, "testDhId");
    EXPECT_EQ(ERR_DH_AUDIO_SA_DISABLE_PARAM_INVALID,
              sourceDev_->TaskDisableDAudio(std::string(cJSON_PrintUnformatted(jParam2))));
    cJSON_Delete(jParam2);

    cJSON *jParam3 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam3, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam3, KEY_DH_ID, DH_ID_UNKNOWN.c_str());
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT,
              sourceDev_->TaskDisableDAudio(std::string(cJSON_PrintUnformatted(jParam3))));
    cJSON_Delete(jParam3);

    cJSON *jParamSpk = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamSpk, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParamSpk, KEY_DH_ID, DH_ID_SPK.c_str());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
              sourceDev_->TaskDisableDAudio(std::string(cJSON_PrintUnformatted(jParamSpk))));
    cJSON_Delete(jParamSpk);

    cJSON *jParamMic = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamMic, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParamMic, KEY_DH_ID, DH_ID_MIC.c_str());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
              sourceDev_->TaskDisableDAudio(std::string(cJSON_PrintUnformatted(jParamMic))));
    cJSON_Delete(jParamMic);
}

/**
 * @tc.name: OnEnableTaskResult_001
 * @tc.desc: Verify the OnEnableTaskResult and OnEnableAudioResult function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, OnEnableTaskResult_001, TestSize.Level1)
{
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, "", FUNC_NAME);

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, tempLongStr, FUNC_NAME);

    cJSON *jParam1 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam1, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam1, KEY_RESULT, "test_result");
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam1)), FUNC_NAME);
    cJSON_Delete(jParam1);

    cJSON *jParam2 = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam2, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam2, KEY_DH_ID, DH_ID_SPK.c_str());
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam2)), FUNC_NAME);
    sourceDev_->OnEnableTaskResult(ERR_DH_AUDIO_NULLPTR, std::string(cJSON_PrintUnformatted(jParam2)), FUNC_NAME);

    sourceDev_->mgrCallback_ = nullptr;
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam2)), FUNC_NAME);
    cJSON_Delete(jParam2);

    auto mgrCb = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_NE(DH_SUCCESS, mgrCb->OnEnableAudioResult(DEV_ID, DH_ID_SPK, DH_SUCCESS));
}

/**
 * @tc.name: OnDisableTaskResult_001
 * @tc.desc: Verify the OnDisableTaskResult and OnDisableAudioResult function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, OnDisableTaskResult_001, TestSize.Level1)
{
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, "", FUNC_NAME);

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, tempLongStr, FUNC_NAME);

    cJSON *jParam = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam, KEY_RESULT, "test_result");
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam)), FUNC_NAME);

    cJSON_AddStringToObject(jParam, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam)), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(ERR_DH_AUDIO_NULLPTR, std::string(cJSON_PrintUnformatted(jParam)), FUNC_NAME);

    sourceDev_->mgrCallback_ = nullptr;
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(cJSON_PrintUnformatted(jParam)), FUNC_NAME);
    cJSON_Delete(jParam);

    auto mgrCb = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_NE(DH_SUCCESS, mgrCb->OnDisableAudioResult(DEV_ID, DH_ID_SPK, DH_SUCCESS));
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
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->EnableDSpeaker(dhId, ATTRS));
    sourceDev_->speaker_ = nullptr;

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
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->EnableDMic(dhId, ATTRS));
    sourceDev_->mic_ = nullptr;

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

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));
    sourceDev_->speaker_ = nullptr;
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

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_NE(DH_SUCCESS, sourceDev_->DisableDMic(dhId));
    sourceDev_->mic_ = nullptr;
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

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDSpeaker(tempLongStr));

    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskOpenDSpeaker(ARGS));

    cJSON *jParamSpk = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamSpk, KEY_DH_ID, DH_ID_SPK.c_str());
    sourceDev_->isRpcOpen_.store(false);
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE,
              sourceDev_->TaskOpenDSpeaker(std::string(cJSON_PrintUnformatted(jParamSpk))));

    sourceDev_->isRpcOpen_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE,
              sourceDev_->TaskOpenDSpeaker(std::string(cJSON_PrintUnformatted(jParamSpk))));

    sourceDev_->rpcResult_ = true;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskOpenDSpeaker(std::string(cJSON_PrintUnformatted(jParamSpk))));
    cJSON_Delete(jParamSpk);
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

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDSpeaker(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDSpeaker(tempLongStr));

    sourceDev_->speaker_->isOpened_ = true;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(ARGS));

    sourceDev_->speaker_->isOpened_ = false;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(ARGS));

    cJSON *jParamSpk = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamSpk, KEY_DH_ID, DH_ID_SPK.c_str());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(std::string(cJSON_PrintUnformatted(jParamSpk))));
    cJSON_Delete(jParamSpk);
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
    sourceDev_->speaker_->speakerTrans_ = std::make_shared<AudioEncodeTransport>(DEV_ID);

    cJSON *jParamSpk = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamSpk, KEY_DH_ID, DH_ID_SPK.c_str());
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(std::string(cJSON_PrintUnformatted(jParamSpk))));
    cJSON_Delete(jParamSpk);
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
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, sourceDev_->TaskOpenDMic(""));

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, sourceDev_->TaskOpenDMic(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, sourceDev_->TaskOpenDMic(tempLongStr));

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, sourceDev_->TaskOpenDMic(ARGS));

    cJSON *jParamMic = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamMic, KEY_DH_ID, DH_ID_MIC.c_str());
    EXPECT_EQ(ERR_DH_AUDIO_TRANS_NULL_VALUE, sourceDev_->TaskOpenDMic(std::string(cJSON_PrintUnformatted(jParamMic))));
    cJSON_Delete(jParamMic);
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

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDMic(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDMic(tempLongStr));

    sourceDev_->mic_->isOpened_ = true;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDMic(ARGS));

    sourceDev_->mic_->isOpened_ = false;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDMic(ARGS));

    cJSON *jParamMic = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamMic, KEY_DH_ID, DH_ID_MIC.c_str());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(std::string(cJSON_PrintUnformatted(jParamMic))));
    cJSON_Delete(jParamMic);
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
    sourceDev_->mic_->micTrans_ = std::make_shared<AudioDecodeTransport>(DEV_ID);

    cJSON *jParamMic = cJSON_CreateObject();
    cJSON_AddStringToObject(jParamMic, KEY_DH_ID, DH_ID_MIC.c_str());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(std::string(cJSON_PrintUnformatted(jParamMic))));
    cJSON_Delete(jParamMic);
}

/**
 * @tc.name: TaskOpenCtrlChannel_001
 * @tc.desc: Verify the TaskOpenCtrlChannel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskOpenCtrlChannel_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(""));

    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(tempLongStr));

    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(ARGS));

    cJSON *jParam = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    sourceDev_->isRpcOpen_.store(false);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(std::string(cJSON_PrintUnformatted(jParam))));

    sourceDev_->isRpcOpen_.store(true);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(std::string(cJSON_PrintUnformatted(jParam))));

    sourceDev_->rpcResult_ = true;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_MIC;
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskOpenCtrlChannel(std::string(cJSON_PrintUnformatted(jParam))));
    cJSON_Delete(jParam);
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

    cJSON *jParam = cJSON_CreateObject();
    cJSON_AddStringToObject(jParam, STREAM_MUTE_STATUS.c_str(), std::to_string(1).c_str());
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskSetVolume(std::string(cJSON_PrintUnformatted(jParam))));
    cJSON_Delete(jParam);

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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_PAUSE));

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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStart(ARGS));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStart(ARGS));
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStop(ARGS));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStart(ARGS));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStart(ARGS));
    std::shared_ptr<AudioData> data = std::make_shared<AudioData>(AUDIO_DATA_CAP);
    for (size_t i = 0; i < TASK_QUEUE_LEN; i++) {
        sourceDev_->mic_->dataQueue_.push(data);
    }
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStop(ARGS));

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
    cJSON *jAudioParam = cJSON_CreateObject();

    sourceDev_->isRpcOpen_.store(false);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));

    sourceDev_->isRpcOpen_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));
}

/**
 * @tc.name: SendAudioEventToRemote_002
 * @tc.desc: Verify the SendAudioEventToRemote function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, SendAudioEventToRemote_002, TestSize.Level1)
{
    AudioEvent event;
    sourceDev_->speaker_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->SendAudioEventToRemote(event));
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->SendAudioEventToRemote(event));
}
} // namespace DistributedHardware
} // namespace OHOS
