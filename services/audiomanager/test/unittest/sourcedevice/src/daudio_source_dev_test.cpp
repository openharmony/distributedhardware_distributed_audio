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
#include "cJSON.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceDevTest"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string ATTRS = "attrs";
const std::string DEV_ID = "devId";
const std::string FUNC_NAME = "funcName";
const std::string ARGS = "{\"dhId\":\"1\"}";
const std::string DH_ID_MIC = "134217728";
const std::string DH_ID_SPK = "1";
const std::string DH_ID_UNKNOWN = "0";
const int32_t TASK_QUEUE_LEN = 20;
const size_t AUDIO_DATA_CAP = 1;
constexpr uint32_t EVENT_MMAP_SPK_START = 81;
constexpr uint32_t EVENT_MMAP_SPK_STOP = 82;
constexpr uint32_t EVENT_MMAP_MIC_START = 83;
constexpr uint32_t EVENT_MMAP_MIC_STOP = 84;
constexpr uint32_t EVENT_DMIC_CLOSED = 24;
constexpr uint32_t EVENT_OPEN_MIC = 21;

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

    AudioEvent event = AudioEvent(OPEN_SPEAKER, "{\"dhId\":\"1\"}");
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDMic(event));
    event.type = MIC_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicOpened(event));
    event.type = CLOSE_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseDMic(event));
    event.type = MIC_CLOSED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicClosed(event));

    int32_t dhId = DEFAULT_RENDER_ID;
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = speaker;
    speaker->isOpened_ = true;
    dhId = DEFAULT_CAPTURE_ID;
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = mic;
    mic->isOpened_ = true;
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

    AudioEvent event = AudioEvent(OPEN_SPEAKER, "{\"dhId\":\"1\"}");
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleOpenDMic(event));
    event.type = MIC_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDMicOpened(event));
    event.type = CLOSE_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseDMic(event));
    event.type = MIC_CLOSED;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleDMicClosed(event));

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
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDSpeaker(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleOpenDMic(event));
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));

    type = CHANGE_PLAY_STATUS;
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = ERR_DH_AUDIO_FAILED;
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
    sourceDev_->rpcResult_ = DH_SUCCESS;
    AudioEventType type = NOTIFY_OPEN_SPEAKER_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    type = NOTIFY_CLOSE_SPEAKER_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_SPK;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    type = NOTIFY_OPEN_MIC_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    type = NOTIFY_CLOSE_MIC_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_MIC;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    type = NOTIFY_OPEN_CTRL_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_CTRL;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    type = NOTIFY_CLOSE_CTRL_RESULT;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_CTRL;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));
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

    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    int32_t dhId = DEFAULT_RENDER_ID;
    sourceDev_->deviceMap_[dhId] = speaker;
    speaker->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    speaker->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    speaker->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    speaker->isOpened_ = true;
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleNotifyRPC(event));
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
    CHECK_NULL_VOID(jParam);
    cJSON_AddNumberToObject(jParam, KEY_RESULT, DH_SUCCESS);
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    AudioEvent event(CHANGE_PLAY_STATUS, std::string(jsonString));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
    EXPECT_EQ(ERR_DH_AUDIO_NOT_FOUND_KEY, sourceDev_->HandleNotifyRPC(event));

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
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDisableDAudio(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(tempLongStr));
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDisableDAudio(tempLongStr));
}

/**
 * @tc.name: TaskEnableDAudio_002
 * @tc.desc: Verify the TaskEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskEnableDAudio_002, TestSize.Level1)
{
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam, KEY_RESULT, "test_result");
    cJSON_AddStringToObject(jParam, KEY_DH_ID, "testDhId");
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(std::string(jsonString)));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskDisableDAudio(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);

    cJSON *jParam1 = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam1);
    cJSON_AddStringToObject(jParam1, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam1, KEY_DH_ID, DH_ID_UNKNOWN.c_str());
    cJSON_AddStringToObject(jParam1, KEY_ATTRS, "");
    char *jsonString1 = cJSON_PrintUnformatted(jParam1);
    CHECK_NULL_AND_FREE_VOID(jsonString1, jParam1);
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->TaskEnableDAudio(std::string(jsonString1)));
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->TaskDisableDAudio(std::string(jsonString1)));
    cJSON_Delete(jParam1);
    cJSON_free(jsonString1);

    cJSON *jParam2 = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam2);
    cJSON_AddStringToObject(jParam2, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam2, KEY_DH_ID, DH_ID_SPK.c_str());
    cJSON_AddStringToObject(jParam2, KEY_ATTRS, "");
    char *jsonString2 = cJSON_PrintUnformatted(jParam2);
    CHECK_NULL_AND_FREE_VOID(jsonString2, jParam2);
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(std::string(jsonString2)));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDisableDAudio(std::string(jsonString2)));
    cJSON_Delete(jParam2);
    cJSON_free(jsonString2);

    cJSON *jParam3 = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam3);
    cJSON_AddStringToObject(jParam3, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam3, KEY_DH_ID, DH_ID_MIC.c_str());
    cJSON_AddStringToObject(jParam3, KEY_ATTRS, "");
    char *jsonString3 = cJSON_PrintUnformatted(jParam3);
    CHECK_NULL_AND_FREE_VOID(jsonString3, jParam3);
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskEnableDAudio(std::string(jsonString3)));
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDisableDAudio(std::string(jsonString3)));
    cJSON_Delete(jParam3);
    cJSON_free(jsonString3);
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
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, "", FUNC_NAME);

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, tempLongStr, FUNC_NAME);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam, KEY_RESULT, "test_result");
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(jsonString), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(jsonString), FUNC_NAME);
    cJSON_Delete(jParam);
    cJSON_free(jsonString);

    cJSON *jParam1 = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam1);
    cJSON_AddStringToObject(jParam1, KEY_DEV_ID, DEV_ID.c_str());
    cJSON_AddStringToObject(jParam1, KEY_DH_ID, DH_ID_SPK.c_str());
    char *jsonString1 = cJSON_PrintUnformatted(jParam1);
    CHECK_NULL_AND_FREE_VOID(jsonString1, jParam1);

    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(jsonString1), FUNC_NAME);
    sourceDev_->OnEnableTaskResult(ERR_DH_AUDIO_NULLPTR, std::string(jsonString1), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(jsonString1), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(ERR_DH_AUDIO_NULLPTR, std::string(jsonString1), FUNC_NAME);

    sourceDev_->mgrCallback_ = nullptr;
    sourceDev_->OnEnableTaskResult(DH_SUCCESS, std::string(jsonString1), FUNC_NAME);
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, std::string(jsonString1), FUNC_NAME);
    cJSON_Delete(jParam1);
    cJSON_free(jsonString1);

    auto mgrCb = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_NE(DH_SUCCESS, mgrCb->OnEnableAudioResult(DEV_ID, DH_ID_SPK, DH_SUCCESS));
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
    int32_t dhId = DEFAULT_RENDER_ID;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDSpeaker(dhId, ATTRS));
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = speaker;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDSpeaker(dhId, ATTRS));
    sourceDev_->deviceMap_[dhId] = nullptr;

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->EnableDSpeaker(dhId, ATTRS));
}

/**
 * @tc.name: EnableDMic_001
 * @tc.desc: Verify the EnableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDMic_001, TestSize.Level1)
{
    int32_t dhId = DEFAULT_CAPTURE_ID;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, ATTRS));
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = mic;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, ATTRS));
    sourceDev_->deviceMap_[dhId] = nullptr;

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->EnableDMic(dhId, ATTRS));
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
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));
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
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDMic(dhId));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = mic;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDMic(dhId));
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
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDSpeaker(""));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDSpeaker(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDSpeaker(tempLongStr));

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskOpenDSpeaker(ARGS));

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    sourceDev_->isRpcOpen_.store(false);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskOpenDSpeaker(std::string(jsonString)));

    sourceDev_->isRpcOpen_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskOpenDSpeaker(std::string(jsonString)));

    sourceDev_->rpcResult_ = DH_SUCCESS;
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskOpenDSpeaker(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
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

    int32_t dhId = DEFAULT_RENDER_ID;
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = speaker;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(tempLongStr));

    speaker->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(ARGS));

    speaker->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(ARGS));

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDSpeaker(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
}

/**
 * @tc.name: TaskCloseDSpeaker_002
 * @tc.desc: Verify the TaskCloseDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDSpeaker_002, TestSize.Level1)
{
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    int32_t dhId = DEFAULT_RENDER_ID;
    sourceDev_->deviceMap_[dhId] = speaker;
    speaker->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, speaker);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_SPK.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDSpeaker(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
}

/**
 * @tc.name: TaskOpenDMic_001
 * @tc.desc: Verify the TaskOpenDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskOpenDMic_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDMic(""));

    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sourceDev_->deviceMap_[dhId] = mic;
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDMic(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskOpenDMic(tempLongStr));

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_MIC.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskOpenDMic(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
}

/**
 * @tc.name: TaskCloseDMic_001
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDMic_001, TestSize.Level1)
{
    std::string dhIdArgs = "{\"dhId\":\"1\"}";
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(dhIdArgs));
    std::string args = "{\"dhId\":\"-1\"}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskCloseDMic(args));

    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sourceDev_->deviceMap_[dhId] = mic;

    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDMic(""));

    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskCloseDMic(tempLongStr));

    mic->isOpened_ = true;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(ARGS));

    mic->isOpened_ = false;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(ARGS));

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_MIC.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
}

/**
 * @tc.name: TaskCloseDMic_002
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskCloseDMic_002, TestSize.Level1)
{
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sourceDev_->deviceMap_[dhId] = mic;
    mic->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic);

    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_MIC.c_str());
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
}

/**
 * @tc.name: TaskDMicClosed_001
 * @tc.desc: Verify the TaskDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDMicClosed_001, TestSize.Level1)
{
    AudioEvent event;
    event.content = "{\"dhId\":\"1\"}";
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDMicClosed(event.content));
    sourceDev_->SleepAudioDev();
}

/**
 * @tc.name: TaskDMicClosed_002
 * @tc.desc: Verify the TaskDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDMicClosed_002, TestSize.Level1)
{
    AudioEvent event;
    event.content = "{\"dhId\":\"1\"}";
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDMicClosed(event.content));
}

/**
 * @tc.name: TaskSetVolume_001
 * @tc.desc: Verify the TaskSetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskSetVolume_001, TestSize.Level1)
{
    int32_t dhId = 3;
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddNumberToObject(jParam, STREAM_MUTE_STATUS.c_str(), 3);
    cJSON_AddStringToObject(jParam, "dhId", "3");
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = speaker;
    speaker->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, speaker);
    std::string param = "dhId=3;" + std::string(jsonString);
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskSetVolume(param));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
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
    CHECK_NULL_VOID(jParam);
    cJSON_AddNumberToObject(jParam, STREAM_MUTE_STATUS.c_str(), 1);
    char *jsonString = cJSON_PrintUnformatted(jParam);
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskSetVolume(std::string(jsonString)));
    cJSON_Delete(jParam);
    cJSON_free(jsonString);
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
    std::string args = "{\"devId\":\"10\"}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskChangeVolume(args));
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
    std::string args = "{\"devId\":\"10\"}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskChangeFocus(args));
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
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    std::string args = "{\"devId\":\"1\"}";
    sourceDev_->deviceMap_[1] = speaker;
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskPlayStatusChange(args));
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

    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[1] = speaker;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStart(ARGS));
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

    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    sourceDev_->deviceMap_[1] = speaker;
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

    auto mic = std::make_shared<DMicDev>(DEV_ID, nullptr);
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sourceDev_->deviceMap_[dhId] = mic;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStart(ARGS));
    std::shared_ptr<AudioData> data = std::make_shared<AudioData>(AUDIO_DATA_CAP);
    for (size_t i = 0; i < TASK_QUEUE_LEN; i++) {
        mic->dataQueue_.push(data);
    }
    EXPECT_EQ(DH_SUCCESS, sourceDev_->deviceMap_[dhId]->MmapStop());
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
    auto mic = std::make_shared<DMicDev>(DEV_ID, nullptr);
    int32_t dhId = 1;
    sourceDev_->deviceMap_[dhId] = mic;

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
    int32_t dhId = 1;
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));

    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = sourceDev_->mic_;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));
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
    int32_t dhId = 1;
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));
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
    int32_t dhId = 1;

    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->NotifyHDF(type, result, dhId));
}

/**
 * @tc.name: NotifySinkDev_001
 * @tc.desc: Verify the NotifySinkDev function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, NotifySinkDev_001, TestSize.Level1)
{
    cJSON *jAudioParam = nullptr;
    int32_t dhId = 1;
    sourceDev_->isRpcOpen_.store(false);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));

    sourceDev_->isRpcOpen_.store(true);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
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

/**
 * @tc.name: TaskDMicClosed_003
 * @tc.desc: Verify the TaskDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDMicClosed_003, TestSize.Level1)
{
    std::string args = "";
    sourceDev_->AwakeAudioDev();
    AudioEvent event;
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_OPEN_MIC, eventParam, 0);
    sourceDev_->handler_->ProcessEvent(msgEvent);
    sourceDev_->handler_->OpenDSpeakerCallback(msgEvent);
    sourceDev_->handler_->CloseDSpeakerCallback(msgEvent);
    sourceDev_->handler_->OpenDMicCallback(msgEvent);
    sourceDev_->handler_->CloseDMicCallback(msgEvent);
    sourceDev_->SleepAudioDev();
    std::shared_ptr<AudioEvent> nullForFail = nullptr;
    auto msg = AppExecFwk::InnerEvent::Get(EVENT_OPEN_MIC, nullForFail, 0);
    sourceDev_->handler_->OpenDSpeakerCallback(msg);
    sourceDev_->handler_->CloseDSpeakerCallback(msg);
    sourceDev_->handler_->OpenDMicCallback(msg);
    sourceDev_->handler_->CloseDMicCallback(msg);
    sourceDev_->handler_->SetVolumeCallback(msg);
    sourceDev_->handler_->SetVolumeCallback(msg);
    sourceDev_->handler_->ChangeFocusCallback(msg);
    sourceDev_->handler_->ChangeRenderStateCallback(msg);
    sourceDev_->handler_->PlayStatusChangeCallback(msg);
    sourceDev_->handler_->SpkMmapStartCallback(msg);
    sourceDev_->handler_->SpkMmapStopCallback(msg);
    sourceDev_->handler_->MicMmapStartCallback(msg);
    sourceDev_->handler_->MicMmapStopCallback(msg);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDMicClosed(args));
}

/**
 * @tc.name: TaskDMicClosed_004
 * @tc.desc: Verify the TaskDMicClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, TaskDMicClosed_004, TestSize.Level1)
{
    std::string devId = "1";
    int32_t dhId = 1;
    std::string args = "{\"dhId\":\"1\"}";
    sourceDev_->AwakeAudioDev();
    AudioEvent event = AudioEvent(MIC_CLOSED, args);
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto mic = std::make_shared<DMicDev>(devId, sourceDev_);
    sourceDev_->deviceMap_.insert(std::make_pair(dhId, mic));
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_MMAP_MIC_START, eventParam, 0);
    sourceDev_->handler_->MicMmapStartCallback(msgEvent);
    auto msgEvent1 = AppExecFwk::InnerEvent::Get(EVENT_MMAP_MIC_STOP, eventParam, 0);
    sourceDev_->handler_->MicMmapStartCallback(msgEvent1);
    dhId = 2;
    args = "{\"dhId\":\"2\"}";
    AudioEvent event1 = AudioEvent(SPEAKER_CLOSED, args);
    auto eventParam2 = std::make_shared<AudioEvent>(event1);
    auto speaker = std::make_shared<DSpeakerDev>(devId, sourceDev_);
    sourceDev_->deviceMap_.insert(std::make_pair(dhId, mic));
    auto msgEvent3 = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_START, eventParam2, 0);
    sourceDev_->handler_->MicMmapStartCallback(msgEvent3);
    auto msgEvent4 = AppExecFwk::InnerEvent::Get(EVENT_MMAP_SPK_STOP, eventParam2, 0);
    sourceDev_->handler_->MicMmapStartCallback(msgEvent4);
    sourceDev_->SleepAudioDev();
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDMicClosed(args));
    args = "{\"dhId\":\"-1\"}";
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskDMicClosed(args));
}

/**
 * @tc.name: EnableDMic_002
 * @tc.desc: Verify the EnableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDMic_002, TestSize.Level1)
{
    int32_t dhId = 1;
    std::string devId = "123";
    std::string attrs = "1234";
    sourceDev_->AwakeAudioDev();
    AudioEvent event = AudioEvent(MIC_CLOSED, "{\"dhId\":\"1\"}");
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DMIC_CLOSED, eventParam, 0);
    sourceDev_->handler_->DMicClosedCallback(msgEvent);
    sourceDev_->SleepAudioDev();
    auto mic = std::make_shared<DMicDev>(devId, sourceDev_);
    sourceDev_->deviceMap_.insert(std::make_pair(dhId, mic));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, attrs));
}

/**
 * @tc.name: EnableDMic_003
 * @tc.desc: Verify the EnableDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDMic_003, TestSize.Level1)
{
    int32_t dhId = 1;
    sourceDev_->AwakeAudioDev();
    AudioEvent event;
    auto eventParam = std::make_shared<AudioEvent>(event);
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DMIC_CLOSED, eventParam, 0);
    sourceDev_->handler_->DMicClosedCallback(msgEvent);
    sourceDev_->handler_->SetVolumeCallback(msgEvent);
    sourceDev_->handler_->ChangeVolumeCallback(msgEvent);
    sourceDev_->handler_->ChangeFocusCallback(msgEvent);
    sourceDev_->handler_->ChangeRenderStateCallback(msgEvent);
    sourceDev_->handler_->PlayStatusChangeCallback(msgEvent);
    sourceDev_->handler_->SpkMmapStartCallback(msgEvent);
    sourceDev_->handler_->SpkMmapStopCallback(msgEvent);
    sourceDev_->handler_->MicMmapStartCallback(msgEvent);
    sourceDev_->handler_->MicMmapStopCallback(msgEvent);
    sourceDev_->SleepAudioDev();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, ATTRS));
}

/**
 * @tc.name: HandleDSpeakerClosed_002
 * @tc.desc: Verify the HandleDSpeakerClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, HandleDSpeakerClosed_002, TestSize.Level1)
{
    AudioEvent event = AudioEvent(SPEAKER_CLOSED, "{\"dhId\":\"-1\"}");
    sourceDev_->AwakeAudioDev();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleDSpeakerClosed(event));
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(event.content));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskOpenDSpeaker(event.content));
    std::string args = "{\"dhId\":\"10\"}";
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(event.content));
    sourceDev_->SleepAudioDev();
}

/**
 * @tc.name: ParseDhidFromEvent_001
 * @tc.desc: Verify the ParseDhidFromEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, ParseDhidFromEvent_001, TestSize.Level1)
{
    std::string args = "{\"dhId\":\"10\"}";
    EXPECT_EQ(10, sourceDev_->ParseDhidFromEvent(args));
    std::string args1 = "{\"devId\":\"10\"}";
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(args1));
}
} // namespace DistributedHardware
} // namespace OHOS
