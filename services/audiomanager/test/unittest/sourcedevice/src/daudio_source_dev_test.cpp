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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDMic(event));
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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDSpeaker(event));
    event.type = SPEAKER_OPENED;
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleDSpeakerOpened(event));
    event.type = CLOSE_SPEAKER;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleCloseDSpeaker(event));
    event.type = SPEAKER_CLOSED;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleDSpeakerClosed(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDMic(event));
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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDSpeaker(event));

    event.type = OPEN_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleOpenDMic(event));
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
    event.type = OPEN_SPEAKER;
    sourceDev_->NotifyEvent(event);
    event.type = CLOSE_SPEAKER;
    sourceDev_->NotifyEvent(event);
    event.type = SPEAKER_OPENED;
    sourceDev_->NotifyEvent(event);
    event.type = SPEAKER_CLOSED;
    sourceDev_->NotifyEvent(event);
    event.type = NOTIFY_OPEN_SPEAKER_RESULT;
    sourceDev_->NotifyEvent(event);
    event.type = NOTIFY_CLOSE_SPEAKER_RESULT;
    sourceDev_->NotifyEvent(event);
    event.type = NOTIFY_OPEN_MIC_RESULT;
    sourceDev_->NotifyEvent(event);
    event.type = NOTIFY_CLOSE_MIC_RESULT;
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
    // Create play status change event with empty content
    AudioEvent event = AudioEvent(CHANGE_PLAY_STATUS, "");
    // Verify the function returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandlePlayStatusChange(event));

    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify the function returns success after device wakeup
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
    // Set event type to open speaker result
    AudioEventType type = NOTIFY_OPEN_SPEAKER_RESULT;
    // Verify RPC wait timeout
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));

    // Change event type to play status change
    type = CHANGE_PLAY_STATUS;
    // Verify RPC wait timeout
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, sourceDev_->WaitForRPC(type));

    // Set RPC result to failed
    sourceDev_->rpcResult_ = ERR_DH_AUDIO_FAILED;
    // Set event type to open speaker result
    type = NOTIFY_OPEN_SPEAKER_RESULT;
    // Set RPC notify event for speaker open
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    // Verify the function returns failed result
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
    // Set RPC result to success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Set event type to open speaker result
    AudioEventType type = NOTIFY_OPEN_SPEAKER_RESULT;
    // Set RPC notify event for speaker open
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_SPK;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    // Keep RPC result as success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Change event type to close speaker result
    type = NOTIFY_CLOSE_SPEAKER_RESULT;
    // Set RPC notify event for speaker close
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_SPK;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    // Keep RPC result as success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Change event type to open mic result
    type = NOTIFY_OPEN_MIC_RESULT;
    // Set RPC notify event for mic open
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_MIC;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    // Keep RPC result as success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Change event type to close mic result
    type = NOTIFY_CLOSE_MIC_RESULT;
    // Set RPC notify event for mic close
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_MIC;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    // Keep RPC result as success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Change event type to open ctrl result
    type = NOTIFY_OPEN_CTRL_RESULT;
    // Set RPC notify event for ctrl open
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_OPEN_CTRL;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->WaitForRPC(type));

    // Keep RPC result as success
    sourceDev_->rpcResult_ = DH_SUCCESS;
    // Change event type to close ctrl result
    type = NOTIFY_CLOSE_CTRL_RESULT;
    // Set RPC notify event for ctrl close
    sourceDev_->rpcNotify_ = sourceDev_->EVENT_NOTIFY_CLOSE_CTRL;
    // Verify the function returns success
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
    // Create ctrl closed event with empty content
    AudioEvent event = AudioEvent(CTRL_CLOSED, "");
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Set DH ID to default render ID
    int32_t dhId = DEFAULT_RENDER_ID;
    // Add speaker device to device map
    sourceDev_->deviceMap_[dhId] = speaker;
    // Mark speaker as not opened
    speaker->isOpened_ = false;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    // Mark speaker as opened
    speaker->isOpened_ = true;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));

    // Create mic device instance
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Mark speaker as not opened
    speaker->isOpened_ = false;
    // Verify the function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->HandleCtrlTransClosed(event));
    // Mark speaker as opened
    speaker->isOpened_ = true;
    // Verify the function returns success
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
    // Create RPC event with empty content
    AudioEvent event(NOTIFY_OPEN_SPEAKER_RESULT, "");
    // Verify invalid parameter error
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->HandleNotifyRPC(event));

    // Create string exceeding max JSON length
    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    // Set over-length content to event
    event.content = tempLongStr;
    // Verify invalid parameter error
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
    // Create RPC event with invalid content
    AudioEvent event(NOTIFY_OPEN_SPEAKER_RESULT, "result");
    // Verify null pointer error
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
    // Create JSON object
    cJSON *jParam = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jParam);
    // Add success result to JSON object
    cJSON_AddNumberToObject(jParam, KEY_RESULT, DH_SUCCESS);
    // Convert JSON to unformatted string
    char *jsonString = cJSON_PrintUnformatted(jParam);
    // Check JSON string is not null
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    // Create event with JSON content
    AudioEvent event(CHANGE_PLAY_STATUS, std::string(jsonString));
    // Release JSON object
    cJSON_Delete(jParam);
    // Release JSON string
    cJSON_free(jsonString);
    // Verify key not found error
    EXPECT_EQ(ERR_DH_AUDIO_NOT_FOUND_KEY, sourceDev_->HandleNotifyRPC(event));

    // Change event type to open speaker result
    event.type = NOTIFY_OPEN_SPEAKER_RESULT;
    // Verify the function returns success
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
    // Create empty audio event
    AudioEvent event;
    // Verify null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleSpkMmapStart(event));

    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify the function returns success
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
    // Create empty audio event
    AudioEvent event;
    // Verify null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleSpkMmapStop(event));

    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify the function returns success
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
    // Create empty audio event
    AudioEvent event;
    // Verify null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleMicMmapStart(event));

    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify the function returns success
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
    // Create empty audio event
    AudioEvent event;
    // Verify null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->HandleMicMmapStop(event));

    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify the function returns success
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
    // Verify enable function with empty string returns invalid param
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(""));
    // Verify disable function with empty string returns invalid param
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskDisableDAudio(""));

    // Create string exceeding max JSON length
    std::string tempLongStr(DAUDIO_MAX_JSON_LEN + 1, 'a');
    // Verify enable function with over-length string returns invalid param
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sourceDev_->TaskEnableDAudio(tempLongStr));
    // Verify disable function with over-length string returns invalid param
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
    sourceDev_->OnDisableTaskResult(DH_SUCCESS, tempLongStr, FUNC_NAME);

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
    // Set default render device ID
    int32_t dhId = DEFAULT_RENDER_ID;
    // Verify enable speaker function returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDSpeaker(dhId, ATTRS));
    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[dhId] = speaker;
    // Verify enable speaker function returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDSpeaker(dhId, ATTRS));
    // Remove speaker from device map
    sourceDev_->deviceMap_[dhId] = nullptr;
    // Define test string parameters
    std::string stra = "123";
    std::string strb = "1";
    // Set device full status to true
    sourceDev_->isFull_ = true;
    // Notify framework running status
    sourceDev_->NotifyFwkRunning(stra, strb);
    // Keep device full status as true
    sourceDev_->isFull_ = true;
    // Notify framework running status again
    sourceDev_->NotifyFwkRunning(stra, strb);
    // Verify enable speaker function returns null pointer error
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
    // Set default capture device ID
    int32_t dhId = DEFAULT_CAPTURE_ID;
    // Verify enable mic function returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, ATTRS));
    // Create mic device instance
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Add mic to device map
    sourceDev_->deviceMap_[dhId] = mic;
    // Verify enable mic function returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->EnableDMic(dhId, ATTRS));
    // Remove mic from device map
    sourceDev_->deviceMap_[dhId] = nullptr;

    // Verify enable mic function returns null pointer error
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
    // Set test device ID to 0
    int32_t dhId = 0;
    // Verify disable speaker function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));

    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Verify disable speaker function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDSpeaker(dhId));
    // Release speaker device instance
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
    // Set test device ID to 0
    int32_t dhId = 0;
    // Verify disable mic function returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->DisableDMic(dhId));

    // Create and set mic device instance
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Create another mic device instance
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Add mic to device map
    sourceDev_->deviceMap_[dhId] = mic;
    // Verify disable mic function returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->DisableDMic(dhId));
    // Release mic device instance
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
    // Create microphone device instance
    auto mic = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Set default capture device ID
    int32_t dhId = DEFAULT_CAPTURE_ID;
    // Add microphone to device map
    sourceDev_->deviceMap_[dhId] = mic;
    // Initialize microphone transport instance
    mic->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic);

    // Create JSON parameter object
    cJSON *jParam = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jParam);
    // Add microphone DH ID to JSON object
    cJSON_AddStringToObject(jParam, KEY_DH_ID, DH_ID_MIC.c_str());
    // Convert JSON object to unformatted string
    char *jsonString = cJSON_PrintUnformatted(jParam);
    // Check JSON string is not null
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    // Verify close microphone task returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskCloseDMic(std::string(jsonString)));
    // Release JSON object
    cJSON_Delete(jParam);
    // Release JSON string
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
    // Define audio event object
    AudioEvent event;
    // Set event content with DH ID
    event.content = "{\"dhId\":\"1\"}";
    // Verify microphone closed task returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskDMicClosed(event.content));
    // Put audio device into sleep mode
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
    // Define audio event object
    AudioEvent event;
    // Set event content with DH ID
    event.content = "{\"dhId\":\"1\"}";
    // Create and set microphone device instance
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Verify microphone closed task returns success
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
    // Set test device ID
    int32_t dhId = 3;
    // Create JSON parameter object
    cJSON *jParam = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jParam);
    // Add mute status to JSON object
    cJSON_AddNumberToObject(jParam, STREAM_MUTE_STATUS.c_str(), 3);
    // Add device ID to JSON object
    cJSON_AddStringToObject(jParam, "dhId", "3");
    // Convert JSON object to unformatted string
    char *jsonString = cJSON_PrintUnformatted(jParam);
    // Check JSON string is not null
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[dhId] = speaker;
    // Initialize speaker transport instance
    speaker->speakerTrans_ = std::make_shared<AVTransSenderTransport>(DEV_ID, speaker);
    // Initialize control transport for speaker
    speaker->InitCtrlTrans();
    // Construct parameter string
    std::string param = "dhId=3;" + std::string(jsonString);
    // Verify set volume task returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->TaskSetVolume(param));
    // Release JSON object
    cJSON_Delete(jParam);
    // Release JSON string
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
    // Create and set audio control manager
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    // Verify set volume task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskSetVolume(ARGS));

    // Create JSON parameter object
    cJSON *jParam = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jParam);
    // Add mute status to JSON object
    cJSON_AddNumberToObject(jParam, STREAM_MUTE_STATUS.c_str(), 1);
    // Convert JSON object to unformatted string
    char *jsonString = cJSON_PrintUnformatted(jParam);
    // Check JSON string is not null
    CHECK_NULL_AND_FREE_VOID(jsonString, jParam);
    // Verify set volume task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskSetVolume(std::string(jsonString)));
    // Release JSON object
    cJSON_Delete(jParam);
    // Release JSON string
    cJSON_free(jsonString);
    // Notify task result with null pointer error
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
    // Verify change volume task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskChangeVolume(ARGS));
    // Define test argument string
    std::string args = "{\"devId\":\"10\"}";
    // Verify change volume task returns failed
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
    // Verify change focus task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskChangeFocus(ARGS));
    // Define test argument string
    std::string args = "{\"devId\":\"10\"}";
    // Verify change focus task returns failed
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
    // Verify change render state task does not return success
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
    // Verify play status change task returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_PAUSE));

    // Create and set audio control manager
    sourceDev_->audioCtrlMgr_ = std::make_shared<DAudioSourceDevCtrlMgr>(DEV_ID, sourceDev_);
    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    // Verify pause play status change task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_PAUSE));
    // Verify restart play status change task does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->TaskPlayStatusChange(AUDIO_EVENT_RESTART));
    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Define test argument string
    std::string args = "{\"devId\":\"1\"}";
    // Add speaker to device map
    sourceDev_->deviceMap_[1] = speaker;
    // Verify play status change task does not return success
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
    // Verify speaker MMAP start task returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStart(ARGS));

    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[1] = speaker;
    // Verify speaker MMAP start task returns null pointer error
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
    // Verify speaker MMAP stop task returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskSpkMmapStop(ARGS));

    // Create speaker device instance
    auto speaker = std::make_shared<DSpeakerDev>(DEV_ID, nullptr);
    // Add speaker to device map
    sourceDev_->deviceMap_[1] = speaker;
    // Verify speaker MMAP stop task returns success
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
    // Verify microphone MMAP start task returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStart(ARGS));

    // Create microphone device instance
    auto mic = std::make_shared<DMicDev>(DEV_ID, nullptr);
    // Set default capture device ID
    int32_t dhId = DEFAULT_CAPTURE_ID;
    // Add microphone to device map
    sourceDev_->deviceMap_[dhId] = mic;
    // Verify microphone MMAP start task returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStart(ARGS));
    // Create audio data instance
    std::shared_ptr<AudioData> data = std::make_shared<AudioData>(AUDIO_DATA_CAP);
    // Fill data queue to maximum length
    for (size_t i = 0; i < TASK_QUEUE_LEN; i++) {
        mic->dataQueue_.push_back(data);
    }
    // Verify MMAP stop returns success
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
    // Verify microphone MMAP stop task returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->TaskMicMmapStop(ARGS));
    // Create microphone device instance
    auto mic = std::make_shared<DMicDev>(DEV_ID, nullptr);
    // Set test device ID
    int32_t dhId = 1;
    // Add microphone to device map
    sourceDev_->deviceMap_[dhId] = mic;

    // Verify microphone MMAP stop task returns success
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
    // Set event type to close microphone result
    AudioEventType type = NOTIFY_CLOSE_MIC_RESULT;
    // Define result string
    std::string result = "result";
    // Set test device ID
    int32_t dhId = 1;
    // Verify HDF notification does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));

    // Create and set microphone device instance
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Add microphone to device map
    sourceDev_->deviceMap_[dhId] = sourceDev_->mic_;
    // Verify HDF notification returns success
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
    // Set event type to audio focus change
    AudioEventType type = AUDIO_FOCUS_CHANGE;
    // Define result string
    std::string result = "result";
    // Set test device ID
    int32_t dhId = 1;
    // Verify HDF notification does not return success
    EXPECT_NE(DH_SUCCESS, sourceDev_->NotifyHDF(type, result, dhId));

    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
    // Verify HDF notification returns success
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
    // Set event type to unknown
    AudioEventType type = EVENT_UNKNOWN;
    // Define result string
    std::string result = "result";
    // Set test device ID
    int32_t dhId = 1;

    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
    // Verify HDF notification returns failed
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
    // Define null JSON parameter
    cJSON *jAudioParam = nullptr;
    // Set test device ID
    int32_t dhId = 1;
    // Set RPC open status to false
    sourceDev_->isRpcOpen_.store(false);
    // Verify sink device notification returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));

    // Set RPC open status to true
    sourceDev_->isRpcOpen_.store(true);
    // Verify sink device notification returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->NotifySinkDev(CLOSE_MIC, jAudioParam, DH_ID_SPK));
    // Create and set microphone device instance
    sourceDev_->mic_ = std::make_shared<DMicDev>(DEV_ID, sourceDev_);
    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Add speaker to device map
    sourceDev_->deviceMap_[dhId] = sourceDev_->speaker_;
    // Verify sink device notification returns success
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
    // Define audio event object
    AudioEvent event;
    // Set speaker instance to null
    sourceDev_->speaker_ = nullptr;
    // Verify send audio event returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceDev_->SendAudioEventToRemote(event));
    // Create and set speaker device instance
    sourceDev_->speaker_ = std::make_shared<DSpeakerDev>(DEV_ID, sourceDev_);
    // Verify send audio event returns null pointer error
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
    // Set test device ID
    int32_t dhId = 1;
    // Define test device ID string
    std::string devId = "123";
    // Define test attribute string
    std::string attrs = "1234";
    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Create microphone closed audio event
    AudioEvent event = AudioEvent(MIC_CLOSED, "{\"dhId\":\"1\"}");
    // Create audio event shared pointer
    auto eventParam = std::make_shared<AudioEvent>(event);
    // Get inner event for microphone closed
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DMIC_CLOSED, eventParam, 0);
    // Call microphone closed callback
    sourceDev_->handler_->DMicClosedCallback(msgEvent);
    // Put audio device into sleep mode
    sourceDev_->SleepAudioDev();
    // Create microphone device instance
    auto mic = std::make_shared<DMicDev>(devId, sourceDev_);
    // Insert microphone into device map
    sourceDev_->deviceMap_.insert(std::make_pair(dhId, mic));
    // Verify enable microphone function returns failed
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
    // Set test device ID
    int32_t dhId = 1;
    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Define empty audio event
    AudioEvent event;
    // Create audio event shared pointer
    auto eventParam = std::make_shared<AudioEvent>(event);
    // Get inner event for microphone closed
    auto msgEvent = AppExecFwk::InnerEvent::Get(EVENT_DMIC_CLOSED, eventParam, 0);
    // Call microphone closed callback
    sourceDev_->handler_->DMicClosedCallback(msgEvent);
    // Call set volume callback
    sourceDev_->handler_->SetVolumeCallback(msgEvent);
    // Call change volume callback
    sourceDev_->handler_->ChangeVolumeCallback(msgEvent);
    // Call change focus callback
    sourceDev_->handler_->ChangeFocusCallback(msgEvent);
    // Call change render state callback
    sourceDev_->handler_->ChangeRenderStateCallback(msgEvent);
    // Call play status change callback
    sourceDev_->handler_->PlayStatusChangeCallback(msgEvent);
    // Call speaker MMAP start callback
    sourceDev_->handler_->SpkMmapStartCallback(msgEvent);
    // Call speaker MMAP stop callback
    sourceDev_->handler_->SpkMmapStopCallback(msgEvent);
    // Call microphone MMAP start callback
    sourceDev_->handler_->MicMmapStartCallback(msgEvent);
    // Call microphone MMAP stop callback
    sourceDev_->handler_->MicMmapStopCallback(msgEvent);
    // Put audio device into sleep mode
    sourceDev_->SleepAudioDev();
    // Verify enable microphone function returns failed
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
    // Create speaker closed audio event
    AudioEvent event = AudioEvent(SPEAKER_CLOSED, "{\"dhId\":\"-1\"}");
    // Wake up the audio device
    sourceDev_->AwakeAudioDev();
    // Verify handle speaker closed returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->HandleDSpeakerClosed(event));
    // Verify disable audio returns not support
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(event.content));
    // Verify open speaker task returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceDev_->TaskOpenDSpeaker(event.content));
    // Define test argument string
    std::string args = "{\"dhId\":\"10\"}";
    // Verify disable audio returns not support
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(event.content));
    // Put audio device into sleep mode
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
    // Define test argument string
    std::string args = "{\"dhId\":\"10\"}";
    // Verify parsed DH ID is correct
    EXPECT_EQ(10, sourceDev_->ParseDhidFromEvent(args));
    // Define test argument with devId
    std::string args1 = "{\"devId\":\"10\"}";
    // Verify disable audio returns not support
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, sourceDev_->DisableDAudio(args1));
}

/**
 * @tc.name: EnableDAudio_001
 * @tc.desc: Verify the EnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, EnableDAudio_001, TestSize.Level1)
{
    // Verify wake up audio device returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->AwakeAudioDev());
    // Set device full status to true
    sourceDev_->isFull_.store(true);
    // Verify enable audio returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID_SPK, ATTRS));
    // Set device full status to false
    sourceDev_->isFull_.store(false);
    // Verify enable audio returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID_SPK, ATTRS));
    // Define meta data type argument
    std::string argsMeta = "{\"dataType\":\"meta\"}";
    // Verify enable audio returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID_SPK, argsMeta));
    // Define full data type argument
    std::string argsFull = "{\"dataType\":\"full\"}";
    // Verify enable audio returns success
    EXPECT_EQ(DH_SUCCESS, sourceDev_->EnableDAudio(DH_ID_SPK, argsFull));
}

/**
 * @tc.name: ParseValueFromCjson_001
 * @tc.desc: Verify the ParseValueFromCjson function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceDevTest, ParseValueFromCjson_001, TestSize.Level1)
{
    int32_t volume = 50;
    std::string jsonStr = "{\"OS_TYPE\": 50}";
    std::string key = "OS_TYPE";
    int32_t result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, volume);

    jsonStr = "invalid_json";
    key = "volume";
    result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "{\"brightness\": 80}";
    result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "{\"volume\": \"high\"}";
    result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "";
    result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "null";
    key = "volume";
    result = sourceDev_->ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);
}
} // namespace DistributedHardware
} // namespace OHOS
