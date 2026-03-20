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
    // Create sender engine provider instance
    std::shared_ptr<IAVEngineProvider> senderPtr = std::make_shared<IAVEngineProvider>();
    // Create receiver engine provider instance
    std::shared_ptr<IAVEngineProvider> receiverPtr = std::make_shared<IAVEngineProvider>();
    // Set channel type to unknown
    ChannelState type = ChannelState::UNKNOWN;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify engine initialization returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->InitAVTransEngines(type, receiverPtr.get()));
    // Set channel type to mic control opened
    type = ChannelState::MIC_CONTROL_OPENED;
    // Verify sender engine initialization returns success
    EXPECT_EQ(DH_SUCCESS, sinkDev_->InitAVTransEngines(type, senderPtr.get()));
    // Set channel type to speaker control opened
    type = ChannelState::SPK_CONTROL_OPENED;
    // Verify receiver engine initialization returns success
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
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify status change with empty string returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskPlayStatusChange(""));

    // Define test device ID
    std::string devId = "devid";
    // Define test DH ID
    int32_t dhId = 1;
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    // Verify status change with valid JSON returns success
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
    // Define test speaker device name
    std::string spkName = "ohos.dhardware.daudio.dspeaker.ohos.dhardware.daudio.dmic";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify device disable returns success
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
    // Initialize empty arguments
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify open speaker with empty args returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDSpeaker(args));
    // Resize args to exceed maximum length
    args.resize(DAUDIO_MAX_JSON_LEN + 1);
    // Verify open speaker returns invalid parameter error
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sinkDev_->TaskOpenDSpeaker(args));
}

/**
 * @tc.name: TaskOpenDSpeaker_002
 * @tc.desc: Verify the TaskOpenDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDSpeaker_002, TestSize.Level1)
{
    // Define test arguments
    std::string args = "args";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify open speaker returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDSpeaker(args));
}

/**
 * @tc.name: TaskOpenDSpeaker_003
 * @tc.desc: Verify the TaskOpenDSpeaker function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDSpeaker_003, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "1";
    // Define test DH ID
    int32_t dhId = 1;
    // Create JSON object
    cJSON *jobject = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jobject);
    // Add DH ID to JSON
    cJSON_AddStringToObject(jobject, KEY_DH_ID, "1");
    // Add sampling rate to JSON
    cJSON_AddNumberToObject(jobject, KEY_SAMPLING_RATE, 0);
    // Add format to JSON
    cJSON_AddNumberToObject(jobject, KEY_FORMAT, 0);
    // Add channels to JSON
    cJSON_AddNumberToObject(jobject, KEY_CHANNELS, 0);
    // Add content type to JSON
    cJSON_AddNumberToObject(jobject, KEY_CONTENT_TYPE, 0);
    // Add stream usage to JSON
    cJSON_AddNumberToObject(jobject, KEY_STREAM_USAGE, 0);
    // Add source type to JSON
    cJSON_AddNumberToObject(jobject, KEY_SOURCE_TYPE, 0);
    // Print JSON to string
    char *jsonData = cJSON_PrintUnformatted(jobject);
    // Check JSON data and free if null
    CHECK_NULL_AND_FREE_VOID(jsonData, jobject);
    // Convert JSON data to string
    std::string args(jsonData);
    // Free JSON memory
    cJSON_free(jsonData);
    // Delete JSON object
    cJSON_Delete(jobject);
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify open speaker returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDSpeaker(args));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify open speaker returns failure
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
    // Define valid JSON arguments
    std::string args = "{\"dhId\":\"1\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify close speaker returns success
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
    // Define valid JSON arguments
    std::string args = "{\"dhId\":\"1\"}";
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    int32_t dhId = 1;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify close speaker returns success
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDSpeaker(args));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify close speaker returns success
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
    // Define JSON with device ID
    std::string args = "{\"devId\":\"1\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify parse DH ID returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->ParseDhidFromEvent(args));
    // Define JSON with DH ID
    std::string dhIdArgs = "{\"dhId\": 1 }";
    // Verify parse DH ID returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->ParseDhidFromEvent(dhIdArgs));
}

/**
 * @tc.name: ParseResultFromEvent_001
 * @tc.desc: Verify the ParseResultFromEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, ParseResultFromEvent_001, TestSize.Level1)
{
    // Define JSON with string result
    std::string args = "{\"result\":\"-40001\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify parse result returns -1
    EXPECT_EQ(-1, sinkDev_->ParseResultFromEvent(args));
    // Define JSON with numeric result
    std::string dhIdArgs = "{\"result\": 1 }";
    // Verify parse result returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->ParseResultFromEvent(dhIdArgs));

    // Create JSON object
    cJSON *jobject = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jobject);
    // Add success result to JSON
    cJSON_AddNumberToObject(jobject, KEY_RESULT, 0);
    // Print JSON to string
    char *jsonData = cJSON_PrintUnformatted(jobject);
    // Check JSON data and free if null
    CHECK_NULL_AND_FREE_VOID(jsonData, jobject);
    // Convert JSON data to string
    std::string args1(jsonData);
    // Free JSON memory
    cJSON_free(jsonData);
    // Delete JSON object
    cJSON_Delete(jobject);
    // Verify parse result returns success
    EXPECT_EQ(DH_SUCCESS, sinkDev_->ParseResultFromEvent(args1));
}

/**
 * @tc.name: TaskStartRender_001
 * @tc.desc: Verify the TaskStartRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskStartRender_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    int32_t dhId = 1;
    // Define valid JSON arguments
    std::string args = "{\"dhId\":\"1\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify start render returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskStartRender(args));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify start render returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskStartRender(args));
    // Define JSON with device ID
    std::string devIdArgs = "{\"devId\":\"1\"}";
    // Verify start render returns failure
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
    // Initialize empty arguments
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify open mic returns failure
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
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Set device level status to true
    sinkDev_->isDevLevelStatus_ = true;
    // Define test device ID
    std::string devId = "1";
    // Define test DH ID
    int32_t dhId = 1;
    // Create JSON object
    cJSON *jobject = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(jobject);
    // Add DH ID to JSON
    cJSON_AddStringToObject(jobject, KEY_DH_ID, "1");
    // Add sampling rate to JSON
    cJSON_AddNumberToObject(jobject, KEY_SAMPLING_RATE, 0);
    // Add format to JSON
    cJSON_AddNumberToObject(jobject, KEY_FORMAT, 0);
    // Add channels to JSON
    cJSON_AddNumberToObject(jobject, KEY_CHANNELS, 0);
    // Add content type to JSON
    cJSON_AddNumberToObject(jobject, KEY_CONTENT_TYPE, 0);
    // Add stream usage to JSON
    cJSON_AddNumberToObject(jobject, KEY_STREAM_USAGE, 0);
    // Add source type to JSON
    cJSON_AddNumberToObject(jobject, KEY_SOURCE_TYPE, 0);
    // Print JSON to string
    char *jsonData = cJSON_PrintUnformatted(jobject);
    // Check JSON data and free if null
    CHECK_NULL_AND_FREE_VOID(jsonData, jobject);
    // Convert JSON data to string
    std::string args(jsonData);
    // Free JSON memory
    cJSON_free(jsonData);
    // Delete JSON object
    cJSON_Delete(jobject);
    // Verify open mic returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDMic(args));
    // Create mic client instance
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    // Insert mic client into map
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    // Verify open mic returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskOpenDMic(args));
}

/**
 * @tc.name: TaskOpenDMic_003
 * @tc.desc: Verify the TaskOpenDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskOpenDMic_003, TestSize.Level1)
{
    // Initialize empty arguments
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Set device level status to true
    sinkDev_->isDevLevelStatus_ = true;
    // Verify open mic returns invalid parameter error
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, sinkDev_->TaskOpenDMic(args));
    // Define JSON with DH ID
    args = "{\"dhId\":\"1\"}";
    // Verify open mic returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskOpenDMic(args));
    // Define invalid JSON arguments
    args = "{\"KEY_DH_ID\":\"1\", \"KEY_AUDIO_PARAM\":\"param\"}}";
    // Verify open mic returns failure
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
    // Define valid JSON arguments
    std::string args = "{\"dhId\":\"1\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify close mic returns success
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
    // Define JSON with test DH ID
    std::string args = "{\"dhId\":\"123\"}";
    // Initialize empty device ID
    std::string devId;
    // Define test DH ID with bit shift
    int32_t dhId = 1 << 27 | 1 << 0;
    // Create mic client instance
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Insert mic client into map
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    // Verify close mic returns success
    EXPECT_EQ(DH_SUCCESS, sinkDev_->TaskCloseDMic(args));
    // Define JSON with numeric DH ID
    std::string dhIdArgs = "{\"dhId\":1}";
    // Verify close mic returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskCloseDMic(dhIdArgs));
}

/**
 * @tc.name: TaskCloseDMic_003
 * @tc.desc: Verify the TaskCloseDMic function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskCloseDMic_003, TestSize.Level1)
{
    // Define JSON with negative DH ID
    std::string args = "{\"dhId\":\"-1\"}";
    // Initialize empty device ID
    std::string devId;
    // Define test DH ID
    int32_t dhId = 1;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Set page status to true
    sinkDev_->isPageStatus_ = true;
    // Verify close mic returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->TaskCloseDMic(args));
    // Define JSON with valid DH ID
    args = "{\"dhId\":\"1\"}";
    // Create mic client instance
    auto micClient = std::make_shared<DMicClient>(devId, dhId, sinkDev_);
    // Insert mic client into map
    sinkDev_->micClientMap_.insert(std::make_pair(dhId, micClient));
    // Verify close mic returns success
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
    // Initialize empty arguments
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify set parameter with empty args returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetParameter(args));
    // Define test DH ID
    int32_t dhId = 1;
    // Define test device ID
    std::string devId = "devId";
    // Append valid JSON to arguments
    args += "{\"dhId\":\"1\"}";
    // Verify set parameter returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->TaskSetParameter(args));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify set parameter returns failure
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
    // Initialize empty arguments string
    std::string args;
    // Initialize empty device ID
    std::string devId;
    // Define test DH ID
    int32_t dhId = 1;
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Insert speaker client into the map
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    // Verify set parameter returns failure with empty args
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
    // Initialize empty arguments string
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify set volume returns failure with empty args
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
    // Define JSON format arguments with DH ID
    std::string args = "{\"dhId\":\"1\"}";
    // Initialize empty device ID
    std::string devId;
    // Define test DH ID
    int32_t dhId = 1;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify set volume returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetVolume(args));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into the map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify set volume returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetVolume(args));
    // Define invalid non-JSON arguments
    std::string args1 = "dhId=1";
    // Verify set volume returns failure with invalid format
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetVolume(args1));
}

/**
 * @tc.name: TaskSetMute_001
 * @tc.desc: Verify the TaskSetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskSetMute_001, TestSize.Level1)
{
    // Initialize empty arguments string
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify set mute returns failure with empty args
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
    // Define JSON arguments with DH ID and event type
    std::string args = "{\"dhId\":\"1\", \"eventType\":\"setMute\"}";
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    int32_t dhId = 1;
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Insert speaker client into the map
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    // Verify set mute returns failure
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetMute(args));
    // Define invalid non-JSON arguments
    std::string args1 = "dhId=1";
    // Verify set mute returns failure with invalid format
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskSetMute(args1));
}

/**
 * @tc.name: TaskVolumeChange_001
 * @tc.desc: Verify the TaskVolumeChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, TaskVolumeChange_001, TestSize.Level1)
{
    // Initialize empty arguments string
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify volume change returns failure with empty args
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
    // Initialize empty arguments string
    std::string args;
    // Define test device ID
    std::string devId = "devId";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Create and set audio control manager
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    // Verify volume change returns failure
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
    // Initialize empty arguments string
    std::string args;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify focus change returns failure with empty args
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
    // Initialize empty arguments string
    std::string args;
    // Define test device ID
    std::string devId = "devId";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Create and set audio control manager
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    // Verify focus change returns failure
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
    std::string dhIdS = "1";
    std::string dhIdM = "134217729";
    int32_t result = 0;
    ASSERT_NE(sinkDev_, nullptr);
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhIdSpk, sinkDev_);
    sinkDev_->spkClientMap_.insert(std::make_pair(DEFAULT_RENDER_ID, spkClient));
    auto micClient = std::make_shared<DMicClient>(devId, dhIdMic, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    sinkDev_->NotifySourceDev(AUDIO_START, dhId, result);
    sinkDev_->NotifySourceDev(NOTIFY_OPEN_CTRL_RESULT, dhId, result);
    sinkDev_->NotifySourceDev(NOTIFY_CLOSE_CTRL_RESULT, dhId, result);
    sinkDev_->NotifySourceDev(AUDIO_START, devId, result);
    sinkDev_->NotifySourceDev(AUDIO_START, dhIdS, result);
    sinkDev_->NotifySourceDev(AUDIO_START, dhIdM, result);
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
    // Initialize empty arguments string
    std::string args;
    // Define test device ID
    std::string devId = "devId";
    // Create JSON object for parameter parsing test
    cJSON *j = cJSON_CreateObject();
    // Check JSON object is not null
    CHECK_NULL_VOID(j);
    // Define audio parameter structure
    AudioParam audioParam;
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Create and set audio control manager
    sinkDev_->audioCtrlMgr_ = std::make_shared<DAudioSinkDevCtrlMgr>(devId, sinkDev_);
    // Verify render state change returns failure with empty args
    EXPECT_NE(DH_SUCCESS, sinkDev_->TaskRenderStateChange(args));
    // Verify JSON to audio parameter conversion returns failure
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sinkDev_->from_json(j, audioParam));
    // Release JSON object memory
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
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    int32_t dhId = 1;
    // Initialize audio event structure
    AudioEvent event;
    // Set event content with valid DH ID JSON
    event.content = "{\"dhId\":\"1\"}";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Verify send audio event returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->SendAudioEventToRemote(event));
    // Create speaker client instance
    auto spkClient = std::make_shared<DSpeakerClient>(devId, dhId, sinkDev_);
    // Insert speaker client into map
    sinkDev_->spkClientMap_.insert(std::make_pair(dhId, spkClient));
    // Verify send audio event returns null pointer error
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
    // Define test network ID
    std::string networkId = "networkId";
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Pull up device page
    sinkDev_->PullUpPage();
    // Verify pause distributed hardware returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->PauseDistributedHardware(networkId));
    // Verify resume distributed hardware returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sinkDev_->ResumeDistributedHardware(networkId));
    // Verify stop distributed hardware returns success
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
    // Verify device instance is not null
    ASSERT_NE(sinkDev_, nullptr);
    // Judge device status with default state
    sinkDev_->JudgeDeviceStatus();
    // Set speaker in use flag to true
    sinkDev_->isSpkInUse_.store(true);
    // Judge device status with speaker in use
    sinkDev_->JudgeDeviceStatus();
    // Set mic in use flag to true
    sinkDev_->isMicInUse_.store(true);
    // Judge device status with speaker and mic in use
    sinkDev_->JudgeDeviceStatus();
    // Set speaker in use flag to false
    sinkDev_->isSpkInUse_.store(false);
    // Judge device status with mic in use
    sinkDev_->JudgeDeviceStatus();
    // Define invalid string for integer conversion
    std::string args = "one";
    // Verify string to integer conversion returns failure
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
    ASSERT_NE(sinkDev_, nullptr);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    ASSERT_NE(sinkDev_->handler_, nullptr);
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
    ASSERT_NE(sinkDev_, nullptr);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    sinkDev_->spkClientMap_[dhId] = nullptr;
    sinkDev_->micClientMap_[dhId] = nullptr;
    ASSERT_NE(sinkDev_->handler_, nullptr);
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
    ASSERT_NE(sinkDev_, nullptr);
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
    ASSERT_NE(sinkDev_, nullptr);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    ASSERT_NE(sinkDev_->handler_, nullptr);
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
    sinkDev_->NotifyEvent(audioEvent);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    sinkDev_->handler_->NotifyCtrlOpened(msg);
    sinkDev_->handler_->NotifyCtrlClosed(msg);
    sinkDev_->handler_->NotifyOpenSpeaker(msg);
    sinkDev_->handler_->NotifyCloseSpeaker(msg);
    sinkDev_->handler_->NotifySpeakerOpened(msg);
    sinkDev_->handler_->NotifySpeakerClosed(msg);
    sinkDev_->handler_->NotifyOpenMic(msg);
    sinkDev_->handler_->NotifyCloseMic(msg);
    sinkDev_->handler_->NotifyMicOpened(msg);
    sinkDev_->handler_->NotifyMicClosed(msg);
    sinkDev_->handler_->NotifySetVolume(msg);
    sinkDev_->handler_->NotifyVolumeChange(msg);
    sinkDev_->handler_->NotifySetParam(msg);
    sinkDev_->handler_->NotifySetMute(msg);
    sinkDev_->handler_->NotifyFocusChange(msg);
    sinkDev_->handler_->NotifyRenderStateChange(msg);
    sinkDev_->handler_->NotifyPlayStatusChange(msg);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->handler_->GetEventParam(msg, paramResult));
}

/**
 * @tc.name: NotifyCtrlClosed_001
 * @tc.desc: Verify the NotifyCtrlClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, NotifyCtrlClosed_001, TestSize.Level1)
{
    std::string eventContent1 = "ohos.dhardware.daudio.dspeaker";
    std::string eventContent2 = "ohos.dhardware.daudio.dmic";
    std::string eventContent3 = "ohos.dhardware.daudio.dspeaker.ohos.dhardware.daudio.dmic";
    int32_t eventType = DISABLE_DEVICE;
    AudioEvent audioEvent(eventType, eventContent1);
    ASSERT_NE(sinkDev_, nullptr);
    sinkDev_->NotifyEvent(audioEvent);
    audioEvent.content = eventContent2;
    sinkDev_->NotifyEvent(audioEvent);
    audioEvent.content = eventContent3;
    sinkDev_->NotifyEvent(audioEvent);
    std::string eventContent = "{\"devId\":\"1\"}";
    std::string paramResult;
    audioEvent.type = OPEN_SPEAKER;
    audioEvent.content = eventContent;
    sinkDev_->NotifyEvent(audioEvent);
    auto eventParam = std::make_shared<AudioEvent>(audioEvent);
    auto msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    EXPECT_EQ(DH_SUCCESS, sinkDev_->AwakeAudioDev());
    ASSERT_NE(sinkDev_->handler_, nullptr);
    sinkDev_->handler_->NotifyCtrlClosed(msg);
    audioEvent.content = "{\"dhId\":\"134217729\"}";
    eventParam = std::make_shared<AudioEvent>(audioEvent);
    msg = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(audioEvent.type), eventParam, 0);
    sinkDev_->handler_->NotifyCtrlClosed(msg);
    int32_t dhIdMic = 1 << 27 | 1 << 0;;
    std::string devId = "devId";
    auto micClient = std::make_shared<DMicClient>(devId, dhIdMic, sinkDev_);
    sinkDev_->micClientMap_.insert(std::make_pair(DEFAULT_CAPTURE_ID, micClient));
    EXPECT_EQ(DH_SUCCESS, sinkDev_->handler_->GetEventParam(msg, paramResult));
}

/**
 * @tc.name: IsIdenticalAccounte_001
 * @tc.desc: Verify the IsIdenticalAccount function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkDevTest, IsIdenticalAccount_001, TestSize.Level1)
{
    ASSERT_NE(sinkDev_, nullptr);
    std::string networkId = "";
    EXPECT_EQ(false, sinkDev_->IsIdenticalAccount(networkId));
    networkId = "networkId";
    EXPECT_EQ(false, sinkDev_->IsIdenticalAccount(networkId));
}
} // DistributedHardware
} // OHOS
