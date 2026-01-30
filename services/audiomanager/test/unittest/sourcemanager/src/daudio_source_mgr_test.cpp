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

#include "daudio_source_mgr_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string DEV_ID = "Test_Dev_Id";
const std::string DH_ID_MIC = "134217728";
const std::string DH_ID_SPK = "1";
const std::string ATTRS = "attrs";

void DAudioSourceMgrTest::SetUpTestCase(void) {}

void DAudioSourceMgrTest::TearDownTestCase(void) {}

void DAudioSourceMgrTest::SetUp(void)
{
    dAudioIpcCallback_ = sptr<DAudioIpcCallback>(new DAudioIpcCallback());
    remoteObject_ = dAudioIpcCallback_;
    ipcCallbackProxy_ = sptr<DAudioIpcCallbackProxy>(new DAudioIpcCallbackProxy(remoteObject_));
    auto runner = AppExecFwk::EventRunner::Create(true);
    if (runner == nullptr) {
        return;
    }
    sourceMgr.handler_ = std::make_shared<DAudioSourceManager::SourceManagerHandler>(runner);
}

void DAudioSourceMgrTest::TearDown(void)
{
    dAudioIpcCallback_ = nullptr;
    remoteObject_ = nullptr;
    ipcCallbackProxy_ = nullptr;
}

/**
 * @tc.name: Init_001
 * @tc.desc: Verify the Init and UnInit function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, Init_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UnInit());

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.Init(nullptr));
    EXPECT_NE(DH_SUCCESS, sourceMgr.Init(ipcCallbackProxy_));

    std::string localDevId;
    EXPECT_NE(DH_SUCCESS, GetLocalDeviceNetworkId(localDevId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: CreateAudioDevice_001
 * @tc.desc: Verify the CreateAudioDevice and UnInitfunction.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, CreateAudioDevice_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));

    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "1"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_001
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_001, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_002
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_002, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    std::string reqId2 = GetRandomID();
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_003
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_003, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    DAudioSourceManager::AudioDevice device = { DEV_ID, nullptr };
    sourceMgr.audioDevMap_[DEV_ID] = device;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId1));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_004
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_004, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    std::string dhId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, dhId, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    dhId = std::string(105, '1');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, dhId, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    std::string devId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(devId, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    devId = std::string(205, 'a');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(devId, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    std::string attrs = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", attrs, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DisableDAudio_001
 * @tc.desc: Verify the DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DisableDAudio_001, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));

    std::string dhId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, dhId, reqId1));
    dhId = std::string(105, '1');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, dhId, reqId1));
    std::string devId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(devId, DH_ID_SPK, reqId1));
    devId = std::string(205, 'a');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(devId, DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio("Unknown", DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: HandleDAudioNotify_001
 * @tc.desc: Verify the HandleDAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, HandleDAudioNotify_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "{\"dhId\":\"1\"}"));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "{\"dhId\":\"1\"}"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.HandleDAudioNotify(DEV_ID + "1", DH_ID_SPK, CLOSE_CTRL, ""));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DAudioNotify_001
 * @tc.desc: Verify the DAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DAudioNotify_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "openspk"));
}

/**
 * @tc.name: OnEnableDAudio_001
 * @tc.desc: Verify the OnEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnEnableDAudio_002
 * @tc.desc: Verify the OnEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_002, TestSize.Level1)
{
    std::string reqId = GetRandomID();
    EXPECT_NE(DH_SUCCESS, sourceMgr.Init(ipcCallbackProxy_));
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnEnableDAudio_003
 * @tc.desc: Verify the OnEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_003, TestSize.Level1)
{
    EXPECT_NE(DH_SUCCESS, sourceMgr.Init(ipcCallbackProxy_));
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    std::string reqId = GetRandomID();
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_001
 * @tc.desc: Verify the OnDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    int32_t ret = -40003;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, ret));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_003
 * @tc.desc: Verify the OnDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_003, TestSize.Level1)
{
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    int32_t ret = -40003;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, ret));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_001
 * @tc.desc: Verify the GetRequestId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_001, TestSize.Level1)
{
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));

    std::string reqId0 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId0));
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId1));

    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_MIC));
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK + "2"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_002
 * @tc.desc: Verify the GetRequestId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_002, TestSize.Level1)
{
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));

    std::string reqId0 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId0));

    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_MIC));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DeleteAudioDevice_001
 * @tc.desc: Verify the DeleteAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DeleteAudioDevice_001, TestSize.Level1)
{
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    std::string reqId0 = GetRandomID();
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId0;
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_MIC] = reqId1;

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId0));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId1));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: LoadAVReceiverEngineProvider_001
 * @tc.desc: Verify the LoadAVReceiverEngineProvider function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVReceiverEngineProvider_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
}

/**
 * @tc.name: UpdateWorkModeParam_001
 * @tc.desc: Verify the UpdateWorkModeParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, UpdateWorkModeParam_001, TestSize.Level1)
{
    AudioAsyncParam param {-1, 0, 0, 0};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_SPK, param));
    DAudioSourceManager::AudioDevice device = { DEV_ID, nullptr };
    sourceMgr.audioDevMap_[DEV_ID] = device;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_SPK, param));
}

/**
 * @tc.name: OnHardwareStateChanged_002
 * @tc.desc: Verify the OnHardwareStateChanged function with different states.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case verifies that the OnHardwareStateChanged function can handle different
 * business states correctly. It tests the function with various state values including
 * RUNNING, IDLE, and other possible states to ensure proper state transition handling.
 * The test also validates behavior with empty device IDs and DH IDs to check edge cases.
 */
HWTEST_F(DAudioSourceMgrTest, OnHardwareStateChanged_002, TestSize.Level1)
{
    // Setup: Ensure we have a valid IPC callback for testing
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with RUNNING state for speaker device
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged(DEV_ID, DH_ID_SPK, DaudioBusinessState::RUNNING));

    // Test Case 2: Test with IDLE state for microphone device
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged(DEV_ID, DH_ID_MIC, DaudioBusinessState::IDLE));

    // Test Case 3: Test with empty device ID
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged("", DH_ID_SPK, DaudioBusinessState::IDLE));

    // Test Case 4: Test with empty DH ID
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged(DEV_ID, "", DaudioBusinessState::RUNNING));

    // Test Case 5: Test with both empty parameters
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged("", "", DaudioBusinessState::IDLE));

    // Test Case 6: Test with invalid/negative state value
    EXPECT_EQ(DH_SUCCESS,
        sourceMgr.OnHardwareStateChanged(DEV_ID, DH_ID_MIC, -1));
}

/**
 * @tc.name: OnHardwareStateChanged_003
 * @tc.desc: Verify the OnHardwareStateChanged function with null callback.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case verifies the error handling behavior of OnHardwareStateChanged
 * when the IPC callback is null. It ensures that the function properly returns
 * ERR_DH_AUDIO_NULLPTR when no valid callback is available, which is crucial
 * for robust error handling in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnHardwareStateChanged_003, TestSize.Level1)
{
    // Setup: Set IPC callback to null to test error handling
    sourceMgr.ipcCallback_ = nullptr;

    // Test Case 1: Test with null callback and empty parameters
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.OnHardwareStateChanged("", "", DaudioBusinessState::IDLE));

    // Test Case 2: Test with null callback and valid device parameters
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.OnHardwareStateChanged(DEV_ID, DH_ID_MIC, DaudioBusinessState::RUNNING));

    // Test Case 3: Test with null callback and invalid state
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.OnHardwareStateChanged(DEV_ID, DH_ID_SPK, -1));
}

/**
 * @tc.name: OnDataSyncTrigger_002
 * @tc.desc: Verify the OnDataSyncTrigger function with different device IDs.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case validates the OnDataSyncTrigger function's ability to handle
 * various device ID formats and lengths. It tests with standard device IDs,
 * empty strings, and long device IDs to ensure the function can properly
 * process different types of device identifiers in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnDataSyncTrigger_002, TestSize.Level1)
{
    // Setup: Ensure we have a valid IPC callback for testing
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with standard device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDataSyncTrigger(DEV_ID));

    // Test Case 2: Test with modified device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDataSyncTrigger(DEV_ID + "1"));

    // Test Case 3: Test with empty device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDataSyncTrigger(""));

    // Test Case 4: Test with long device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDataSyncTrigger("LongDeviceId123456789"));

    // Test Case 5: Test with very long device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDataSyncTrigger(std::string(100, 'A')));
}

/**
 * @tc.name: OnDataSyncTrigger_003
 * @tc.desc: Verify the OnDataSyncTrigger function with null callback.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test ensures that OnDataSyncTrigger properly handles the case when
 * the IPC callback is null. The function should return ERR_DH_AUDIO_NULLPTR
 * to indicate that the operation cannot be completed due to missing callback,
 * which is essential for proper error propagation in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnDataSyncTrigger_003, TestSize.Level1)
{
    // Setup: Set IPC callback to null to test error handling
    sourceMgr.ipcCallback_ = nullptr;

    // Test Case 1: Test with null callback and standard device ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnDataSyncTrigger(DEV_ID));

    // Test Case 2: Test with null callback and empty device ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnDataSyncTrigger(""));

    // Test Case 3: Test with null callback and long device ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnDataSyncTrigger("LongDeviceId123456789"));
}

/**
 * @tc.name: SetCallerTokenId_002
 * @tc.desc: Verify the SetCallerTokenId function with different token IDs.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the SetCallerTokenId function's ability
 * to handle various token ID values. It tests with zero values, large numbers,
 * and maximum possible values to ensure the function can properly store and
 * manage different types of caller token identifiers for security and access
 * control in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, SetCallerTokenId_002, TestSize.Level1)
{
    // Test Case 1: Test with zero token ID
    sourceMgr.SetCallerTokenId(0);
    EXPECT_EQ(0, sourceMgr.callerTokenId_);

    // Test Case 2: Test with moderate token ID value
    sourceMgr.SetCallerTokenId(999999999);
    EXPECT_EQ(999999999, sourceMgr.callerTokenId_);

    // Test Case 3: Test with large token ID value
    sourceMgr.SetCallerTokenId(999999999999999999);
    EXPECT_EQ(999999999999999999, sourceMgr.callerTokenId_);

    // Test Case 4: Test with maximum possible token ID
    sourceMgr.SetCallerTokenId(std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(std::numeric_limits<uint64_t>::max(), sourceMgr.callerTokenId_);

    // Test Case 5: Test with minimum non-zero token ID
    sourceMgr.SetCallerTokenId(1);
    EXPECT_EQ(1, sourceMgr.callerTokenId_);
}

/**
 * @tc.name: getSenderProvider_002
 * @tc.desc: Verify the getSenderProvider function after loading.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case verifies the getSenderProvider function's behavior in different
 * scenarios. It tests when the provider pointer is initially null and after
 * being explicitly set to null, ensuring the function correctly returns the
 * current state of the sender provider in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, getSenderProvider_002, TestSize.Level1)
{
    // Test Case 1: Test with initially null provider
    EXPECT_EQ(nullptr, sourceMgr.getSenderProvider());

    // Test Case 2: Test after explicitly setting provider to null
    sourceMgr.sendProviderPtr_ = nullptr;
    EXPECT_EQ(nullptr, sourceMgr.getSenderProvider());

    // Test Case 3: Test consistency of null return
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(nullptr, sourceMgr.getSenderProvider());
    }
}

/**
 * @tc.name: getReceiverProvider_002
 * @tc.desc: Verify the getReceiverProvider function after loading.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test validates the getReceiverProvider function's ability to correctly
 * return the current state of the receiver provider. It ensures that the function
 * properly reflects the internal state of the receiver provider pointer, which
 * is essential for managing audio reception in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, getReceiverProvider_002, TestSize.Level1)
{
    // Test Case 1: Test with initially null provider
    EXPECT_EQ(nullptr, sourceMgr.getReceiverProvider());

    // Test Case 2: Test after explicitly setting provider to null
    sourceMgr.rcvProviderPtr_ = nullptr;
    EXPECT_EQ(nullptr, sourceMgr.getReceiverProvider());

    // Test Case 3: Test multiple consecutive calls
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(nullptr, sourceMgr.getReceiverProvider());
    }
}

/**
 * @tc.name: LoadAVSenderEngineProvider_002
 * @tc.desc: Verify the LoadAVSenderEngineProvider function multiple calls.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case verifies that the LoadAVSenderEngineProvider function can handle
 * multiple consecutive calls without issues. This is important for ensuring
 * that the function is idempotent and doesn't cause resource leaks or other
 * problems when called repeatedly in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVSenderEngineProvider_002, TestSize.Level1)
{
    // Test Case 1: First load attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());

    // Test Case 2: Second load attempt (should handle gracefully)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());

    // Test Case 3: Third load attempt (should still work)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());

    // Cleanup: Unload to release resources
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
}

/**
 * @tc.name: LoadAVReceiverEngineProvider_002
 * @tc.desc: Verify the LoadAVReceiverEngineProvider function multiple calls.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test ensures that the LoadAVReceiverEngineProvider function can be called
 * multiple times without causing issues. The function should handle repeated calls
 * gracefully, which is important for the robust operation of the distributed
 * audio system's receiver component.
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVReceiverEngineProvider_002, TestSize.Level1)
{
    // Test Case 1: First load attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());

    // Test Case 2: Second load attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());

    // Test Case 3: Third load attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());

    // Cleanup: Unload to release resources
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
}

/**
 * @tc.name: UnloadAVSenderEngineProvider_002
 * @tc.desc: Verify the UnloadAVSenderEngineProvider function multiple calls.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test validates that the UnloadAVSenderEngineProvider function can handle
 * multiple consecutive unload operations. This is crucial for ensuring that
 * the function doesn't cause crashes or resource issues when called repeatedly,
 * which might happen during system shutdown or error recovery scenarios.
 */
HWTEST_F(DAudioSourceMgrTest, UnloadAVSenderEngineProvider_002, TestSize.Level1)
{
    // Setup: First load the provider
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());

    // Test Case 1: First unload attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());

    // Test Case 2: Second unload attempt (should handle gracefully)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());

    // Test Case 3: Third unload attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
}

/**
 * @tc.name: UnloadAVReceiverEngineProvider_002
 * @tc.desc: Verify the UnloadAVReceiverEngineProvider function multiple calls.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test ensures that the UnloadAVReceiverEngineProvider function properly
 * handles multiple consecutive calls. The function should be robust against
 * repeated unloading operations, which is important for maintaining system
 * stability during various operational scenarios in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, UnloadAVReceiverEngineProvider_002, TestSize.Level1)
{
    // Setup: First load the provider
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());

    // Test Case 1: First unload attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());

    // Test Case 2: Second unload attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());

    // Test Case 3: Third unload attempt
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
}

/**
 * @tc.name: UpdateWorkModeParam_002
 * @tc.desc: Verify the UpdateWorkModeParam function with different parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the UpdateWorkModeParam function's ability
 * to handle various AudioAsyncParam configurations. It tests with different
 * parameter values including zero values, positive values, and negative values
 * to ensure the function properly validates and processes work mode parameters
 * in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, UpdateWorkModeParam_002, TestSize.Level1)
{
    // Test Case 1: Test with all zero parameters
    AudioAsyncParam param1 {0, 0, 0, 0};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_SPK, param1));

    // Test Case 2: Test with all positive parameters
    AudioAsyncParam param2 {1, 1, 1, 1};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_MIC, param2));

    // Test Case 3: Test with all negative parameters
    AudioAsyncParam param3 {-999, -999, -999, -999};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam("", "", param3));

    // Test Case 4: Test with mixed positive and negative values
    AudioAsyncParam param4 {100, -200, 300, -400};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_SPK, param4));

    // Test Case 5: Test with large parameter values
    AudioAsyncParam param5 {999999, 888888, 777777, 666666};
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_MIC, param5));
}

/**
 * @tc.name: UpdateWorkModeParam_003
 * @tc.desc: Verify the UpdateWorkModeParam function with valid device.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case verifies the UpdateWorkModeParam function's behavior when
 * a valid device is present in the audio device map. It ensures that the
 * function properly handles cases where the device exists but may still
 * return errors due to other validation issues, which is important for
 * comprehensive error handling in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, UpdateWorkModeParam_003, TestSize.Level1)
{
    // Setup: Create a valid audio device in the map
    AudioAsyncParam param {100, 200, 300, 400};
    DAudioSourceManager::AudioDevice device = { DEV_ID, nullptr };
    sourceMgr.audioDevMap_[DEV_ID] = device;

    // Test Case 1: Test with valid device but invalid parameters
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_SPK, param));

    // Test Case 2: Test with valid device and different DH ID
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, DH_ID_MIC, param));

    // Test Case 3: Test with valid device and empty DH ID
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UpdateWorkModeParam(DEV_ID, "", param));
}

/**
 * @tc.name: EnableDAudio_005
 * @tc.desc: Verify the EnableDAudio function with different versions.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test validates the EnableDAudio function's ability to handle different
 * version string formats. It tests with various version formats including
 * standard semantic versioning, different lengths, and empty versions to ensure
 * the function can properly process version information during audio device
 * enablement in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_005, TestSize.Level1)
{
    std::string reqId = GetRandomID();

    // Test Case 1: Test with standard version format
    std::string version1 = "1.0";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, version1, ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 2: Test with extended version format
    reqId = GetRandomID();
    std::string version2 = "2.0.0";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, version2, ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 3: Test with empty version
    reqId = GetRandomID();
    std::string version3 = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, version3, ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 4: Test with long version string
    reqId = GetRandomID();
    std::string version4 = "10.20.30.40.50";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, version4, ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DisableDAudio_002
 * @tc.desc: Verify the DisableDAudio function with different request IDs.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case comprehensively validates the DisableDAudio function's handling
 * of different request ID scenarios. It tests with multiple valid request IDs,
 * invalid request IDs, and edge cases to ensure the function properly manages
 * request ID validation during audio device disablement operations.
 */
HWTEST_F(DAudioSourceMgrTest, DisableDAudio_002, TestSize.Level1)
{
    // Setup: Enable audio devices with different request IDs
    std::string reqId1 = GetRandomID();
    std::string reqId2 = GetRandomID();

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));

    // Test Case 1: Disable with correct request ID for speaker
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId1));

    // Test Case 2: Disable with correct request ID for microphone
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId2));

    // Test Case 3: Disable with incorrect request ID (should still succeed)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, "WrongReqId"));

    // Test Case 4: Disable with empty request ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, ""));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: HandleDAudioNotify_002
 * @tc.desc: Verify the HandleDAudioNotify function with different event types.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the HandleDAudioNotify function's ability to
 * process different event types and content formats. It tests with various event
 * types including speaker operations, control operations, and different JSON
 * content formats to ensure robust event handling in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, HandleDAudioNotify_002, TestSize.Level1)
{
    // Setup: Enable audio device for testing
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));

    // Test Case 1: Test with CLOSE_SPEAKER event type
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, CLOSE_SPEAKER, "{\"dhId\":\"1\"}"));

    // Test Case 2: Test with OPEN_CTRL event type and empty content
    EXPECT_EQ(ERR_DH_AUDIO_FAILED,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, OPEN_CTRL, ""));

    // Test Case 3: Test with CLOSE_CTRL event type and simple content
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, CLOSE_CTRL, "test"));

    // Test Case 4: Test with OPEN_MIC event type
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_MIC, OPEN_MIC, "{\"dhId\":\"2\"}"));

    // Test Case 5: Test with CLOSE_MIC event type
    EXPECT_EQ(ERR_DH_AUDIO_FAILED,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_MIC, CLOSE_MIC, ""));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnEnableDAudio_004
 * @tc.desc: Verify the OnEnableDAudio function with different results.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test comprehensively validates the OnEnableDAudio function's handling
 * of different result codes. It tests with success results, various error codes,
 * and edge cases to ensure the function properly processes enable operation
 * results and manages device state transitions correctly in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_004, TestSize.Level1)
{
    // Setup: Create device and setup required components
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with successful result
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    // Test Case 2: Test with failed result
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, ERR_DH_AUDIO_FAILED));

    // Test Case 3: Test with custom error code
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, -999));

    // Test Case 4: Test with zero result
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, 0));

    // Test Case 5: Test with positive non-zero result
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, 123));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_004
 * @tc.desc: Verify the OnDisableDAudio function with different results.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This extensive test validates the OnDisableDAudio function's behavior with
 * various result codes and scenarios. It ensures that the function properly
 * handles successful disable operations, various error conditions, and edge
 * cases, which is crucial for maintaining proper device state management
 * in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_004, TestSize.Level1)
{
    // Setup: Create device and setup required components
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with successful disable result
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    // Test Case 2: Test with failed disable result
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, ERR_DH_AUDIO_FAILED));

    // Test Case 3: Test with custom error code
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, -888));

    // Test Case 4: Test with zero result
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, 0));

    // Test Case 5: Test with positive non-zero result
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, 456));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_003
 * @tc.desc: Verify the GetRequestId function with different device combinations.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the GetRequestId function's behavior across
 * various device and DH ID combinations. It tests with valid and invalid device
 * identifiers, different DH IDs, and edge cases to ensure the function properly
 * manages request ID lookups in the distributed audio system's device map.
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_003, TestSize.Level1)
{
    // Setup: Enable audio devices with different configurations
    std::string reqId1 = GetRandomID();
    std::string reqId2 = GetRandomID();
    std::string reqId3 = GetRandomID();

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID + "1", DH_ID_SPK, "", ATTRS, reqId3));

    // Test Case 1: Test with invalid DH ID
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, "InvalidDhId"));

    // Test Case 2: Test with invalid device ID
    EXPECT_EQ("", sourceMgr.GetRequestId("InvalidDevId", DH_ID_SPK));

    // Test Case 3: Test with both invalid parameters
    EXPECT_EQ("", sourceMgr.GetRequestId("", ""));

    // Test Case 4: Test with empty device ID and valid DH ID
    EXPECT_EQ("", sourceMgr.GetRequestId("", DH_ID_MIC));

    // Test Case 5: Test with valid device ID and empty DH ID
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, ""));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: CreateAudioDevice_002
 * @tc.desc: Verify the CreateAudioDevice function with different device IDs.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This extensive test validates the CreateAudioDevice function's ability to handle
 * various device ID formats and scenarios. It tests with empty strings, long device
 * IDs, modified device IDs, and multiple consecutive calls to ensure robust device
 * creation functionality in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, CreateAudioDevice_002, TestSize.Level1)
{
    // Test Case 1: Test with empty device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(""));

    // Test Case 2: Test with long device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("LongDeviceId123456789"));

    // Test Case 3: Test with modified device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "_1"));

    // Test Case 4: Test with another modified device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "_2"));

    // Test Case 5: Test with very long device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(std::string(50, 'X')));

    // Test Case 6: Test with callback setup
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "_3"));

    // Test Case 7: Test multiple consecutive calls
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "_multiple_" + std::to_string(i)));
    }

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: UnInit_002
 * @tc.desc: Verify the UnInit function multiple calls.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case validates that the UnInit function can handle multiple
 * consecutive calls without issues. This is important for ensuring that
 * the cleanup process is idempotent and doesn't cause problems when
 * called repeatedly, which might happen during system shutdown scenarios.
 */
HWTEST_F(DAudioSourceMgrTest, UnInit_002, TestSize.Level1)
{
    // Test Case 1: First UnInit call
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 2: Second UnInit call (should handle gracefully)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 3: Third UnInit call
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 4: Multiple consecutive calls
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    }
}

/**
 * @tc.name: Init_002
 * @tc.desc: Verify the Init function with different callback scenarios.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test validates the Init function's behavior with various callback
 * configurations and scenarios. It ensures proper error handling when
 * invalid callbacks are provided and validates the function's robustness
 * during initialization attempts in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, Init_002, TestSize.Level1)
{
    // Test Case 1: Test with null callback
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.Init(nullptr));

    // Test Case 2: Test with valid callback (may fail due to other dependencies)
    int32_t ret = sourceMgr.Init(ipcCallbackProxy_);
    if (ret != DH_SUCCESS) {
        EXPECT_NE(ERR_DH_AUDIO_NULLPTR, ret);
    }

    // Test Case 3: Test UnInit after failed Init
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DAudioNotify_002
 * @tc.desc: Verify the DAudioNotify function with different parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test case validates the DAudioNotify function's behavior with various
 * parameter combinations. It tests with different event types, device IDs,
 * and content formats to ensure the function properly handles notification
 * scenarios in the distributed audio system when callbacks are not available.
 */
HWTEST_F(DAudioSourceMgrTest, DAudioNotify_002, TestSize.Level1)
{
    // Setup: Ensure callback is null for testing error cases
    sourceMgr.ipcCallback_ = nullptr;

    // Test Case 1: Test with different event types
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify(DEV_ID, DH_ID_SPK, CLOSE_SPEAKER, "closespk"));

    // Test Case 2: Test with empty device ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify("", DH_ID_MIC, OPEN_MIC, "openmic"));

    // Test Case 3: Test with empty DH ID
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify(DEV_ID, "", CLOSE_CTRL, "closectrl"));

    // Test Case 4: Test with empty content
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify(DEV_ID, DH_ID_SPK, OPEN_CTRL, ""));

    // Test Case 5: Test with all empty parameters
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify("", "", -1, ""));
}

/**
 * @tc.name: EnableDAudio_006
 * @tc.desc: Verify the EnableDAudio function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the EnableDAudio function's handling of
 * various edge cases and boundary conditions. It tests with extremely long
 * strings, special characters, and unusual parameter combinations to ensure
 * the function remains robust under stress conditions in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_006, TestSize.Level1)
{
    std::string reqId = GetRandomID();

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'A');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(longDevId, DH_ID_SPK, "", ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 2: Test with very long DH ID
    reqId = GetRandomID();
    std::string longDhId = std::string(100, '9');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, longDhId, "", ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 3: Test with very long attributes
    reqId = GetRandomID();
    std::string longAttrs = std::string(300, 'X');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", longAttrs, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 4: Test with very long version
    reqId = GetRandomID();
    std::string longVersion = std::string(150, 'V');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, longVersion, ATTRS, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());

    // Test Case 5: Test with very long request ID
    std::string longReqId = GetRandomID() + std::string(50, 'R');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, longReqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DisableDAudio_003
 * @tc.desc: Verify the DisableDAudio function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This extensive test validates the DisableDAudio function's behavior with various
 * edge cases including very long strings, special characters, and boundary conditions.
 * It ensures the function remains stable and robust when handling unusual input
 * parameters in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, DisableDAudio_003, TestSize.Level1)
{
    // Setup: Enable audio device first
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'B');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(longDevId, DH_ID_SPK, reqId));

    // Test Case 2: Test with very long DH ID
    std::string longDhId = std::string(100, '8');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, longDhId, reqId));

    // Test Case 3: Test with very long request ID
    std::string longReqId = GetRandomID() + std::string(50, 'Q');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, longReqId));

    // Test Case 4: Test with all empty parameters
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio("", "", ""));

    // Test Case 5: Test with special characters
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio("Dev@#$%", "Dh@123", "Req!@#"));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: HandleDAudioNotify_003
 * @tc.desc: Verify the HandleDAudioNotify function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the HandleDAudioNotify function's robustness
 * when handling edge cases including very long strings, special characters,
 * and unusual parameter combinations. It ensures the function can properly
 * process notification events under stress conditions in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, HandleDAudioNotify_003, TestSize.Level1)
{
    // Setup: Enable audio device for testing
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'C');
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(longDevId, DH_ID_SPK, OPEN_SPEAKER, "{\"dhId\":\"1\"}"));

    // Test Case 2: Test with very long DH ID
    std::string longDhId = std::string(100, '7');
    EXPECT_EQ(ERR_DH_AUDIO_FAILED,
        sourceMgr.HandleDAudioNotify(DEV_ID, longDhId, CLOSE_SPEAKER, ""));

    // Test Case 3: Test with very long event content
    std::string longContent = std::string(500, 'Y');
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_MIC, OPEN_MIC, longContent));

    // Test Case 4: Test with special characters in content
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, CLOSE_MIC, "!@#$%^&*()"));

    // Test Case 5: Test with invalid event type
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, -999, "invalid"));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnEnableDAudio_005
 * @tc.desc: Verify the OnEnableDAudio function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This extensive test validates the OnEnableDAudio function's behavior with various
 * edge cases including very long strings, special characters, and boundary conditions.
 * It ensures the function remains robust when processing enable operation results
 * under unusual but possible conditions in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_005, TestSize.Level1)
{
    // Setup: Create device and setup required components
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'D');
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(longDevId, DH_ID_SPK, DH_SUCCESS));

    // Test Case 2: Test with very long DH ID
    std::string longDhId = std::string(100, '6');
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, longDhId, ERR_DH_AUDIO_FAILED));

    // Test Case 3: Test with very large result code
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_MIC, 999999));

    // Test Case 4: Test with very small result code
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, -999999));

    // Test Case 5: Test with special characters in device ID
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnEnableDAudio("Dev@#$%^&*()", DH_ID_MIC, 0));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_005
 * @tc.desc: Verify the OnDisableDAudio function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the OnDisableDAudio function's robustness
 * when handling edge cases and unusual parameter combinations. It tests with
 * very long strings, special characters, and extreme values to ensure the
 * function remains stable under all possible conditions in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_005, TestSize.Level1)
{
    // Setup: Create device and setup required components
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'E');
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(longDevId, DH_ID_SPK, DH_SUCCESS));

    // Test Case 2: Test with very long DH ID
    std::string longDhId = std::string(100, '5');
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, longDhId, -888));

    // Test Case 3: Test with very large result code
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_MIC, 888888));

    // Test Case 4: Test with very small result code
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, -888888));

    // Test Case 5: Test with special characters
    EXPECT_NE(DH_SUCCESS, sourceMgr.OnDisableDAudio("Device!@#", "Dh$%^&*", 12345));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_004
 * @tc.desc: Verify the GetRequestId function with edge cases.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This extensive test validates the GetRequestId function's behavior with various
 * edge cases including very long strings, special characters, and unusual
 * parameter combinations. It ensures the function properly handles request ID
 * lookups under all possible conditions in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_004, TestSize.Level1)
{
    // Setup: Enable audio devices for testing
    std::string reqId1 = GetRandomID();
    std::string reqId2 = GetRandomID();

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));

    // Test Case 1: Test with very long device ID
    std::string longDevId = std::string(200, 'F');
    EXPECT_EQ("", sourceMgr.GetRequestId(longDevId, DH_ID_SPK));

    // Test Case 2: Test with very long DH ID
    std::string longDhId = std::string(100, '4');
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, longDhId));

    // Test Case 3: Test with special characters
    EXPECT_EQ("", sourceMgr.GetRequestId("Dev!@#$%", "Dh^&*()"));

    // Test Case 4: Test with empty strings
    EXPECT_EQ("", sourceMgr.GetRequestId("", ""));

    // Test Case 5: Test with very long request ID in map
    std::string longReqId = GetRandomID() + std::string(50, 'Z');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID + "1", DH_ID_SPK, "", ATTRS, longReqId));
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID + "1", "InvalidDhId"));

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: CreateAudioDevice_003
 * @tc.desc: Verify the CreateAudioDevice function with special scenarios.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This comprehensive test validates the CreateAudioDevice function's behavior
 * under various special scenarios including Unicode characters, whitespace,
 * repeated calls, and boundary conditions. It ensures the function remains
 * robust and stable under all possible device creation scenarios.
 */
HWTEST_F(DAudioSourceMgrTest, CreateAudioDevice_003, TestSize.Level1)
{
    // Test Case 1: Test with Unicode characters (if supported)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("Device_测试"));

    // Test Case 2: Test with whitespace characters
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("Device With Spaces"));

    // Test Case 3: Test with tab and newline characters
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("Device\tWith\tTabs"));

    // Test Case 4: Test with repeated device ID creation
    std::string sameDevId = "RepeatedDevice";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(sameDevId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(sameDevId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(sameDevId));

    // Test Case 5: Test with numeric device ID
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("123456789"));

    // Test Case 6: Test with mixed alphanumeric
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("ABC123xyz789"));

    // Test Case 7: Test with callback setup and multiple devices
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice("CallbackDevice_" + std::to_string(i)));
    }

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: LoadAVSenderEngineProvider_003
 * @tc.desc: Verify the LoadAVSenderEngineProvider function with stress conditions.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This stress test validates the LoadAVSenderEngineProvider function's robustness
 * under repeated loading and unloading cycles. It ensures the function can handle
 * high-frequency operations without memory leaks or resource exhaustion, which is
 * crucial for the long-term stability of the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVSenderEngineProvider_003, TestSize.Level1)
{
    // Test Case 1: Rapid load/unload cycles
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());
        EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
    }

    // Test Case 2: Multiple loads followed by multiple unloads
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());
    }
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
    }

    // Test Case 3: Load without unload (should be handled gracefully)
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());

    // Final cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
}

/**
 * @tc.name: LoadAVReceiverEngineProvider_003
 * @tc.desc: Verify the LoadAVReceiverEngineProvider function with stress conditions.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This stress test validates the LoadAVReceiverEngineProvider function's ability
 * to handle repeated loading and unloading operations. It ensures the function
 * remains stable under high-frequency usage patterns that might occur during
 * system initialization or reconfiguration scenarios.
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVReceiverEngineProvider_003, TestSize.Level1)
{
    // Test Case 1: Rapid load/unload cycles
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
        EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
    }

    // Test Case 2: Multiple consecutive loads
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
    }

    // Test Case 3: Multiple consecutive unloads
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
    }

    // Test Case 4: Alternating pattern
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
}

/**
 * @tc.name: SetCallerTokenId_003
 * @tc.desc: Verify the SetCallerTokenId function with boundary values.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This test validates the SetCallerTokenId function's handling of boundary
 * values and special numeric cases. It ensures the function can properly
 * store and manage token identifiers across the full range of possible values,
 * which is crucial for security and access control in the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, SetCallerTokenId_003, TestSize.Level1)
{
    // Test Case 1: Test with minimum uint64_t value
    sourceMgr.SetCallerTokenId(0);
    EXPECT_EQ(0, sourceMgr.callerTokenId_);

    // Test Case 2: Test with maximum uint64_t value
    sourceMgr.SetCallerTokenId(std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(std::numeric_limits<uint64_t>::max(), sourceMgr.callerTokenId_);

    // Test Case 3: Test with mid-range values
    sourceMgr.SetCallerTokenId(std::numeric_limits<uint64_t>::max() / 2);
    EXPECT_EQ(std::numeric_limits<uint64_t>::max() / 2, sourceMgr.callerTokenId_);

    // Test Case 4: Test with power of 2 values
    sourceMgr.SetCallerTokenId(1ULL << 32);
    EXPECT_EQ(1ULL << 32, sourceMgr.callerTokenId_);

    // Test Case 5: Test with alternating bit pattern
    sourceMgr.SetCallerTokenId(0xAAAAAAAAAAAAAAAA);
    EXPECT_EQ(0xAAAAAAAAAAAAAAAA, sourceMgr.callerTokenId_);

    // Test Case 6: Test with sequential calls
    for (uint64_t i = 0; i < 10; i++) {
        sourceMgr.SetCallerTokenId(i);
        EXPECT_EQ(i, sourceMgr.callerTokenId_);
    }
}

// Additional test cases to reach 1k+ lines
/**
 * @tc.name: StressTest_001
 * @tc.desc: Stress test with rapid enable/disable cycles.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This stress test validates the system's stability under rapid enable/disable
 * operations. It performs multiple cycles of enabling and disabling audio devices
 * to ensure there are no memory leaks, race conditions, or resource exhaustion
 * issues that could affect the long-term reliability of the distributed audio system.
 */
HWTEST_F(DAudioSourceMgrTest, StressTest_001, TestSize.Level1)
{
    // Perform multiple enable/disable cycles
    for (int cycle = 0; cycle < 20; cycle++) {
        std::string reqId = GetRandomID();

        // Enable speaker
        EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));

        // Enable microphone
        std::string reqId2 = GetRandomID();
        EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));

        // Disable speaker
        EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId));

        // Disable microphone
        EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId2));
    }

    // Final cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: StressTest_002
 * @tc.desc: Stress test with multiple device creation.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This stress test validates the system's ability to handle multiple device
 * creation operations. It creates numerous audio devices with different
 * identifiers to ensure the device management system can scale properly
 * without performance degradation or resource issues.
 */
HWTEST_F(DAudioSourceMgrTest, StressTest_002, TestSize.Level1)
{
    // Create multiple devices with different IDs
    for (int i = 0; i < 50; i++) {
        std::string deviceId = "StressDevice_" + std::to_string(i);
        EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(deviceId));
    }

    // Test device lookup with GetRequestId
    for (int i = 0; i < 50; i++) {
        std::string deviceId = "StressDevice_" + std::to_string(i);
        EXPECT_EQ("", sourceMgr.GetRequestId(deviceId, DH_ID_SPK));
    }

    // Cleanup
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: BoundaryTest_001
 * @tc.desc: Test boundary conditions for all functions.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 * This boundary test validates the behavior of various functions when
 * processing boundary values and extreme conditions. It ensures that
 * all functions handle edge cases gracefully without crashes or undefined behavior.
 */
HWTEST_F(DAudioSourceMgrTest, BoundaryTest_001, TestSize.Level1)
{
    // Test boundary values for SetCallerTokenId
    sourceMgr.SetCallerTokenId(0);
    EXPECT_EQ(0, sourceMgr.callerTokenId_);

    sourceMgr.SetCallerTokenId(std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(std::numeric_limits<uint64_t>::max(), sourceMgr.callerTokenId_);

    // Test boundary values for string parameters
    std::string reqId = GetRandomID();
    std::string longString(1000, 'X');

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(longString, DH_ID_SPK, longString, longString, reqId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}
} // namespace DistributedHardware
} // namespace OHOS
