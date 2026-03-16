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

#include "daudio_sink_manager_test.h"

#include "audio_event.h"
#include "daudio_errorcode.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "daudio_sink_ipc_callback_proxy.h"
#include "daudio_sink_load_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkManagerTest::SetUpTestCase(void) {}

void DAudioSinkManagerTest::TearDownTestCase(void) {}

void DAudioSinkManagerTest::SetUp()
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    remoteObject_ = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject_ == nullptr) {
        return;
    }
}

void DAudioSinkManagerTest::TearDown() {}

/**
 * @tc.name: Init_001
 * @tc.desc: Verify the Init function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, Init_001, TestSize.Level1)
{
    // Create callback proxy instance with remote object
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject_));
    // Verify initialization returns failure
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.Init(dAudioSinkIpcCallbackProxy));
    // Verify uninitialization returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.UnInit());
}

/**
 * @tc.name: HandleDAudioNotify_001
 * @tc.desc: Verify the HandleDAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, HandleDAudioNotify_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "1";
    // Define test DH ID
    std::string dhId = "1";
    // Define test notify content
    std::string content = "1";
    // Define test notify type
    int32_t type = 1;
    // Insert null device into map
    daudioSinkManager.audioDevMap_.emplace(devId, nullptr);
    // Verify notify handling returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.HandleDAudioNotify(devId, dhId, type, content));
}

/**
 * @tc.name: DAudioNotify_001
 * @tc.desc: Verify the DAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, DAudioNotify_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    std::string dhId = "dhId";
    // Define test event type
    const int32_t eventType = 1;
    // Define test event content
    const std::string eventContent = "eventContent";
    // Verify notify returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        daudioSinkManager.DAudioNotify(devId, dhId, eventType, eventContent));
    // Get system ability manager instance
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    // Get remote system ability object
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID, devId);
    // Cast remote object to service proxy
    sptr<IDAudioSource> remoteSvrProxy = iface_cast<IDAudioSource>(remoteObject);
    // Store service proxy into map
    daudioSinkManager.sourceServiceMap_[devId] = remoteSvrProxy;
    // Verify notify returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, daudioSinkManager.DAudioNotify(devId, dhId, eventType, eventContent));
}

/**
 * @tc.name: CreateAudioDevice_001
 * @tc.desc: Verify the CreateAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, CreateAudioDevice_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test parameters
    std::string params = "params";
    // Get system ability manager instance
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    // Verify system ability manager is not null
    ASSERT_TRUE(samgr != nullptr);
    // Create load callback instance
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    // Load system ability
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    // Get remote system ability object
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    // Verify remote object is not null
    ASSERT_TRUE(remoteObject != nullptr);
    // Create callback proxy instance
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    // Set callback proxy to manager
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    // Verify create device returns not support error
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, daudioSinkManager.CreateAudioDevice(devId));
    // Insert null device into map
    daudioSinkManager.audioDevMap_.emplace(devId, nullptr);
    // Verify create device returns not support error
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, daudioSinkManager.CreateAudioDevice(devId));
    // Set channel state to speaker control opened
    daudioSinkManager.channelState_ = ChannelState::SPK_CONTROL_OPENED;
    // Verify create device returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.CreateAudioDevice(devId));
    // Clear audio device
    daudioSinkManager.ClearAudioDev(devId);
    // Set channel state to mic control opened
    daudioSinkManager.channelState_ = ChannelState::MIC_CONTROL_OPENED;
    // Verify create device returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.CreateAudioDevice(devId));
}

/**
 * @tc.name: InitAudioDevice_001
 * @tc.desc: Verify the InitAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, InitAudioDevice_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "1";
    // Define test parameters
    std::string params = "params";
    // Initialize device pointer to null
    std::shared_ptr<DAudioSinkDev> dev = nullptr;
    // Verify device initialization returns failure
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.InitAudioDevice(dev, devId, true));
    // Get system ability manager instance
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    // Verify system ability manager is not null
    ASSERT_TRUE(samgr != nullptr);
    // Create load callback instance
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    // Load system ability
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    // Get remote system ability object
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    // Verify remote object is not null
    ASSERT_TRUE(remoteObject != nullptr);
    // Create callback proxy instance
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    // Set callback proxy to manager
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    // Create valid device instance
    dev = std::make_shared<DAudioSinkDev>(devId, dAudioSinkIpcCallbackProxy);
    // Verify device initialization returns failure
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.InitAudioDevice(dev, devId, true));
    // Verify device initialization returns failure
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.InitAudioDevice(dev, devId, false));
}

/**
 * @tc.name: LoadAVSenderEngineProvider_001
 * @tc.desc: Verify the LoadAVSenderEngineProvider function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, LoadAVSenderEngineProvider_001, TestSize.Level1)
{
    // Verify load sender engine provider returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.LoadAVSenderEngineProvider());
    // Verify unload sender engine provider returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.UnloadAVSenderEngineProvider());
    // Verify load receiver engine provider returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.LoadAVReceiverEngineProvider());
    // Verify unload receiver engine provider returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.UnloadAVReceiverEngineProvider());
}

/**
 * @tc.name: PauseDistributedHardware_001
 * @tc.desc: Verify the PauseDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, PauseDistributedHardware_001, TestSize.Level1)
{
    // Define test network ID
    std::string networkId = "networkId";
    // Define test device ID
    std::string devId = "devId";
    // Define test parameters
    std::string params = "params";
    // Get system ability manager instance
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    // Verify system ability manager is not null
    ASSERT_TRUE(samgr != nullptr);
    // Create load callback instance
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    // Load system ability
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    // Get remote system ability object
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    // Verify remote object is not null
    ASSERT_TRUE(remoteObject != nullptr);
    // Create callback proxy instance
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    // Create device instance
    auto dev = std::make_shared<DAudioSinkDev>(networkId, dAudioSinkIpcCallbackProxy);
    // Verify pause distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.PauseDistributedHardware(networkId));
    // Verify resume distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.ResumeDistributedHardware(networkId));
    // Verify stop distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.StopDistributedHardware(networkId));
    // Insert device into map
    daudioSinkManager.audioDevMap_.emplace(networkId, dev);
    // Verify pause distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.PauseDistributedHardware(networkId));
    // Verify resume distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.ResumeDistributedHardware(networkId));
    // Verify stop distributed hardware returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.StopDistributedHardware(networkId));
}

/**
 * @tc.name: VerifySecurityLevel_001
 * @tc.desc: Verify the VerifySecurityLevel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, VerifySecurityLevel_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test network ID
    std::string networkId = "networkId";
    // Define test parameters
    std::string params = "params";
    // Get system ability manager instance
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    // Verify system ability manager is not null
    ASSERT_TRUE(samgr != nullptr);
    // Create load callback instance
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    // Load system ability
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    // Get remote system ability object
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    // Verify remote object is not null
    ASSERT_TRUE(remoteObject != nullptr);
    // Create callback proxy instance
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    // Set callback proxy to manager
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    // Verify security level check returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    // Set sensitive flag to true
    daudioSinkManager.isSensitive_ = true;
    // Set same account flag to false
    daudioSinkManager.isSameAccount_ = false;
    // Verify security level check returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    // Set same account flag to true
    daudioSinkManager.isSameAccount_ = true;
    // Verify security level check returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
}

/**
 * @tc.name: GetDeviceSecurityLevel_001
 * @tc.desc: Verify the GetDeviceSecurityLevel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, GetDeviceSecurityLevel_001, TestSize.Level1)
{
    // Define test UDID
    std::string udid = "udid";
    // Initialize empty content
    std::string content = "";
    // Initialize result to invalid value
    int32_t ret = -1;
    // Set empty channel state
    daudioSinkManager.SetChannelState(content);
    // Set mic channel state
    content = "ohos.dhardware.daudio.dmic";
    daudioSinkManager.SetChannelState(content);
    // Set speaker channel state
    content = "ohos.dhardware.daudio.dspeaker";
    daudioSinkManager.SetChannelState(content);
    // Verify get security level returns invalid value
    EXPECT_EQ(ret, daudioSinkManager.GetDeviceSecurityLevel(udid));
}

/**
 * @tc.name: CheckDeviceSecurityLevel_001
 * @tc.desc: Verify the CheckDeviceSecurityLevel function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, CheckDeviceSecurityLevel_001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "1";
    // Create device clear thread
    daudioSinkManager.devClearThread_ = std::thread(&DAudioSinkManager::ClearAudioDev, &daudioSinkManager, devId);
    // Handle sink device released event
    daudioSinkManager.OnSinkDevReleased(devId);
    // Define source device ID
    std::string srcDeviceId = "srcDeviceId";
    // Define destination device ID
    std::string dstDeviceId = "dstDeviceId";
    // Verify security level check returns false
    EXPECT_EQ(false, daudioSinkManager.CheckDeviceSecurityLevel(srcDeviceId, dstDeviceId));
}

/**
 * @tc.name: GetUdidByNetworkId_001
 * @tc.desc: Verify the GetUdidByNetworkId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, GetUdidByNetworkId_001, TestSize.Level1)
{
    // Initialize empty network ID
    std::string networkId;
    // Verify get UDID returns empty string
    EXPECT_EQ("", daudioSinkManager.GetUdidByNetworkId(networkId));
    // Set test network ID
    networkId = "123";
    // Verify get UDID returns empty string
    EXPECT_EQ("", daudioSinkManager.GetUdidByNetworkId(networkId));
}

/**
 * @tc.name: OnProviderEvent_001
 * @tc.desc: Verify the OnProviderEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, OnProviderEvent_001, TestSize.Level1)
{
    // Create channel opened event
    AVTransEvent event1 = { EventType::EVENT_CHANNEL_OPENED, "", ""};
    // Create provider listener instance
    daudioSinkManager.providerListener_ = std::make_shared<EngineProviderListener>();
    // Verify provider event callback returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.providerListener_->OnProviderEvent(event1));
    // Create channel closed event
    AVTransEvent event2 = { EventType::EVENT_CHANNEL_CLOSED, "", ""};
    // Verify provider event callback returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.providerListener_->OnProviderEvent(event2));
    // Create remove stream event
    AVTransEvent event3 = { EventType::EVENT_REMOVE_STREAM, "", ""};
    // Verify provider event callback returns success
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.providerListener_->OnProviderEvent(event3));
}

/**
 * @tc.name: ParseValueFromCjson_001
 * @tc.desc: Verify the ParseValueFromCjson function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkManagerTest, ParseValueFromCjson_001, TestSize.Level1)
{
    // Initialize test volume value
    int32_t volume = 50;
    // Define valid JSON string
    std::string jsonStr = "{\"OS_TYPE\": 50}";
    // Define parse key
    std::string key = "OS_TYPE";
    // Parse value from JSON
    int32_t result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse result matches expected value
    EXPECT_EQ(result, volume);

    // Define invalid JSON string
    jsonStr = "invalid_json";
    // Change parse key
    key = "volume";
    // Parse value from invalid JSON
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse returns failed error
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    // Define JSON with different key
    jsonStr = "{\"brightness\": 80}";
    // Parse value from JSON
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse returns failed error
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    // Define JSON with string value
    jsonStr = "{\"volume\": \"high\"}";
    // Parse value from JSON
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse returns failed error
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    // Define empty JSON string
    jsonStr = "";
    // Parse value from empty string
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse returns failed error
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    // Define null JSON string
    jsonStr = "null";
    // Change parse key
    key = "volume";
    // Parse value from null string
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    // Verify parse returns failed error
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);
}

/**
 * @tc.name: SetAccessListener_001
 * @tc.desc: Verify the SetAccessListener function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkManagerTest, SetAccessListener_001, TestSize.Level1)
{
    // Initialize listener pointer to null
    sptr<IAccessListener> listener = nullptr;
    // Set test timeout value
    int32_t timeOut = 5000;
    // Set test package name
    std::string pkgName = "com.example.test";
    // Call set access listener with null listener
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    // Set zero timeout
    timeOut = 0;
    // Set empty package name
    pkgName = "";
    // Call set access listener
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    // Set negative timeout
    timeOut = -1;
    // Set test package name
    pkgName = "com.test.empty";
    // Call set access listener
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    // Set maximum timeout
    timeOut = 30000;
    // Create valid test listener
    sptr<IAccessListener> accessListener(new TestAccessListener());
    // Set test package name
    pkgName = "com.test.empty";
    // Verify no fatal failure during set access listener
    EXPECT_NO_FATAL_FAILURE(daudioSinkManager.SetAccessListener(accessListener, timeOut, pkgName));
}

/**
 * @tc.name: RemoveAccessListener_001
 * @tc.desc: Verify the RemoveAccessListener function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkManagerTest, RemoveAccessListener_001, TestSize.Level1)
{
    // Set test package name
    std::string pkgName = "com.example.test";
    // Call remove access listener
    daudioSinkManager.RemoveAccessListener(pkgName);

    // Set empty package name
    pkgName = "";
    // Call remove access listener
    daudioSinkManager.RemoveAccessListener(pkgName);

    // Set long package name for test
    pkgName = "very.long.package.name.that.exceeds.normal.length.for.testing.purposes";
    // Call remove access listener
    daudioSinkManager.RemoveAccessListener(pkgName);

    // Set package name with special characters
    pkgName = "com.test123.special!@#$%^&*()_+";
    // Verify no fatal failure during remove access listener
    EXPECT_NO_FATAL_FAILURE(daudioSinkManager.RemoveAccessListener(pkgName));
}

/**
 * @tc.name: SetAuthorizationResult_001
 * @tc.desc: Verify the SetAuthorizationResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkManagerTest, SetAuthorizationResult_001, TestSize.Level1)
{
    // Set test request ID
    std::string requestId = "123";
    // Set granted flag to true
    bool granted = true;
    // Call set authorization result
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    // Set granted flag to false
    granted = false;
    // Call set authorization result
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    // Set test request ID
    requestId = "empty.request.test";
    // Call set authorization result
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    // Set empty request ID
    requestId = "";
    // Call set authorization result
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    // Set long request ID for test
    requestId = "very.long.request.id.that.exceeds.normal.length.for.testing.purposes";
    // Set granted flag to true
    granted = true;
    // Verify no fatal failure during set authorization result
    EXPECT_NO_FATAL_FAILURE(daudioSinkManager.SetAuthorizationResult(requestId, granted));
}
} // DistributedHardware
} // OHOS
