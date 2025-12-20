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
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject_));
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.Init(dAudioSinkIpcCallbackProxy));
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
    std::string devId = "1";
    std::string dhId = "1";
    std::string content = "1";
    int32_t type = 1;
    daudioSinkManager.audioDevMap_.emplace(devId, nullptr);
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
    std::string devId = "devId";
    std::string dhId = "dhId";
    const int32_t eventType = 1;
    const std::string eventContent = "eventContent";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        daudioSinkManager.DAudioNotify(devId, dhId, eventType, eventContent));
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID, devId);
    sptr<IDAudioSource> remoteSvrProxy = iface_cast<IDAudioSource>(remoteObject);
    daudioSinkManager.sourceServiceMap_[devId] = remoteSvrProxy;
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
    std::string devId = "devId";
    std::string params = "params";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.audioDevMap_.emplace(devId, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_NOT_SUPPORT, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.channelState_ = ChannelState::SPK_CONTROL_OPENED;
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.ClearAudioDev(devId);
    daudioSinkManager.channelState_ = ChannelState::MIC_CONTROL_OPENED;
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
    std::string devId = "1";
    std::string params = "params";
    std::shared_ptr<DAudioSinkDev> dev = nullptr;
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.InitAudioDevice(dev, devId, true));
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    dev = std::make_shared<DAudioSinkDev>(devId, dAudioSinkIpcCallbackProxy);
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.InitAudioDevice(dev, devId, true));
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
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.LoadAVSenderEngineProvider());
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.UnloadAVSenderEngineProvider());
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.LoadAVReceiverEngineProvider());
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
    std::string networkId = "networkId";
    std::string devId = "devId";
    std::string params = "params";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    auto dev = std::make_shared<DAudioSinkDev>(networkId, dAudioSinkIpcCallbackProxy);
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.PauseDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.ResumeDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.StopDistributedHardware(networkId));
    daudioSinkManager.audioDevMap_.emplace(networkId, dev);
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.PauseDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.ResumeDistributedHardware(networkId));
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
    std::string devId = "devId";
    std::string networkId = "networkId";
    std::string params = "params";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    daudioSinkManager.isSensitive_ = true;
    daudioSinkManager.isSameAccount_ = false;
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    daudioSinkManager.isSameAccount_ = true;
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
    std::string udid = "udid";
    std::string content = "";
    int32_t ret = -1;
    daudioSinkManager.SetChannelState(content);
    content = "ohos.dhardware.daudio.dmic";
    daudioSinkManager.SetChannelState(content);
    content = "ohos.dhardware.daudio.dspeaker";
    daudioSinkManager.SetChannelState(content);
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
    std::string devId = "1";
    daudioSinkManager.devClearThread_ = std::thread(&DAudioSinkManager::ClearAudioDev, &daudioSinkManager, devId);
    daudioSinkManager.OnSinkDevReleased(devId);
    std::string srcDeviceId = "srcDeviceId";
    std::string dstDeviceId = "dstDeviceId";
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
    std::string networkId;
    EXPECT_EQ("", daudioSinkManager.GetUdidByNetworkId(networkId));
    networkId = "123";
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
    AVTransEvent event1 = { EventType::EVENT_CHANNEL_OPENED, "", ""};
    daudioSinkManager.providerListener_ = std::make_shared<EngineProviderListener>();
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.providerListener_->OnProviderEvent(event1));
    AVTransEvent event2 = { EventType::EVENT_CHANNEL_CLOSED, "", ""};
    EXPECT_EQ(DH_SUCCESS, daudioSinkManager.providerListener_->OnProviderEvent(event2));
    AVTransEvent event3 = { EventType::EVENT_REMOVE_STREAM, "", ""};
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
    int32_t volume = 50;
    std::string jsonStr = "{\"OS_TYPE\": 50}";
    std::string key = "OS_TYPE";
    int32_t result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, volume);

    jsonStr = "invalid_json";
    key = "volume";
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "{\"brightness\": 80}";
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "{\"volume\": \"high\"}";
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "";
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, ERR_DH_AUDIO_FAILED);

    jsonStr = "null";
    key = "volume";
    result = daudioSinkManager.ParseValueFromCjson(jsonStr, key);
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
    sptr<IAccessListener> listener = nullptr;
    int32_t timeOut = 5000;
    std::string pkgName = "com.example.test";
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    timeOut = 0;
    pkgName = "";
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    timeOut = -1;
    pkgName = "com.test.empty";
    daudioSinkManager.SetAccessListener(listener, timeOut, pkgName);

    timeOut = 30000;
    sptr<IAccessListener> accessListener(new TestAccessListener());
    pkgName = "com.test.empty";
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
    std::string pkgName = "com.example.test";
    daudioSinkManager.RemoveAccessListener(pkgName);

    pkgName = "";
    daudioSinkManager.RemoveAccessListener(pkgName);

    pkgName = "very.long.package.name.that.exceeds.normal.length.for.testing.purposes";
    daudioSinkManager.RemoveAccessListener(pkgName);

    pkgName = "com.test123.special!@#$%^&*()_+";
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
    std::string requestId = "123";
    bool granted = true;
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    granted = false;
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    requestId = "empty.request.test";
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    requestId = "";
    daudioSinkManager.SetAuthorizationResult(requestId, granted);

    requestId = "very.long.request.id.that.exceeds.normal.length.for.testing.purposes";
    granted = true;
    EXPECT_NO_FATAL_FAILURE(daudioSinkManager.SetAuthorizationResult(requestId, granted));
}
} // DistributedHardware
} // OHOS
