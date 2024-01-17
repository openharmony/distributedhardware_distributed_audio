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
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.audioDevMap_.emplace(devId, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.channelState_ = ChannelState::SPK_CONTROL_OPENED;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, daudioSinkManager.CreateAudioDevice(devId));
    daudioSinkManager.ClearAudioDev(devId);
    daudioSinkManager.channelState_ = ChannelState::MIC_CONTROL_OPENED;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, daudioSinkManager.CreateAudioDevice(devId));
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
    if (samgr == nullptr) {
        return;
    }
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    auto dev = std::make_shared<DAudioSinkDev>(networkId, dAudioSinkIpcCallbackProxy);
    daudioSinkManager.audioDevMap_.emplace(devId, dev);
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
    if (samgr == nullptr) {
        return;
    }
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject));
    daudioSinkManager.ipcSinkCallback_ = dAudioSinkIpcCallbackProxy;
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    daudioSinkManager.isSensitive_ = true;
    daudioSinkManager.isSameAccount_ = false;
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
    daudioSinkManager.isSameAccount_ = true;
    EXPECT_NE(DH_SUCCESS, daudioSinkManager.VerifySecurityLevel(devId));
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
    std::string srcDeviceId = "srcDeviceId";
    std::string dstDeviceId = "dstDeviceId";
    EXPECT_EQ(false, daudioSinkManager.CheckDeviceSecurityLevel(srcDeviceId, dstDeviceId));
}
} // DistributedHardware
} // OHOS
