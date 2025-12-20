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

#define private public
#include "daudio_sink_handler_test.h"
#undef private

#include "daudio_sink_proxy.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkHandlerTest::SetUpTestCase(void)
{
    DAudioSinkHandler::GetInstance().InitSink("DAudioSinkHandlerTest");
}

void DAudioSinkHandlerTest::TearDownTestCase(void)
{
    DAudioSinkHandler::GetInstance().ReleaseSink();
}

void DAudioSinkHandlerTest::SetUp(void) {}

void DAudioSinkHandlerTest::TearDown(void) {}

/**
 * @tc.name: LocalHardware_001
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_001, TestSize.Level1)
{
    const std::string dhId = "DAudioSinkHandlerTest";
    const std::string param = "DAudioSinkHandlerTest";
    int32_t ret = DAudioSinkHandler::GetInstance().SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = DAudioSinkHandler::GetInstance().UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_002
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_002, TestSize.Level1)
{
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    std::string dhId;
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    const std::string param = "DAudioSinkHandlerTest";
    int32_t ret = DAudioSinkHandler::GetInstance().SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = DAudioSinkHandler::GetInstance().UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
}

/**
 * @tc.name: LocalHardware_003
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_003, TestSize.Level1)
{
    const std::string dhId = "DAudioSinkHandlerTest";
    const std::string param = "DAudioSinkHandlerTest";
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    ret = DAudioSinkHandler::GetInstance().UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    wptr<IRemoteObject> remote = nullptr;
    DAudioSinkHandler::GetInstance().OnRemoteSinkSvrDied(remote);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    wptr<IRemoteObject> remoteobject (remoteObject);
    DAudioSinkHandler::GetInstance().OnRemoteSinkSvrDied(remoteobject);
    DAudioSinkHandler::GetInstance().sinkSvrRecipient_ = sptr<DAudioSinkHandler::DAudioSinkSvrRecipient>(
        new DAudioSinkHandler::DAudioSinkSvrRecipient());
    ASSERT_TRUE(DAudioSinkHandler::GetInstance().sinkSvrRecipient_ != nullptr);
    DAudioSinkHandler::GetInstance().sinkSvrRecipient_->OnRemoteDied(remoteobject);
    DAudioSinkHandler::GetInstance().sinkSvrRecipient_ = nullptr;
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    DAudioSinkHandler::GetInstance().OnRemoteSinkSvrDied(remoteobject);
}

/**
 * @tc.name: LocalHardware_004
 * @tc.desc: Verify the RegisterPrivacyResources function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_004, TestSize.Level1)
{
    std::shared_ptr<PrivacyResourcesListener> listener = nullptr;
    DAudioSinkHandler::GetInstance().dAudioSinkIpcCallback_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().RegisterPrivacyResources(listener);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    DAudioSinkHandler::GetInstance().dAudioSinkIpcCallback_ = sptr<DAudioSinkIpcCallback>(new DAudioSinkIpcCallback());
    ret = DAudioSinkHandler::GetInstance().RegisterPrivacyResources(listener);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_005
 * @tc.desc: Verify the PauseDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_005, TestSize.Level1)
{
    std::string networkId = "networkId";
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().PauseDistributedHardware(networkId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    ret = DAudioSinkHandler::GetInstance().PauseDistributedHardware(networkId);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_006
 * @tc.desc: Verify the ResumeDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_006, TestSize.Level1)
{
    std::string networkId = "networkId";
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().ResumeDistributedHardware(networkId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, DAudioSinkHandler::GetInstance().StopDistributedHardware(networkId));
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    ret = DAudioSinkHandler::GetInstance().ResumeDistributedHardware(networkId);
    EXPECT_EQ(DH_SUCCESS, ret);
    EXPECT_EQ(DH_SUCCESS, DAudioSinkHandler::GetInstance().StopDistributedHardware(networkId));
}

/**
 * @tc.name: LocalHardware_007
 * @tc.desc: Verify the SetAccessListener function with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_007, TestSize.Level1)
{
    sptr<IAccessListener> listener = nullptr;
    int32_t timeOut = 5000;
    std::string pkgName = "com.example.test";
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAccessListener(listener, timeOut, pkgName);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: LocalHardware_008
 * @tc.desc: Verify the SetAccessListener function with null proxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_008, TestSize.Level1)
{
    sptr<IAccessListener> listener = nullptr;
    int32_t timeOut = 3000;
    std::string pkgName = "com.example.test";
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAccessListener(listener, timeOut, pkgName);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: LocalHardware_009
 * @tc.desc: Verify the SetAccessListener function with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_009, TestSize.Level1)
{
    sptr<IAccessListener> listener = nullptr;
    int32_t timeOut = 0;
    std::string emptyPkgName = "";
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAccessListener(listener, timeOut, emptyPkgName);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: LocalHardware_010
 * @tc.desc: Verify the RemoveAccessListener function with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_010, TestSize.Level1)
{
    std::string pkgName = "com.example.test";
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().RemoveAccessListener(pkgName);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_011
 * @tc.desc: Verify the RemoveAccessListener function with null proxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_011, TestSize.Level1)
{
    std::string pkgName = "com.example.test";
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().RemoveAccessListener(pkgName);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: LocalHardware_012
 * @tc.desc: Verify the RemoveAccessListener function with empty package name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_012, TestSize.Level1)
{
    std::string emptyPkgName = "";
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().RemoveAccessListener(emptyPkgName);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_013
 * @tc.desc: Verify the SetAuthorizationResult function with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_013, TestSize.Level1)
{
    std::string requestId = "123";
    bool granted = true;
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAuthorizationResult(requestId, granted);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: LocalHardware_014
 * @tc.desc: Verify the SetAuthorizationResult function with null proxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_014, TestSize.Level1)
{
    std::string requestId = "456";
    bool granted = false;
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = nullptr;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAuthorizationResult(requestId, granted);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: LocalHardware_015
 * @tc.desc: Verify the SetAuthorizationResult function with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkHandlerTest, LocalHardware_015, TestSize.Level1)
{
    std::string emptyRequestId = "";
    bool granted = true;
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    sptr<IDAudioSink> proxy(new DAudioSinkProxy(remoteObject));
    DAudioSinkHandler::GetInstance().dAudioSinkProxy_ = proxy;
    int32_t ret = DAudioSinkHandler::GetInstance().SetAuthorizationResult(emptyRequestId, granted);
    EXPECT_EQ(DH_SUCCESS, ret);
    std::string requestId2 = "789";
    ret = DAudioSinkHandler::GetInstance().SetAuthorizationResult(requestId2, false);
    EXPECT_EQ(DH_SUCCESS, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
