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

#define private public
#include "daudio_sink_proxy_test.h"
#undef private

#include "daudio_constants.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "daudio_sink_ipc_callback.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkProxyTest::SetUpTestCase(void) {}

void DAudioSinkProxyTest::TearDownTestCase(void) {}

void DAudioSinkProxyTest::SetUp(void)
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    dAudioProxy = std::make_shared<DAudioSinkProxy>(remoteObject);
}

void DAudioSinkProxyTest::TearDown(void) {}

/**
 * @tc.name: SubscribeLocalHardware_001
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkProxyTest, SubscribeLocalHardware_001, TestSize.Level1)
{
    const std::string dhId = "dhId";
    const std::string param = "param";
    int32_t ret = dAudioProxy->SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = dAudioProxy->UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: SubscribeLocalHardware_002
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkProxyTest, SubscribeLocalHardware_002, TestSize.Level1)
{
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    size_t DAUDIO_LEGAL_DEVICE_ID_LEN = 10;
    std::string dhId;
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    const std::string param = "param";
    std::string devId = "devId";
    const int32_t eventType = 1;
    const std::string eventContent = "eventContent";
    int32_t ret = dAudioProxy->SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = dAudioProxy->UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    dAudioProxy->DAudioNotify(devId, dhId, eventType, eventContent);
    devId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    dhId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    dAudioProxy->DAudioNotify(devId, dhId, eventType, eventContent);
    ret = dAudioProxy->SubscribeLocalHardware(dhId, param);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = dAudioProxy->UnsubscribeLocalHardware(dhId);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: InitSink_001
 * @tc.desc: Verify the InitSink function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkProxyTest, InitSink_001, TestSize.Level1)
{
    const std::string params = "params";
    auto dAudioSinkIpcCallback = new DAudioSinkIpcCallback();
    int32_t ret = dAudioProxy->InitSink(params, dAudioSinkIpcCallback);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = dAudioProxy->ReleaseSink();
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: PauseDistributedHardware_001
 * @tc.desc: Verify the PauseDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkProxyTest, PauseDistributedHardware_001, TestSize.Level1)
{
    std::string networkId = "123";
    EXPECT_EQ(DH_SUCCESS, dAudioProxy->PauseDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, dAudioProxy->ResumeDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, dAudioProxy->StopDistributedHardware(networkId));
}
} // namespace DistributedHardware
} // namespace OHOS
