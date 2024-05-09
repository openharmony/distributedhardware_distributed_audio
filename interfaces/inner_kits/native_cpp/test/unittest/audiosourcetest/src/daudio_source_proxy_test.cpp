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
#include "daudio_source_proxy_test.h"
#undef private

#include "daudio_constants.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSourceProxyTest::SetUpTestCase(void) {}

void DAudioSourceProxyTest::TearDownTestCase(void) {}

void DAudioSourceProxyTest::SetUp(void)
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject == nullptr) {
        return;
    }
    dAudioProxy = std::make_shared<DAudioSourceProxy>(remoteObject);
}

void DAudioSourceProxyTest::TearDown(void) {}

/**
 * @tc.name: RegisterDistributedHardware_001
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceProxyTest, RegisterDistributedHardware_001, TestSize.Level1)
{
    const std::string devId = "devId";
    const std::string dhId = "dhId";
    const std::string reqId = "reqId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";

    int32_t ret = dAudioProxy->RegisterDistributedHardware(devId, dhId, param, reqId);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = dAudioProxy->UnregisterDistributedHardware(devId, dhId, reqId);
    EXPECT_EQ(DH_SUCCESS, ret);
    ret = dAudioProxy->ReleaseSource();
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: RegisterDistributedHardware_002
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceProxyTest, RegisterDistributedHardware_002, TestSize.Level1)
{
    size_t  DAUDIO_MAX_DEVICE_ID_LEN = 101;
    std::string devId;
    devId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    const std::string dhId = "dhId";
    const std::string reqId = "reqId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";

    int32_t ret = dAudioProxy->RegisterDistributedHardware(devId, dhId, param, reqId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = dAudioProxy->UnregisterDistributedHardware(devId, dhId, reqId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
}

/**
 * @tc.name: RegisterDistributedHardware_003
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceProxyTest, RegisterDistributedHardware_003, TestSize.Level1)
{
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    size_t DAUDIO_LEGAL_DEVICE_ID_LEN = 10;
    std::string devId;
    devId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    std::string dhId;
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    std::string reqId = "reqId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";

    int32_t ret = dAudioProxy->RegisterDistributedHardware(devId, dhId, param, reqId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = dAudioProxy->UnregisterDistributedHardware(devId, dhId, reqId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    dhId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    reqId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    ret = dAudioProxy->RegisterDistributedHardware(devId, dhId, param, reqId);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = dAudioProxy->UnregisterDistributedHardware(devId, dhId, reqId);
}

/**
 * @tc.name: ConfigDistributedHardware_001
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceProxyTest, ConfigDistributedHardware_001, TestSize.Level1)
{
    const std::string devId = "devId";
    const std::string dhId = "dhId";
    const std::string key = "value";
    const std::string value = "value";

    int32_t ret = dAudioProxy->ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: ConfigDistributedHardware_002
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceProxyTest, ConfigDistributedHardware_002, TestSize.Level1)
{
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    size_t DAUDIO_LEGAL_DEVICE_ID_LEN = 10;
    const int32_t eventType = 1;
    std::string devId;
    devId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    std::string dhId = "dhId";
    const std::string key = "value";
    const std::string value = "value";
    dAudioProxy->DAudioNotify(devId, dhId, eventType, value);
    int32_t ret = dAudioProxy->ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    devId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    dAudioProxy->DAudioNotify(devId, dhId, eventType, value);
    ret = dAudioProxy->ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
