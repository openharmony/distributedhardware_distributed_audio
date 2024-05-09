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
#include "daudio_source_handler_test.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSourceHandlerTest::SetUpTestCase(void)
{
    DAudioSourceHandler::GetInstance().InitSource("DAudioSourceHandlerTest");
}

void DAudioSourceHandlerTest::TearDownTestCase(void)
{
    DAudioSourceHandler::GetInstance().ReleaseSource();
}

void DAudioSourceHandlerTest::SetUp(void) {}

void DAudioSourceHandlerTest::TearDown(void) {}

/**
 * @tc.name: RegisterDistributedHardware_001
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, RegisterDistributedHardware_001, TestSize.Level1)
{
    const std::string devId = "devId";
    const std::string dhId = "dhId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";
    std::shared_ptr<RegisterCallback> callback = std::make_shared<RegisterCallbackTest>();
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    int32_t ret = DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
    EXPECT_EQ(DH_SUCCESS, ret);
    std::shared_ptr<UnregisterCallback> uncallback = std::make_shared<UnregisterCallbackTest>();
    ret = DAudioSourceHandler::GetInstance().UnregisterDistributedHardware(devId, dhId, uncallback);
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: RegisterDistributedHardware_002
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, RegisterDistributedHardware_002, TestSize.Level1)
{
    const std::string devId = "devId";
    const std::string dhId = "dhId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";
    std::shared_ptr<RegisterCallback> callback = std::make_shared<RegisterCallbackTest>();
    DAudioSourceHandler::GetInstance().dAudioIpcCallback_ = nullptr;
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    int32_t ret = DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    std::shared_ptr<UnregisterCallback> uncallback = std::make_shared<UnregisterCallbackTest>();
    ret = DAudioSourceHandler::GetInstance().UnregisterDistributedHardware(devId, dhId, uncallback);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: RegisterDistributedHardware_003
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, RegisterDistributedHardware_003, TestSize.Level1)
{
    const std::string devId = "devId";
    const std::string dhId = "dhId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";
    std::shared_ptr<RegisterCallback> callback = std::make_shared<RegisterCallbackTest>();
    DAudioSourceHandler::GetInstance().dAudioIpcCallback_ = nullptr;
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = nullptr;
    int32_t ret = DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
    std::shared_ptr<UnregisterCallback> uncallback = std::make_shared<UnregisterCallbackTest>();
    ret = DAudioSourceHandler::GetInstance().UnregisterDistributedHardware(devId, dhId, uncallback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: RegisterDistributedHardware_004
 * @tc.desc: Verify the RegisterDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, RegisterDistributedHardware_004, TestSize.Level1)
{
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    size_t DAUDIO_LEGAL_DEVICE_ID_LEN = 10;
    std::string devId;
    devId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    std::string dhId = "dhId";
    EnableParam param;
    param.sinkVersion = "1";
    param.sinkAttrs = "attrs";
    std::shared_ptr<RegisterCallback> callback = std::make_shared<RegisterCallbackTest>();
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    DAudioSourceHandler::GetInstance().dAudioIpcCallback_ = new DAudioIpcCallback();
    int32_t ret = DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    std::shared_ptr<UnregisterCallback> uncallback = std::make_shared<UnregisterCallbackTest>();
    ret = DAudioSourceHandler::GetInstance().UnregisterDistributedHardware(devId, dhId, uncallback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    devId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    ret = DAudioSourceHandler::GetInstance().RegisterDistributedHardware(devId, dhId, param, callback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    ret = DAudioSourceHandler::GetInstance().UnregisterDistributedHardware(devId, dhId, uncallback);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
}

/**
 * @tc.name: ReleaseSource_001
 * @tc.desc: Verify the ReleaseSource function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, ReleaseSource_001, TestSize.Level1)
{
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = nullptr;
    int32_t ret = DAudioSourceHandler::GetInstance().ReleaseSource();
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: ReleaseSource_001
 * @tc.desc: Verify the ReleaseSource function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, ReleaseSource_002, TestSize.Level1)
{
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    int32_t ret = DAudioSourceHandler::GetInstance().ReleaseSource();
    EXPECT_EQ(DH_SUCCESS, ret);
    wptr<IRemoteObject> remote = nullptr;
    DAudioSourceHandler::GetInstance().OnRemoteSourceSvrDied(remote);
}

/**
 * @tc.name: ConfigDistributedHardware_001
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, ConfigDistributedHardware_001, TestSize.Level1)
{
    std::string devId = "devId";
    std::string dhId = "dhId";
    std::string key = "key";
    std::string value = "value";
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = nullptr;
    int32_t ret = DAudioSourceHandler::GetInstance().ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PROXY_NOT_INIT, ret);
}

/**
 * @tc.name: ConfigDistributedHardware_002
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, ConfigDistributedHardware_002, TestSize.Level1)
{
    std::string dhId = "dhId";
    std::string key = "key";
    std::string value = "value";
    size_t DAUDIO_MAX_DEVICE_ID_LEN = 101;
    size_t DAUDIO_LEGAL_DEVICE_ID_LEN = 10;
    std::string devId;
    devId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    int32_t ret = DAudioSourceHandler::GetInstance().ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
    devId.resize(DAUDIO_LEGAL_DEVICE_ID_LEN);
    dhId.resize(DAUDIO_MAX_DEVICE_ID_LEN);
    ret = DAudioSourceHandler::GetInstance().ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVID_ILLEGAL, ret);
}

/**
 * @tc.name: ConfigDistributedHardware_002
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceHandlerTest, ConfigDistributedHardware_003, TestSize.Level1)
{
    std::string devId = "devId";
    std::string dhId = "dhId";
    std::string key = "key";
    std::string value = "value";
    DAudioSourceHandler::GetInstance().dAudioSourceProxy_ = new MockIDAudioSource();
    int32_t ret = DAudioSourceHandler::GetInstance().ConfigDistributedHardware(devId, dhId, key, value);
    EXPECT_EQ(DH_SUCCESS, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
