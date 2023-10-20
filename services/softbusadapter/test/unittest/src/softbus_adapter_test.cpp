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

#include "softbus_adapter_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void SoftbusAdapterTest::SetUpTestCase(void) {}

void SoftbusAdapterTest::TearDownTestCase(void) {}

void SoftbusAdapterTest::SetUp(void) {}

void SoftbusAdapterTest::TearDown(void) {}

/**
 * @tc.name: RegisterSoftbusListener_001
 * @tc.desc: Verify the RegisterSoftbusListener and UnRegisterSoftbusListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusListener_001, TestSize.Level1)
{
    std::string sessionName = CTRL_SESSION_NAME;
    std::string peerDevId = "peerDevId";
    std::shared_ptr<ISoftbusListener> listener = std::make_shared<MockISoftbusListener>();

    EXPECT_EQ(DH_SUCCESS, softbusAdapter.RegisterSoftbusListener(listener, sessionName, peerDevId));
    EXPECT_EQ(DH_SUCCESS, softbusAdapter.UnRegisterSoftbusListener(sessionName, peerDevId));
}

/**
 * @tc.name: CreateSoftbusSessionServer_001
 * @tc.desc: Verify the CreateSoftbusSessionServer and RemoveSoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, CreateSoftbusSessionServer_001, TestSize.Level1)
{
    std::string pkgname;
    std::string sessionName = CTRL_SESSION_NAME;
    std::string peerDevId = "peerDevId";

    EXPECT_NE(DH_SUCCESS, softbusAdapter.CreateSoftbusSessionServer(pkgname, sessionName, peerDevId));
    EXPECT_EQ(DH_SUCCESS, softbusAdapter.RemoveSoftbusSessionServer(pkgname, sessionName, peerDevId));
}

/**
 * @tc.name: OpenSoftbusSession_001
 * @tc.desc: Verify the OpenSoftbusSession and CloseSoftbusSession function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, OpenSoftbusSession_001, TestSize.Level1)
{
    std::string localSessionName;
    std::string peerSessionName;
    std::string peerDevId;
    int32_t actual = softbusAdapter.OpenSoftbusSession(localSessionName, peerSessionName, peerDevId);

    EXPECT_EQ(ERR_DH_AUDIO_FAILED, actual);
    EXPECT_EQ(DH_SUCCESS, softbusAdapter.CloseSoftbusSession(actual));
}

/**
 * @tc.name: OpenSoftbusSession_002
 * @tc.desc: Verify the OpenSoftbusSession and CloseSoftbusSession function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, OpenSoftbusSession_002, TestSize.Level1)
{
    std::string localSessionName = CTRL_SESSION_NAME;
    std::string peerSessionName = CTRL_SESSION_NAME;
    std::string peerDevId = "peerDevId";
    int actual = softbusAdapter.OpenSoftbusSession(localSessionName, peerSessionName, peerDevId);

    EXPECT_NE(DH_SUCCESS, actual);
    EXPECT_EQ(DH_SUCCESS, softbusAdapter.CloseSoftbusSession(actual));
}

/**
 * @tc.name: SendSoftbusBytes_001
 * @tc.desc: Verify the SendSoftbusBytes function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, SendSoftbusBytes_001, TestSize.Level1)
{
    int32_t sessionId = -1;
    uint8_t *data = nullptr;
    int32_t dataLen = 0;

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, softbusAdapter.SendSoftbusBytes(sessionId, data, dataLen));
}

/**
 * @tc.name: SendSoftbusStream_001
 * @tc.desc: Verify the SendSoftbusStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, SendSoftbusStream_001, TestSize.Level1)
{
    int32_t sessionId = 0;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);

    EXPECT_EQ(DH_SUCCESS, softbusAdapter.SendSoftbusStream(sessionId, audioData));
}

/**
 * @tc.name: OnSoftbusSessionOpened_001
 * @tc.desc: Verify the OnSoftbusSessionOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, OnSoftbusSessionOpened_001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t result = -1;

    EXPECT_EQ(ERR_DH_AUDIO_FAILED, softbusAdapter.OnSoftbusSessionOpened(sessionId, result));
}

/**
 * @tc.name: OnSoftbusSessionOpened_001
 * @tc.desc: Verify the OnSoftbusSessionClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(SoftbusAdapterTest, OnSoftbusSessionOpened_002, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t result = 0;

    EXPECT_EQ(ERR_DH_AUDIO_TRANS_ERROR, softbusAdapter.OnSoftbusSessionOpened(sessionId, result));
    softbusAdapter.OnSoftbusSessionClosed(sessionId);
}
} // namespace DistributedHardware
} // namespace OHOS
