/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "daudio_source_stub_test.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_callback_proxy.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_log.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSourceStubTest::SetUpTestCase(void) {}

void DAudioSourceStubTest::TearDownTestCase(void) {}

void DAudioSourceStubTest::SetUp()
{
    uint32_t saId = 6666;
    bool runOnCreate = true;
    sourceStub_ = std::make_shared<DAudioSourceService>(saId, runOnCreate);
}

void DAudioSourceStubTest::TearDown()
{
    sourceStub_ = nullptr;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: Verify the OnRemoteRequest function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSourceStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN, sourceStub_->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: VerifyPermission_001
 * @tc.desc: Verify the VerifyPermission function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSourceStubTest, VerifyPermission_001, TestSize.Level1)
{
    EXPECT_EQ(false, sourceStub_->VerifyPermission());
}

/**
 * @tc.name: InitSourceInner_001
 * @tc.desc: Verify the InitSourceInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSourceStubTest, InitSourceInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sourceStub_->InitSourceInner(data, reply, option));
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sourceStub_->ReleaseSourceInner(data, reply, option));
}

/**
 * @tc.name: RegisterDistributedHardwareInner_001
 * @tc.desc: Verify the RegisterDistributedHardwareInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSourceStubTest, RegisterDistributedHardwareInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sourceStub_->ConfigDistributedHardwareInner(data, reply, option);
    sourceStub_->DAudioNotifyInner(data, reply, option);
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sourceStub_->RegisterDistributedHardwareInner(data, reply, option));
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sourceStub_->UnregisterDistributedHardwareInner(data, reply, option));
}

/**
 * @tc.name: ConfigDistributedHardwareInner_001
 * @tc.desc: Verify the ConfigDistributedHardwareInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSourceStubTest, ConfigDistributedHardwareInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(DH_SUCCESS, sourceStub_->ConfigDistributedHardwareInner(data, reply, option));
    EXPECT_EQ(DH_SUCCESS, sourceStub_->DAudioNotifyInner(data, reply, option));
}
} // DistributedHardware
} // OHOS
