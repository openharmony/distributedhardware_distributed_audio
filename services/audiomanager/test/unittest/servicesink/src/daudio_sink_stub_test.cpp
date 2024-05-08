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

#include "daudio_sink_stub_test.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "audio_event.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_ipc_interface_code.h"
#include "daudio_sink_ipc_callback_proxy.h"
#include "daudio_sink_load_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkStubTest::SetUpTestCase(void) {}

void DAudioSinkStubTest::TearDownTestCase(void) {}

void DAudioSinkStubTest::SetUp()
{
    uint32_t saId = 6666;
    bool runOnCreate = true;
    sinkStub_ = std::make_shared<DAudioSinkService>(saId, runOnCreate);
}

void DAudioSinkStubTest::TearDown()
{
    sinkStub_ = nullptr;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: Verify the OnRemoteRequest function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_DH_AUDIO_SA_INVALID_INTERFACE_TOKEN, sinkStub_->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: VerifyPermission_001
 * @tc.desc: Verify the VerifyPermission function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkStubTest, VerifyPermission_001, TestSize.Level1)
{
    EXPECT_EQ(false, sinkStub_->VerifyPermission());
}

/**
 * @tc.name: InitSinkInner_001
 * @tc.desc: Verify the InitSinkInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkStubTest, InitSinkInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sinkStub_->InitSinkInner(data, reply, option));
    EXPECT_EQ(ERR_DH_AUDIO_SA_PERMISSION_FAIED, sinkStub_->ReleaseSinkInner(data, reply, option));
}

/**
 * @tc.name: PauseDistributedHardwareInner_001
 * @tc.desc: Verify the PauseDistributedHardwareInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkStubTest, PauseDistributedHardwareInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL,
        sinkStub_->PauseDistributedHardwareInner(data, reply, option));
    EXPECT_EQ(ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL,
        sinkStub_->ResumeDistributedHardwareInner(data, reply, option));
    EXPECT_EQ(ERR_DH_AUDIO_ACCESS_PERMISSION_CHECK_FAIL,
        sinkStub_->StopDistributedHardwareInner(data, reply, option));
}

/**
 * @tc.name: SubscribeLocalHardwareInner_001
 * @tc.desc: Verify the SubscribeLocalHardwareInner function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DAudioSinkStubTest, SubscribeLocalHardwareInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(DH_SUCCESS, sinkStub_->SubscribeLocalHardwareInner(data, reply, option));
    EXPECT_EQ(DH_SUCCESS, sinkStub_->UnsubscribeLocalHardwareInner(data, reply, option));
    EXPECT_EQ(DH_SUCCESS, sinkStub_->DAudioNotifyInner(data, reply, option));
}
} // DistributedHardware
} // OHOS
