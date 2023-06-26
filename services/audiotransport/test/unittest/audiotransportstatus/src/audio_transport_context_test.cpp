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

#include "audio_transport_context_test.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void AudioTransportContextTest::SetUpTestCase(void) {}

void AudioTransportContextTest::TearDownTestCase(void) {}

void AudioTransportContextTest::SetUp(void)
{
    stateContext_ = std::make_shared<AudioTransportContext>();
}

void AudioTransportContextTest::TearDown(void)
{
    stateContext_ = nullptr;
}

/**
 * @tc.name: GetTransportStatus_001
 * @tc.desc: Verify GetTransportStatus func.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportContextTest, GetTransportStatus_001, TestSize.Level1)
{
    TransportStateType type = TransportStateType::TRANSPORT_STATE_START;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, stateContext_->GetTransportStatusType());
    stateContext_->SetTransportStatus(type);
    EXPECT_EQ(TransportStateType::TRANSPORT_STATE_START, stateContext_->GetTransportStatusType());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify Stop func.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(AudioTransportContextTest, Stop_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, stateContext_->Start());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, stateContext_->Pause());
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, stateContext_->Stop());
    TransportStateType type = TransportStateType::TRANSPORT_STATE_START;
    stateContext_->SetTransportStatus(type);
    EXPECT_EQ(DH_SUCCESS, stateContext_->Start());
    EXPECT_NE(DH_SUCCESS, stateContext_->Stop());
}
} // namespace DistributedHardware
} // namespace OHOS
