/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "daudio_ctrl_channel_listener_test.h"

#include "audio_data.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DaudioCtrlChannelListenerTest::SetUpTestCase(void) {}

void DaudioCtrlChannelListenerTest::TearDownTestCase(void) {}

void DaudioCtrlChannelListenerTest::SetUp()
{
    ctrlListenerCallback_ = std::make_shared<CtrlChannelListener>();
    ctrlChannelListener_ = std::make_shared<DaudioCtrlChannelListener>(ctrlListenerCallback_);
}

void DaudioCtrlChannelListenerTest::TearDown()
{
    ctrlChannelListener_ = nullptr;
    ctrlListenerCallback_ = nullptr;
}

void CtrlChannelListener::OnCtrlChannelEvent(const AVTransEvent &event)
{
    (void)event;
}

/**
 * @tc.name: Initialize_001
 * @tc.desc: Verify the Initialize function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(DaudioCtrlChannelListenerTest, Initialize_001, TestSize.Level1)
{
    StreamData data;
    StreamData ext;
    std::string dataStr = "event";
    std::string peerDevId = "1";
    ctrlChannelListener_->OnStreamReceived(&data, &ext);
    AVTransEvent eventOpend = {EventType::EVENT_CHANNEL_OPENED, dataStr, peerDevId};
    AVTransEvent eventClosed = {EventType::EVENT_CHANNEL_CLOSED, dataStr, peerDevId};
    ctrlChannelListener_->OnChannelEvent(eventOpend);
    ctrlChannelListener_->OnChannelEvent(eventClosed);
    EXPECT_NE(DH_SUCCESS, ctrlChannelListener_->Init());
}
} // namespace DistributedHardware
} // namespace OHOS