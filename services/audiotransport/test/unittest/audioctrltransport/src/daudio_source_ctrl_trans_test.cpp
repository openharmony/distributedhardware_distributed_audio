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

#include "daudio_source_ctrl_trans_test.h"

#include "audio_data.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DaudioSourceCtrlTransTest::SetUpTestCase(void) {}

void DaudioSourceCtrlTransTest::TearDownTestCase(void) {}

void DaudioSourceCtrlTransTest::SetUp()
{
    std::string devId = "devId";
    std::string sessionName = "sessionName";
    std::string peerSessName = "peerSessName";
    ctrlTransCallback_ = std::make_shared<CtrlTransCallback>();
    ctrlTrans_ = std::make_shared<DaudioSourceCtrlTrans>(devId, sessionName, peerSessName, ctrlTransCallback_);
}

void DaudioSourceCtrlTransTest::TearDown()
{
    ctrlTrans_ = nullptr;
    ctrlTransCallback_ = nullptr;
}

void CtrlTransCallback::OnCtrlTransEvent(const AVTransEvent &event)
{
    (void)event;
}

void CtrlTransCallback::OnCtrlTransMessage(const std::shared_ptr<AVTransMessage> &message)
{
    (void)message;
}

/**
 * @tc.name: SendAudioEvent_001
 * @tc.desc: Verify the SendAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(DaudioSourceCtrlTransTest, SendAudioEvent_001, TestSize.Level1)
{
    ctrlTransCallback_ = nullptr;
    uint32_t type = 0;
    EventType eventType = EventType::EVENT_CHANNEL_OPEN_FAIL;
    std::string content = "content";
    std::string devId = "devId";
    AVTransEvent event = {eventType, content, devId};
    ctrlTrans_->OnChannelEvent(event);
    EXPECT_NE(DH_SUCCESS, ctrlTrans_->SendAudioEvent(type, content, devId));
}

/**
 * @tc.name: OnChannelEvent_001
 * @tc.desc: Verify the OnChannelEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000HTAPM
 */
HWTEST_F(DaudioSourceCtrlTransTest, OnChannelEvent_001, TestSize.Level1)
{
    uint32_t eventType = 0;
    EventType type = EventType::EVENT_CHANNEL_OPEN_FAIL;
    std::string content = "content";
    std::string devId = "devId";
    AVTransEvent event = {type, content, devId};
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_CHANNEL_OPENED;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_START_FAIL;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_START_SUCCESS;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_STOP_SUCCESS;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_ENGINE_ERROR;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_REMOTE_ERROR;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_DATA_RECEIVED;
    ctrlTrans_->OnChannelEvent(event);
    event.type = EventType::EVENT_ADD_STREAM;
    ctrlTrans_->OnChannelEvent(event);
    EXPECT_NE(DH_SUCCESS, ctrlTrans_->SendAudioEvent(eventType, content, devId));
}
} // namespace DistributedHardware
} // namespace OHOS