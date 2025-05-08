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

#include "daudio_sink_ctrl_trans.h"

#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "SinkCtrlTrans"

namespace OHOS {
namespace DistributedHardware {
int32_t DaudioSinkCtrlTrans::SetUp(const std::shared_ptr<IAudioCtrlTransCallback> &callback)
{
    DHLOGI("SetUp.");
    CHECK_NULL_RETURN(callback, ERR_DH_AUDIO_NULLPTR);
    ctrlTransCallback_ = callback;
    SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, devId_, this);
    return DH_SUCCESS;
}

int32_t DaudioSinkCtrlTrans::Release()
{
    DHLOGI("Release.");
    SoftbusChannelAdapter::GetInstance().CloseSoftbusChannel(sessionName_, devId_);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(sessionName_, devId_);
    ctrlTransCallback_.reset();
    return DH_SUCCESS;
}

int32_t DaudioSinkCtrlTrans::Start()
{
    DHLOGI("Start.");
    return DH_SUCCESS;
}

int32_t DaudioSinkCtrlTrans::Stop()
{
    DHLOGI("Stop.");
    return DH_SUCCESS;
}

int32_t DaudioSinkCtrlTrans::SendAudioEvent(uint32_t type, const std::string &content, const std::string &dstDevId)
{
    DHLOGI("SendAudioEvent, type: %{public}u, content: %{public}s.", type, content.c_str());
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    std::string msgData = message->MarshalMessage();
    return SoftbusChannelAdapter::GetInstance().SendBytesData(sessionName_, message->dstDevId_, msgData);
}

void DaudioSinkCtrlTrans::OnChannelEvent(const AVTransEvent &event)
{
    DHLOGI("OnChannelEvent, type: %{public}d", event.type);
    auto sourceDevObj = ctrlTransCallback_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    switch (event.type) {
        case EventType::EVENT_CHANNEL_OPEN_FAIL:
        case EventType::EVENT_CHANNEL_OPENED:
        case EventType::EVENT_CHANNEL_CLOSED:
        case EventType::EVENT_START_FAIL:
        case EventType::EVENT_START_SUCCESS:
        case EventType::EVENT_STOP_SUCCESS:
        case EventType::EVENT_ENGINE_ERROR:
        case EventType::EVENT_REMOTE_ERROR:
            sourceDevObj->OnCtrlTransEvent(event);
            break;
        case EventType::EVENT_DATA_RECEIVED: {
            auto avMessage = std::make_shared<AVTransMessage>();
            CHECK_AND_RETURN_LOG(!avMessage->UnmarshalMessage(event.content,
                event.peerDevId), "unmarshal message failed");
            sourceDevObj->OnCtrlTransMessage(avMessage);
            break;
        }
        default:
            DHLOGE("Invaild event type.");
            break;
    }
}

void DaudioSinkCtrlTrans::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}
} // namespace DistributedHardware
} // namespace OHOS