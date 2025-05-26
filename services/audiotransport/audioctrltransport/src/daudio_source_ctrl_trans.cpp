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

#include "daudio_source_ctrl_trans.h"

#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "SourceCtrlTrans"

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t WAIT_TIMEOUT_MS = 5000;
int32_t DaudioSourceCtrlTrans::SetUp(const std::shared_ptr<IAudioCtrlTransCallback> &callback)
{
    DHLOGI("SetUp.");
    CHECK_NULL_RETURN(callback, ERR_DH_AUDIO_NULLPTR);
    ctrlTransCallback_ = callback;
    SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, devId_, this);
    return DH_SUCCESS;
}

int32_t DaudioSourceCtrlTrans::Release()
{
    DHLOGI("Release.");
    SoftbusChannelAdapter::GetInstance().CloseSoftbusChannel(sessionName_, devId_);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(sessionName_, devId_);
    chnCreateSuccess_.store(false);
    return DH_SUCCESS;
}

int32_t DaudioSourceCtrlTrans::Start()
{
    DHLOGI("Start.");
    int32_t ret = SoftbusChannelAdapter::GetInstance().OpenSoftbusChannel(sessionName_, peerSessName_, devId_);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "OpenSoftbusChannel failed");
    ret = WaitForChannelCreated();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Wait for create ctrlChannel failed ret: %{public}d", ret);
    return DH_SUCCESS;
}

int32_t DaudioSourceCtrlTrans::Stop()
{
    DHLOGI("Stop.");
    return DH_SUCCESS;
}

int32_t DaudioSourceCtrlTrans::SendAudioEvent(uint32_t type, const std::string &content, const std::string &dstDevId)
{
    DHLOGI("SendAudioEvent, type: %{public}u.", type);
    auto message = std::make_shared<AVTransMessage>(type, content, dstDevId);
    std::string msgData = message->MarshalMessage();
    return SoftbusChannelAdapter::GetInstance().SendBytesData(sessionName_, message->dstDevId_, msgData);
}

void DaudioSourceCtrlTrans::OnChannelEvent(const AVTransEvent &event)
{
    DHLOGI("OnChannelEvent, type: %{public}d", event.type);
    auto sourceDevObj = ctrlTransCallback_.lock();
    CHECK_NULL_VOID(sourceDevObj);
    switch (event.type) {
        case EventType::EVENT_CHANNEL_OPEN_FAIL:
        case EventType::EVENT_CHANNEL_OPENED: {
            chnCreateSuccess_ = (event.type == EventType::EVENT_CHANNEL_OPENED);
            chnCreatedCondVar_.notify_one();
            break;
        }
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

void DaudioSourceCtrlTrans::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}

int32_t DaudioSourceCtrlTrans::WaitForChannelCreated()
{
    std::unique_lock<std::mutex> lock(chnCreatedMtx_);
    auto status = chnCreatedCondVar_.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS),
        [this]() { return chnCreateSuccess_.load(); });
    CHECK_AND_RETURN_RET_LOG(!status, ERR_DH_AUDIO_SA_WAIT_TIMEOUT, "Wait timeout.");
    CHECK_AND_RETURN_RET_LOG(!chnCreateSuccess_.load(), ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED,
        "Create ctrl channel failed.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS