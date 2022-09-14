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

#include "daudio_sink_dev_ctrl_manager.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"

#include "audio_ctrl_transport.h"
#include "audio_param.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkDevCtrlMgr"

namespace OHOS {
namespace DistributedHardware {
DAudioSinkDevCtrlMgr::DAudioSinkDevCtrlMgr(const std::string &devId,
    std::shared_ptr<IAudioEventCallback> audioEventCallback)
    : devId_(devId), audioEventCallback_(audioEventCallback)
{
    DHLOGI("Control manager constructed.");
}

DAudioSinkDevCtrlMgr::~DAudioSinkDevCtrlMgr()
{
    DHLOGI("Control manager deconstructed.");
}

void DAudioSinkDevCtrlMgr::OnStateChange(int32_t type)
{
    DHLOGI("Distributed audio sink development control manager state change, type: %d.", type);
    if (audioEventCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return;
    }
    std::shared_ptr<AudioEvent> event = std::make_shared<AudioEvent>();
    event->type = static_cast<AudioEventType>(type);
    event->content = "";
    audioEventCallback_->NotifyEvent(event);
    switch (type) {
        case AudioEventType::CTRL_OPENED:
            isOpened_.store(true);
            return;
        case AudioEventType::CTRL_CLOSED:
            return;
        default:
            DHLOGE("Invalid parameter type, type: %d.", type);
            return;
    }
}

int32_t DAudioSinkDevCtrlMgr::SetUp()
{
    DHLOGI("Set up sink development control manager.");
    if (audioCtrlTrans_ == nullptr) {
        audioCtrlTrans_ = std::make_shared<AudioCtrlTransport>(devId_);
    }

    int32_t ret = audioCtrlTrans_->SetUp(shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Ctrl trans setup failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkDevCtrlMgr::Start()
{
    DHLOGI("Start sink development control manager.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDevCtrlMgr::Stop()
{
    DHLOGI("Stop sink development control manager.");
    isOpened_.store(false);
    if (audioCtrlTrans_ == nullptr) {
        DHLOGI("Ctrl trans already stop.");
        return DH_SUCCESS;
    }

    int32_t ret = audioCtrlTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Ctrl trans stop failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSinkDevCtrlMgr::Release()
{
    DHLOGI("Release sink development control manager.");
    if (audioCtrlTrans_ == nullptr) {
        DHLOGI("Ctrl trans already release.");
        return DH_SUCCESS;
    }
    int32_t ret = audioCtrlTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Ctrl trans release failed, ret: %d.", ret);
        return ret;
    }
    audioCtrlTrans_ = nullptr;
    return DH_SUCCESS;
}

bool DAudioSinkDevCtrlMgr::IsOpened()
{
    return isOpened_.load();
}

void DAudioSinkDevCtrlMgr::OnEventReceived(const std::shared_ptr<AudioEvent> &event)
{
    DHLOGI("Received event.");
    if (audioEventCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return;
    }
    if (event == nullptr) {
        DHLOGE("The parameter is empty.");
        return;
    }
    audioEventCallback_->NotifyEvent(event);
}

int32_t DAudioSinkDevCtrlMgr::SendAudioEvent(const std::shared_ptr<AudioEvent> &event)
{
    DHLOGI("Send audio event.");
    if (audioCtrlTrans_ == nullptr) {
        return ERR_DH_AUDIO_SA_SINK_CTRL_TRANS_NULL;
    }
    if (event == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = audioCtrlTrans_->SendAudioEvent(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Audio control transfer sending audio event error,ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
