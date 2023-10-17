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
    DHLOGD("Control manager constructed.");
}

DAudioSinkDevCtrlMgr::~DAudioSinkDevCtrlMgr()
{
    DHLOGD("Control manager deconstructed.");
}

void DAudioSinkDevCtrlMgr::OnStateChange(int32_t type)
{
    DHLOGD("Distributed audio sink device control manager state change, type: %d.", type);
    switch (type) {
        case AudioEventType::CTRL_OPENED:
            isOpened_.store(true);
            break;
        case AudioEventType::CTRL_CLOSED:
            isOpened_.store(false);
            break;
        default:
            DHLOGE("Invalid parameter type, type: %d.", type);
            return;
    }

    auto callback = audioEventCallback_.lock();
    if (callback == nullptr) {
        DHLOGE("Callback is nullptr.");
        return;
    }
    AudioEvent event(static_cast<AudioEventType>(type), "");
    callback->NotifyEvent(event);
}

int32_t DAudioSinkDevCtrlMgr::SetUp()
{
    DHLOGI("Set up sink device control manager.");
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
    DHLOGI("Start sink device control manager.");
    return DH_SUCCESS;
}

int32_t DAudioSinkDevCtrlMgr::Stop()
{
    DHLOGI("Stop sink device control manager.");
    isOpened_.store(false);
    if (audioCtrlTrans_ == nullptr) {
        DHLOGD("Ctrl trans already stop.");
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
    DHLOGI("Release sink device control manager.");
    if (audioCtrlTrans_ == nullptr) {
        DHLOGD("Ctrl trans already release.");
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

void DAudioSinkDevCtrlMgr::OnEventReceived(const AudioEvent &event)
{
    DHLOGD("Received event type %d.", event.type);
    auto callback = audioEventCallback_.lock();
    if (callback == nullptr) {
        DHLOGE("Callback is nullptr.");
        return;
    }
    callback->NotifyEvent(event);
}

int32_t DAudioSinkDevCtrlMgr::SendAudioEvent(const AudioEvent &event)
{
    DHLOGD("Send audio event.");
    if (audioCtrlTrans_ == nullptr) {
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
