/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "av_receiver_engine_adapter.h"

#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AVTransReceiverAdapter"

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t WAIT_TIMEOUT_MS = 5000;
int32_t AVTransReceiverAdapter::Initialize(IAVEngineProvider *providerPtr, const std::string &peerDevId)
{
    DHLOGI("Initialize!");
    if (initialized_.load()) {
        return DH_SUCCESS;
    }
    if (providerPtr == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    receiverEngine_ = providerPtr->CreateAVReceiverEngine(peerDevId);
    if (receiverEngine_ == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    receiverEngine_->RegisterReceiverCallback(shared_from_this());
    initialized_ = true;
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::Release()
{
    DHLOGI("Release!");
    if (receiverEngine_ != nullptr) {
        if (!receiverEngine_->Release()) {
            DHLOGE("Release av transport receiver engine failed");
        }
    }
    initialized_ = false;
    receiverEngine_ = nullptr;
    chnCreateSuccess_ = false;
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::Start()
{
    DHLOGI("Start enter");
    if (receiverEngine_ == nullptr) {
        DHLOGE("Av transport receiver engine is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return receiverEngine_->Start();
}

int32_t AVTransReceiverAdapter::Stop()
{
    DHLOGI("Stop!");
    if (receiverEngine_ == nullptr) {
        DHLOGE("Av transport receiver engine is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return receiverEngine_->Stop();
}

int32_t AVTransReceiverAdapter::SetParameter(const AVTransTag &tag, const std::string &param)
{
    DHLOGI("SetParameter!");
    if (receiverEngine_ == nullptr) {
        DHLOGE("av transport receiver engine is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverEngine_->SetParameter(tag, param);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set av transport receiver parameter failed, ret: %d.", ret);
    }
    return ret;
}

int32_t AVTransReceiverAdapter::CreateControlChannel(const std::string &peerDevId)
{
    DHLOGI("CreateControlChannel enter, peerDevId:%s", GetAnonyString(peerDevId).c_str());
    if (chnCreateSuccess_.load()) {
        DHLOGI("Av transport receiver channel already created");
        return DH_SUCCESS;
    }

    if (receiverEngine_ == nullptr) {
        DHLOGE("Av transport receiver engine is null");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::vector<std::string> dstDevIds = {peerDevId};
    int32_t ret = receiverEngine_->CreateControlChannel(dstDevIds,
        ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    if (ret != DH_SUCCESS) {
        DHLOGE("Create av transport receiver channel failed, ret: %d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    ret = WaitForChannelCreated();
    if (ret != DH_SUCCESS) {
        DHLOGE("Wait for create av transport sender channel failed, ret: %d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::SendMessageToRemote(const std::shared_ptr<AVTransMessage> &message)
{
    DHLOGI("Send message to remote.");
    if (receiverEngine_ == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = receiverEngine_->SendMessage(message);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send meassage to remote sender engine failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::RegisterAdapterCallback(const std::shared_ptr<AVReceiverAdapterCallback> &callback)
{
    if (callback == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    adapterCallback_ = callback;
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::WaitForChannelCreated()
{
    std::unique_lock<std::mutex> lock(chnCreatedMtx_);
    auto status = chnCreatedCondVar_.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS));
    if (status == std::cv_status::timeout) {
        DHLOGI("Wait for av transport receiver channel created timeout");
        return ERR_DH_AUDIO_SA_WAIT_TIMEOUT;
    }
    if (!chnCreateSuccess_.load()) {
        DHLOGE("Create av transport receiver channel failed");
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::OnReceiverEvent(const AVTransEvent &event)
{
    DHLOGI("On Receiver event, type: %d", event.type);
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
            if (adapterCallback_ != nullptr) {
                DHLOGI("callback on engine event.");
                adapterCallback_->OnEngineEvent(event);
            }
            break;
        default:
            DHLOGI("Invaild event type");
            break;
    }
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::OnMessageReceived(const std::shared_ptr<AVTransMessage> &message)
{
    if (adapterCallback_ != nullptr) {
        adapterCallback_->OnEngineMessage(message);
    }
    return DH_SUCCESS;
}

int32_t AVTransReceiverAdapter::OnDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer)
{
    if (adapterCallback_ != nullptr) {
        adapterCallback_->OnEngineDataAvailable(buffer);
    }
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS