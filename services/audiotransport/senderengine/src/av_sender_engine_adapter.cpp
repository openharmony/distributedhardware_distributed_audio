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

#include "av_sender_engine_adapter.h"
#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#include "av_trans_types.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AVTransSenderAdapter"

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t WAIT_TIMEOUT_MS = 5000;

int32_t AVTransSenderAdapter::Initialize(IAVEngineProvider *providerPtr, const std::string &peerDevId)
{
    DHLOGI("Initialize!");
    if (initialized_.load()) {
        return DH_SUCCESS;
    }
    if (providerPtr == nullptr) {
        DHLOGE("Av Transport sender engine provider ptr is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    senderEngine_ = providerPtr->CreateAVSenderEngine(peerDevId);
    if (senderEngine_ == nullptr) {
        DHLOGE("Create av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    senderEngine_->RegisterSenderCallback(shared_from_this());
    initialized_ = true;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::Release()
{
    DHLOGI("Release!");
    if (senderEngine_ != nullptr) {
        int32_t ret = senderEngine_->Release();
        if (ret != DH_SUCCESS) {
            DHLOGE("Release av transport sender engine failed");
        }
    }
    initialized_ = false;
    senderEngine_ = nullptr;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::Start()
{
    DHLOGI("Start!");
    if (senderEngine_ == nullptr) {
        DHLOGE("Av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    return senderEngine_->Start();
}

int32_t AVTransSenderAdapter::Stop()
{
    DHLOGI("Stop");
    if (senderEngine_ == nullptr) {
        DHLOGE("Av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    int32_t ret = senderEngine_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop av transport sender engine failed");
        return ERR_DH_AV_TRANS_STOP_FAILED;
    }
    DHLOGI("Stop Success");
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::CreateControlChannel(const std::string &peerDevId)
{
    DHLOGI("createControlChannel enter, peerDevId:%s", GetAnonyString(peerDevId).c_str());
    if (chnCreateSuccess_.load()) {
        DHLOGI("Av transport sender channel already created");
        return DH_SUCCESS;
    }

    if (senderEngine_ == nullptr) {
        DHLOGE("Av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    std::vector<std::string> dstDevIds = {peerDevId};
    int32_t ret = senderEngine_->CreateControlChannel(dstDevIds,
        ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    if (ret != DH_SUCCESS) {
        DHLOGI("Create av transport sender channel failed, ret: %d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    ret = WaitForChannelCreated();
    if (ret != DH_SUCCESS) {
        DHLOGE("Wait for create av transport sender channel failed ret: %d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::SetParameter(const AVTransTag &tag, const std::string &param)
{
    DHLOGI("SetParameter!");
    if (senderEngine_ == nullptr) {
        DHLOGE("av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    int32_t ret = senderEngine_->SetParameter(tag, param);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set av transport sender parameter failed, ret: %d", ret);
        return ERR_DH_AV_TRANS_SETUP_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::PushData(std::shared_ptr<AudioData> &audioData)
{
    if (senderEngine_ == nullptr) {
        DHLOGE("Av transport sender engine null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    auto transBuffer = std::make_shared<AVTransBuffer>(MetaType::AUDIO);
    auto bufferData = transBuffer->CreateBufferData(audioData->Size());
    bufferData->Write(audioData->Data(), audioData->Size());

    int32_t ret = senderEngine_->PushData(transBuffer);
    if (ret != DH_SUCCESS) {
        DHLOGI("Push data to av transport sender failed");
        return ERR_DH_AV_TRANS_FEED_DATA_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::SendMessageToRemote(const std::shared_ptr<AVTransMessage> &message)
{
    DHLOGI("Send message to remote");
    if (senderEngine_ == nullptr) {
        DHLOGE("Av transport sender engine is null");
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    int32_t ret = senderEngine_->SendMessage(message);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send Message to remote receiver engine failed, ret: %d", ret);
        return ERR_DH_AV_TRANS_SEND_MSG_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::RegisterAdapterCallback(const std::shared_ptr<AVSenderAdapterCallback> &callback)
{
    DHLOGI("RegisterAdapterCallback");
    if (callback == nullptr) {
        return ERR_DH_AV_TRANS_NULL_VALUE;
    }
    adapterCallback_ = callback;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::WaitForChannelCreated()
{
    std::unique_lock<std::mutex> lock(chnCreatedMtx_);
    auto status = chnCreatedCondVar_.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS));
    if (status == std::cv_status::timeout) {
        DHLOGI("Wait for av transport sender channel created timeout");
        return ERR_DH_AV_TRANS_TIMEOUT;
    }
    if (!chnCreateSuccess_.load()) {
        DHLOGE("Create av transport sender channel failed");
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::OnSenderEvent(const AVTransEvent &event)
{
    DHLOGI("On sender event, type: %d", event.type);
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

int32_t AVTransSenderAdapter::OnMessageReceived(const std::shared_ptr<AVTransMessage> &message)
{
    if (adapterCallback_ != nullptr) {
        adapterCallback_->OnEngineMessage(message);
    }
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS