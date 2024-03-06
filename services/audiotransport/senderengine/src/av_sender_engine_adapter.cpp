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
    DHLOGI("Init av sender engine.");
    CHECK_NULL_RETURN(providerPtr, ERR_DH_AUDIO_NULLPTR);
    if (initialized_.load()) {
        return DH_SUCCESS;
    }

    senderEngine_ = providerPtr->CreateAVSenderEngine(peerDevId);
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    senderEngine_->RegisterSenderCallback(shared_from_this());
    initialized_ = true;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::Release()
{
    DHLOGI("Release av sender engine.");
    if (senderEngine_ != nullptr) {
        if (senderEngine_->Release() != DH_SUCCESS) {
            DHLOGE("Release av sender engine failed");
        }
    }
    initialized_ = false;
    senderEngine_ = nullptr;
    chnCreateSuccess_ = false;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::Start()
{
    DHLOGI("Start av sender engine.");
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    return senderEngine_->Start();
}

int32_t AVTransSenderAdapter::Stop()
{
    DHLOGI("Stop av sender engine.");
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    return senderEngine_->Stop();
}

int32_t AVTransSenderAdapter::CreateControlChannel(const std::string &peerDevId)
{
    DHLOGI("Create control channel,peerDevId:%{public}s", GetAnonyString(peerDevId).c_str());
    if (chnCreateSuccess_.load()) {
        DHLOGI("Channel already created.");
        return DH_SUCCESS;
    }

    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    std::vector<std::string> dstDevIds = {peerDevId};
    int32_t ret = senderEngine_->CreateControlChannel(dstDevIds,
        ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    if (ret != DH_SUCCESS) {
        DHLOGI("Create control channel failed, ret: %{public}d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    ret = WaitForChannelCreated();
    if (ret != DH_SUCCESS) {
        DHLOGE("Wait for create av transport sender channel failed ret: %{public}d", ret);
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::SetParameter(const AVTransTag &tag, const std::string &param)
{
    DHLOGI("Set audio param.");
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    return senderEngine_->SetParameter(tag, param);
}

int32_t AVTransSenderAdapter::PushData(std::shared_ptr<AudioData> &audioData)
{
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    auto transBuffer = std::make_shared<AVTransBuffer>(MetaType::AUDIO);
    auto bufferData = transBuffer->CreateBufferData(audioData->Size());
    CHECK_NULL_RETURN(bufferData, ERR_DH_AUDIO_NULLPTR);

    bufferData->Write(audioData->Data(), audioData->Size());
    return senderEngine_->PushData(transBuffer);
}

int32_t AVTransSenderAdapter::SendMessageToRemote(const std::shared_ptr<AVTransMessage> &message)
{
    DHLOGI("Send message to remote.");
    CHECK_NULL_RETURN(senderEngine_, ERR_DH_AUDIO_NULLPTR);
    return senderEngine_->SendMessage(message);
}

int32_t AVTransSenderAdapter::RegisterAdapterCallback(const std::shared_ptr<AVSenderAdapterCallback> &callback)
{
    DHLOGI("Register adapter callback.");
    CHECK_NULL_RETURN(callback, ERR_DH_AUDIO_NULLPTR);
    adapterCallback_ = callback;
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::WaitForChannelCreated()
{
    std::unique_lock<std::mutex> lock(chnCreatedMtx_);
    auto status = chnCreatedCondVar_.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS),
        [this]() { return chnCreateSuccess_.load(); });
    if (!status) {
        DHLOGI("Wait timeout.");
        return ERR_DH_AUDIO_SA_WAIT_TIMEOUT;
    }
    if (!chnCreateSuccess_.load()) {
        DHLOGE("Create av sender channel failed.");
        return ERR_DH_AV_TRANS_CREATE_CHANNEL_FAILED;
    }
    return DH_SUCCESS;
}

int32_t AVTransSenderAdapter::OnSenderEvent(const AVTransEvent &event)
{
    DHLOGI("On sender event, type: %{public}d", event.type);
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
                DHLOGI("Send event.");
                adapterCallback_->OnEngineEvent(event);
            }
            break;
        default:
            DHLOGI("Invaild event type.");
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