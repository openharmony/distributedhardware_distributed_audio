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

#ifndef OHOS_AV_SENDER_ENGINE_ADAPTER_H
#define OHOS_AV_SENDER_ENGINE_ADAPTER_H

#include <condition_variable>
#include <mutex>
#include <string>

#include <fstream>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "audio_param.h"
#include "audio_data.h"

#include "i_av_sender_engine_callback.h"
#include "i_av_sender_engine.h"
#include "i_av_engine_provider.h"

namespace OHOS {
namespace DistributedHardware {
class AVSenderAdapterCallback {
public:
    AVSenderAdapterCallback() {};
    virtual ~AVSenderAdapterCallback() = default;
    virtual void OnEngineEvent(const AVTransEvent &event) = 0;
    virtual void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) = 0;
};

class AVTransSenderAdapter : public IAVSenderEngineCallback,
    public std::enable_shared_from_this<AVTransSenderAdapter> {
public:
    AVTransSenderAdapter() = default;
    ~AVTransSenderAdapter() = default;

    int32_t Initialize(IAVEngineProvider *providerPtr, const std::string &peerDevId);
    int32_t Release();
    int32_t Start();
    int32_t Stop();
    int32_t SetParameter(const AVTransTag &tag, const std::string &param);
    int32_t PushData(std::shared_ptr<AudioData> &audioData);
    int32_t SendMessageToRemote(const std::shared_ptr<AVTransMessage> &message);
    int32_t CreateControlChannel(const std::string &peerDevId);
    int32_t RegisterAdapterCallback(const std::shared_ptr<AVSenderAdapterCallback> &back);

    int32_t OnSenderEvent(const AVTransEvent &event) override;
    int32_t OnMessageReceived(const std::shared_ptr<AVTransMessage> &message) override;
private:
    int32_t WaitForChannelCreated();
private:
    std::atomic<bool> initialized_ = false;
    std::mutex chnCreatedMtx_;
    std::condition_variable chnCreatedCondVar_;
    std::atomic<bool> chnCreateSuccess_ = false;
    std::shared_ptr<IAVSenderEngine> senderEngine_;
    std::shared_ptr<AVSenderAdapterCallback> adapterCallback_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_AV_SENDER_ENGINE_ADAPTER_H