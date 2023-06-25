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

#ifndef OHOS_AV_TRANS_RECEIVER_ADAPTER_H
#define OHOS_AV_TRANS_RECEIVER_ADAPTER_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <dlfcn.h>

#include "i_av_receiver_engine_callback.h"
#include "i_av_receiver_engine.h"
#include "i_av_engine_provider.h"

namespace OHOS {
namespace DistributedHardware {
class AVReceiverAdapterCallback {
public:
    AVReceiverAdapterCallback() {};
    virtual ~AVReceiverAdapterCallback() = default;
    virtual void OnEngineEvent(const AVTransEvent &event) = 0;
    virtual void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) = 0;
    virtual void OnEngineDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer) = 0;
};

class AVTransReceiverAdapter : public IAVReceiverEngineCallback,
    public std::enable_shared_from_this<AVTransReceiverAdapter> {
public:
    AVTransReceiverAdapter() {};
    ~AVTransReceiverAdapter() override {};

    int32_t Initialize(IAVEngineProvider *providerPtr, const std::string &peerDevId);
    int32_t Start();
    int32_t Stop();
    int32_t Release();
    int32_t SetParameter(const AVTransTag &tag, const std::string &value);
    int32_t SendMessageToRemote(const std::shared_ptr<AVTransMessage> &message);
    int32_t CreateControlChannel(const std::string &peerDevId);
    int32_t RegisterAdapterCallback(const std::shared_ptr<AVReceiverAdapterCallback> &callback);

    int32_t OnReceiverEvent(const AVTransEvent &event) override;
    int32_t OnMessageReceived(const std::shared_ptr<AVTransMessage> &message) override;
    int32_t OnDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer) override;

private:
    int32_t WaitForChannelCreated();
private:
    std::atomic<bool> initialized_ = false;
    std::mutex chnCreatedMtx_;
    std::shared_ptr<IAVReceiverEngine> receiverEngine_;
    std::shared_ptr<AVReceiverAdapterCallback> adapterCallback_;
    std::atomic<bool> chnCreateSuccess_ = false;
    std::condition_variable chnCreatedCondVar_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif