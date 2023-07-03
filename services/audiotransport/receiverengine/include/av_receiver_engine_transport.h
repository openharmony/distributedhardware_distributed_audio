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

#ifndef OHOS_AV_TRANS_RECEIVER_TRANS_H
#define OHOS_AV_TRANS_RECEIVER_TRANS_H

#include <condition_variable>
#include <mutex>
#include <string>

#include "audio_data.h"
#include "audio_param.h"
#include "av_receiver_engine_adapter.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "i_av_receiver_engine_callback.h"
#include "i_av_receiver_engine.h"
#include "i_av_engine_provider.h"

namespace OHOS {
namespace DistributedHardware {
class AVReceiverTransportCallback {
public:
    AVReceiverTransportCallback() {};
    virtual ~AVReceiverTransportCallback() = default;
    virtual void OnEngineTransEvent(const AVTransEvent &event) = 0;
    virtual void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) = 0;
    virtual void OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData) = 0;
};

class AVTransReceiverTransport :  public IAudioDataTransport,
    public AVReceiverAdapterCallback,
    public std::enable_shared_from_this<AVTransReceiverTransport> {
public:
    AVTransReceiverTransport(const std::string &devId,
        const std::shared_ptr<AVReceiverTransportCallback> &callback)
        : transCallback_(callback), devId_(devId) {};
    ~AVTransReceiverTransport() override {};

    int32_t SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
        const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t Pause() override;
    int32_t Restart(const AudioParam &localParam, const AudioParam &remoteParam) override;
    int32_t FeedAudioData(std::shared_ptr<AudioData> &audioData) override;
    int32_t CreateCtrl() override;
    int32_t InitEngine(IAVEngineProvider *providerPtr) override;
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override;

    void OnEngineEvent(const AVTransEvent &event) override;
    void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) override;
    void OnEngineDataAvailable(const std::shared_ptr<AVTransBuffer> &buffer) override;

private:
    int32_t SetParameter(const AudioParam &audioParam);

private:
    std::shared_ptr<AVTransReceiverAdapter> receiverAdapter_;
    std::shared_ptr<AVReceiverTransportCallback> transCallback_;
    std::string devId_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif