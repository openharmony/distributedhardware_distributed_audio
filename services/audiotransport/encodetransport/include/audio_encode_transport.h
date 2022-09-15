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

#ifndef AUDIO_ENCODE_TRANSPORT_H
#define AUDIO_ENCODE_TRANSPORT_H

#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "audio_event.h"
#include "iaudio_channel.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_data_transport.h"
#include "iaudio_processor.h"
#include "iaudio_processor_callback.h"

namespace OHOS {
namespace DistributedHardware {
class AudioEncodeTransport : public IAudioDataTransport,
    public IAudioChannelListener,
    public IAudioProcessorCallback,
    public std::enable_shared_from_this<AudioEncodeTransport> {
public:
    explicit AudioEncodeTransport(const std::string peerDevId) : peerDevId_(peerDevId) {}
    ~AudioEncodeTransport() = default;
    int32_t SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
        const std::shared_ptr<IAudioDataTransCallback> &callback, const std::string &role) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t FeedAudioData(std::shared_ptr<AudioData> &audioData) override;

    void OnSessionOpened() override;
    void OnSessionClosed() override;
    void OnDataReceived(const std::shared_ptr<AudioData> &data) override;
    void OnEventReceived(const AudioEvent &event) override;

    void OnAudioDataDone(const std::shared_ptr<AudioData> &outputData) override;
    void OnStateNotify(const AudioEvent &event) override;

private:
    int32_t InitAudioEncodeTrans(const AudioParam &localParam, const AudioParam &remoteParam, const std::string &role);
    int32_t RegisterChannelListener(const std::string &role);
    int32_t RegisterProcessorListener(const AudioParam &localParam, const AudioParam &remoteParam);

private:
    static const constexpr uint8_t SESSION_WAIT_SECONDS = 5;

    std::weak_ptr<IAudioDataTransCallback> dataTransCallback_;
    std::shared_ptr<IAudioChannel> audioChannel_ = nullptr;
    std::shared_ptr<IAudioProcessor> processor_ = nullptr;
    std::string peerDevId_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // AUDIO_ENCODE_TRANSPORT_H
