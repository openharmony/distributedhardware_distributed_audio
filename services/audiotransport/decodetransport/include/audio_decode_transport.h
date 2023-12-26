/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef AUDIO_DECODE_TRANSPORT_H
#define AUDIO_DECODE_TRANSPORT_H

#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include "audio_event.h"
#include "audio_transport_context.h"
#include "daudio_constants.h"
#include "iaudio_channel.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_data_transport.h"
#include "iaudio_processor.h"
#include "iaudio_processor_callback.h"

namespace OHOS {
namespace DistributedHardware {
class AudioDecodeTransport : public IAudioDataTransport,
    public IAudioChannelListener,
    public IAudioProcessorCallback,
    public std::enable_shared_from_this<AudioDecodeTransport> {
public:
    explicit AudioDecodeTransport(const std::string &peerDevId) : peerDevId_(peerDevId)
    {
        audioParam_.comParam.sampleRate = AudioSampleRate::SAMPLE_RATE_8000;
        audioParam_.comParam.channelMask = AudioChannel::MONO;
        audioParam_.comParam.bitFormat = AudioSampleFormat::SAMPLE_U8;
        audioParam_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    }
    ~AudioDecodeTransport() override = default;
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

    void OnSessionOpened() override;
    void OnSessionClosed() override;
    void OnDataReceived(const std::shared_ptr<AudioData> &data) override;
    void OnEventReceived(const AudioEvent &event) override;

    void OnAudioDataDone(const std::shared_ptr<AudioData> &outputData) override;
    void OnStateNotify(const AudioEvent &event) override;

private:
    int32_t InitAudioDecodeTransport(const AudioParam &localParam, const AudioParam &remoteParam,
        const PortCapType capType);
    int32_t RegisterChannelListener(const PortCapType capType);
    int32_t RegisterProcessorListener(const AudioParam &localParam, const AudioParam &remoteParam);

private:
    static constexpr size_t DATA_QUEUE_MAX_SIZE = 10;
    static constexpr size_t SLEEP_TIME = 20000;

    std::weak_ptr<IAudioDataTransCallback> dataTransCallback_;
    std::shared_ptr<IAudioChannel> audioChannel_ = nullptr;
    std::shared_ptr<IAudioProcessor> processor_ = nullptr;
    std::shared_ptr<AudioTransportContext> context_ = nullptr;

    std::mutex dataQueueMtx_;
    std::queue<std::shared_ptr<AudioData>> dataQueue_;
    std::string peerDevId_;
    AudioParam audioParam_;
    PortCapType capType_ = CAP_UNKNOWN;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // AUDIO_DECODE_TRANSPORT_H
