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

#ifndef OHOS_DMIC_CLIENT_H
#define OHOS_DMIC_CLIENT_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <queue>
#include <sstream>
#include <string>
#include <thread>

#include "audio_capturer.h"
#include "audio_info.h"

#include "audio_data.h"
#include "audio_event.h"
#include "audio_param.h"
#include "audio_status.h"
#include "av_sender_engine_transport.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_event_callback.h"
#include "imic_client.h"

namespace OHOS {
namespace DistributedHardware {
class DMicClient : public IAudioDataTransCallback,
    public AudioStandard::AudioCapturerReadCallback,
    public IMicClient, public AVSenderTransportCallback,
    public std::enable_shared_from_this<DMicClient> {
public:
    DMicClient(const std::string &devId, const int32_t dhId, const std::shared_ptr<IAudioEventCallback> &callback)
        : devId_(devId), dhId_(dhId), eventCallback_(callback) {};
    ~DMicClient() override;
    int32_t OnStateChange(const AudioEventType type) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;
    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
    int32_t InitSenderEngine(IAVEngineProvider *providerPtr) override;
    int32_t SetUp(const AudioParam &param) override;
    int32_t Release() override;
    int32_t StartCapture() override;
    int32_t StopCapture() override;
    void SetAttrs(const std::string &devId, const std::shared_ptr<IAudioEventCallback> &callback) override;
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override;

    void OnReadData(size_t length) override;
    int32_t PauseCapture();
    int32_t ResumeCapture();
private:
    void CaptureThreadRunning();

    int32_t AudioFwkClientSetUp();
    int32_t TransSetUp();
    void AudioFwkCaptureData();
private:
    constexpr static uint8_t CHANNEL_WAIT_SECONDS = 5;
    static constexpr const char* CAPTURETHREAD = "captureThread";
    const std::string MIC_CLIENT_FILENAME = DUMP_FILE_PATH + "/sink_mic_send_to_trans.pcm";

    std::string devId_;
    int32_t dhId_;
    std::thread captureDataThread_;
    AudioParam audioParam_;
    std::atomic<bool> isBlocking_ = false;
    std::atomic<bool> isCaptureReady_ = false;
    std::mutex devMtx_;
    AudioStatus clientStatus_ = AudioStatus::STATUS_IDLE;

    std::weak_ptr<IAudioEventCallback> eventCallback_;
    std::unique_ptr<AudioStandard::AudioCapturer> audioCapturer_ = nullptr;
    std::shared_ptr<IAudioDataTransport> micTrans_ = nullptr;
    int64_t lastCaptureStartTime_ = 0;
    int64_t lastTransStartTime_ = 0;
    std::atomic<bool> isPauseStatus_ = false;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DMIC_CLIENT_H
