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

#ifndef OHOS_DSPEAKER_CLIENT_H
#define OHOS_DSPEAKER_CLIENT_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <securec.h>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

#include "audio_info.h"
#include "audio_renderer.h"
#include "audio_system_manager.h"

#include "audio_data.h"
#include "audio_status.h"
#include "audio_event.h"
#include "av_receiver_engine_transport.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_event_callback.h"
#include "ispk_client.h"

namespace OHOS {
namespace DistributedHardware {
class DSpeakerClient : public IAudioDataTransCallback,
    public ISpkClient, public AVReceiverTransportCallback,
    public AudioStandard::VolumeKeyEventCallback,
    public AudioStandard::AudioRendererCallback,
    public AudioStandard::AudioRendererWriteCallback,
    public std::enable_shared_from_this<DSpeakerClient> {
public:
    DSpeakerClient(const std::string &devId, const int32_t &dhId, const std::shared_ptr<IAudioEventCallback> &callback)
        : devId_(devId), dhId_(dhId), eventCallback_(callback) {};
    ~DSpeakerClient() override;

    int32_t OnStateChange(const AudioEventType type) override;
    void OnStateChange(const AudioStandard::RendererState state,
        const AudioStandard::StateChangeCmdType __attribute__((unused)) cmdType) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;
    void OnVolumeKeyEvent(AudioStandard::VolumeEvent volumeEvent) override;
    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    int32_t InitReceiverEngine(IAVEngineProvider *providerPtr) override;
    int32_t SetUp(const AudioParam &param) override;
    int32_t Release() override;
    int32_t StartRender() override;
    int32_t StopRender() override;
    int32_t SetMute(const AudioEvent &event) override;
    int32_t SetAudioParameters(const AudioEvent &event) override;
    void PlayStatusChange(const std::string &args) override;
    void SetAttrs(const std::string &devId, const std::shared_ptr<IAudioEventCallback> &callback) override;
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override;

    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
    void OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData) override;

    void OnWriteData(size_t length) override;
private:
    std::string GetVolumeLevel();
    void PlayThreadRunning();
    void Pause();
    void ReStart();
    void FillJitterQueue();
    void FlushJitterQueue();
    int32_t CreateAudioRenderer(const AudioParam &param);

private:
    constexpr static size_t DATA_QUEUE_MAX_SIZE = 12;
    constexpr static size_t REQUEST_DATA_WAIT = 10;
    constexpr static size_t DATA_QUEUE_SIZE = 8;
    constexpr static size_t SLEEP_TIME = 5000;
    static constexpr const char* RENDERTHREAD = "renderThread";
    const std::string SPK_CLIENT_FILENAME = DUMP_FILE_PATH + "/sink_spk_recv_from_trans.pcm";

    std::string devId_;
    const int32_t dhId_;
    std::thread renderDataThread_;
    AudioParam audioParam_;
    std::atomic<bool> isRenderReady_ = false;
    std::mutex dataQueueMtx_;
    std::mutex devMtx_;
    std::queue<std::shared_ptr<AudioData>> dataQueue_;
    std::condition_variable dataQueueCond_;
    AudioStatus clientStatus_ = AudioStatus::STATUS_IDLE;

    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer_ = nullptr;
    std::shared_ptr<IAudioDataTransport> speakerTrans_ = nullptr;
    std::weak_ptr<IAudioEventCallback> eventCallback_;
    int64_t lastPlayStartTime_ = 0;
    int64_t lastReceiveStartTime_ = 0;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DSPEAKER_CLIENT_H
