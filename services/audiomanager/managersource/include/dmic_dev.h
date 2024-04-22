/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DMIC_DEV_H
#define OHOS_DMIC_DEV_H

#include <queue>
#include <set>
#include <thread>
#include "cJSON.h"

#include "audio_param.h"
#include "audio_status.h"
#include "av_receiver_engine_transport.h"
#include "ashmem.h"
#include "daudio_constants.h"
#include "daudio_hdi_handler.h"
#include "daudio_io_dev.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_event_callback.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DMicDev : public DAudioIoDev,
    public IAudioDataTransCallback,
    public AVReceiverTransportCallback,
    public std::enable_shared_from_this<DMicDev> {
public:
    DMicDev(const std::string &devId, std::shared_ptr<IAudioEventCallback> callback)
        : DAudioIoDev(devId), audioEventCallback_(callback) {};
    ~DMicDev() override = default;

    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
    void OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData) override;

    int32_t InitReceiverEngine(IAVEngineProvider *providerPtr) override;
    int32_t InitSenderEngine(IAVEngineProvider *providerPtr) override;

    int32_t EnableDevice(const int32_t dhId, const std::string &capability) override;
    int32_t DisableDevice(const int32_t dhId) override;
    int32_t CreateStream(const int32_t streamId) override;
    int32_t DestroyStream(const int32_t streamId) override;
    int32_t SetParameters(const int32_t streamId, const AudioParamHDF &param) override;
    int32_t WriteStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data) override;
    int32_t ReadStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data) override;
    int32_t NotifyEvent(const int32_t streamId, const AudioEvent &event) override;
    int32_t ReadMmapPosition(const int32_t streamId, uint64_t &frames, CurrentTimeHDF &time) override;
    int32_t RefreshAshmemInfo(const int32_t streamId,
        int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans) override;

    int32_t MmapStart() override;
    int32_t MmapStop() override;

    int32_t SetUp() override;
    int32_t Start() override;
    int32_t Pause() override;
    int32_t Restart() override;
    int32_t Stop() override;
    int32_t Release() override;
    bool IsOpened() override;
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override;

    AudioParam GetAudioParam() const override;
    int32_t NotifyHdfAudioEvent(const AudioEvent &event, const int32_t portId) override;

    int32_t OnStateChange(const AudioEventType type) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;

private:
    void EnqueueThread();
    void FillJitterQueue();

private:
    static constexpr uint8_t CHANNEL_WAIT_SECONDS = 5;
    static constexpr size_t DATA_QUEUE_MAX_SIZE = 10;
    static constexpr size_t DATA_QUEUE_HALF_SIZE = DATA_QUEUE_MAX_SIZE >> 1U;
    static constexpr size_t LOW_LATENCY_DATA_QUEUE_MAX_SIZE = 30;
    static constexpr size_t LOW_LATENCY_DATA_QUEUE_HALF_SIZE = 10;
    static constexpr size_t LOW_LATENCY_JITTER_TIME_MS = 50;
    static constexpr uint32_t MMAP_WAIT_FRAME_US = 5000;
    static constexpr const char* ENQUEUE_THREAD = "micEnqueueTh";
    const std::string MIC_DEV_FILENAME = DUMP_FILE_PATH + "/source_mic_read_from_trans.pcm";
    const std::string MIC_LOWLATENCY_FILENAME = DUMP_FILE_PATH + "/source_mic_write_to_ashmem.pcm";

    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::mutex dataQueueMtx_;
    std::mutex channelWaitMutex_;
    std::condition_variable channelWaitCond_;
    int32_t curPort_ = 0;
    std::atomic<bool> isTransReady_ = false;
    std::atomic<bool> isOpened_ = false;
    std::atomic<bool> dumpFlag_ = false;
    std::shared_ptr<IAudioDataTransport> micTrans_ = nullptr;
    std::queue<std::shared_ptr<AudioData>> dataQueue_;
    AudioStatus curStatus_ = AudioStatus::STATUS_IDLE;
    // Mic capture parameters
    AudioParamHDF paramHDF_;
    AudioParam param_;

    uint32_t insertFrameCnt_ = 0;
    std::atomic<bool> isExistedEmpty_ = false;
    size_t dataQueSize_ = 0;
    sptr<Ashmem> ashmem_ = nullptr;
    std::atomic<bool> isEnqueueRunning_ = false;
    int32_t ashmemLength_ = -1;
    int32_t lengthPerTrans_ = -1;
    int32_t writeIndex_ = -1;
    int64_t frameIndex_ = 0;
    int64_t startTime_ = 0;
    uint64_t writeNum_ = 0;
    int64_t writeTvSec_ = 0;
    int64_t writeTvNSec_ = 0;
    int64_t lastReadStartTime_ = 0;
    std::thread enqueueDataThread_;
    std::mutex writeAshmemMutex_;
    std::condition_variable dataQueueCond_;
    int32_t dhId_ = -1;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_DMIC_DEV_H
