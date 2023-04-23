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

#ifndef OHOS_DMIC_DEV_H
#define OHOS_DMIC_DEV_H

#include <queue>
#include <set>
#include <thread>
#include "nlohmann/json.hpp"

#include "audio_param.h"
#include "audio_status.h"
#include "ashmem.h"
#include "daudio_hdi_handler.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_data_transport.h"
#include "iaudio_event_callback.h"
#include "idaudio_hdi_callback.h"

using json = nlohmann::json;

namespace OHOS {
namespace DistributedHardware {
class DMicDev : public IDAudioHdiCallback,
    public IAudioDataTransCallback,
    public std::enable_shared_from_this<DMicDev> {
public:
    DMicDev(const std::string &devId, std::shared_ptr<IAudioEventCallback> callback)
        : devId_(devId), audioEventCallback_(callback) {};
    ~DMicDev() override = default;

    int32_t EnableDMic(const int32_t dhId, const std::string &capability);
    int32_t DisableDMic(const int32_t dhId);

    int32_t OpenDevice(const std::string &devId, const int32_t dhId) override;
    int32_t CloseDevice(const std::string &devId, const int32_t dhId) override;
    int32_t SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param) override;
    int32_t WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override;
    int32_t ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override;
    int32_t NotifyEvent(const std::string &devId, const int32_t dhId, const AudioEvent &event) override;
    int32_t ReadMmapPosition(const std::string &devId, const int32_t dhId,
        uint64_t frames, CurrentTimeHDF &time) override;
    int32_t RefreshAshmemInfo(const std::string &devId, const int32_t dhId,
        int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans) override;
    int32_t MmapStart();
    int32_t MmapStop();

    int32_t SetUp();
    int32_t Start();
    int32_t Stop();
    int32_t Release();
    bool IsOpened();

    AudioParam GetAudioParam() const;
    int32_t NotifyHdfAudioEvent(const AudioEvent &event);
    int32_t OnStateChange(const AudioEventType type) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;

private:
    int32_t EnableDevice(const int32_t dhId, const std::string &capability);
    int32_t DisableDevice(const int32_t dhId);
    void EnqueueThread();

private:
    static constexpr uint8_t CHANNEL_WAIT_SECONDS = 5;
    static constexpr size_t DATA_QUEUE_MAX_SIZE = 10;
    static constexpr size_t DATA_QUEUE_HALF_SIZE = DATA_QUEUE_MAX_SIZE >> 1U;
    static constexpr size_t LOW_LATENCY_DATA_QUEUE_MAX_SIZE = 40;
    static constexpr size_t LOW_LATENCY_DATA_QUEUE_HALF_SIZE = LOW_LATENCY_DATA_QUEUE_MAX_SIZE >> 1U;
    static constexpr const char* ENQUEUE_THREAD = "micEnqueueTh";

    std::string devId_;
    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::mutex dataQueueMtx_;
    std::mutex channelWaitMutex_;
    std::condition_variable channelWaitCond_;
    int32_t curPort_ = 0;
    std::atomic<bool> isTransReady_ = false;
    std::atomic<bool> isOpened_ = false;
    std::shared_ptr<IAudioDataTransport> micTrans_ = nullptr;
    std::queue<std::shared_ptr<AudioData>> dataQueue_;
    std::set<int32_t> enabledPorts_;
    AudioStatus curStatus_ = AudioStatus::STATUS_IDLE;

    // Mic capture parameters
    AudioParamHDF paramHDF_;
    AudioParam param_;

    uint32_t timeInterval_ = 5;
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
    std::thread enqueueDataThread_;
    std::mutex writeAshmemMutex_;
    std::condition_variable dataQueueCond_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_DMIC_DEV_H