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

#ifndef OHOS_DSPEAKER_DEV_H
#define OHOS_DSPEAKER_DEV_H

#include <condition_variable>
#include <set>
#include <thread>
#include "nlohmann/json.hpp"

#include "audio_param.h"
#include "ashmem.h"
#include "av_sender_engine_transport.h"
#include "daudio_hdi_handler.h"
#include "iaudio_event_callback.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "idaudio_hdi_callback.h"

using json = nlohmann::json;

namespace OHOS {
namespace DistributedHardware {
class DSpeakerDev : public IDAudioHdiCallback,
    public IAudioDataTransCallback,
    public AVSenderTransportCallback,
    public std::enable_shared_from_this<DSpeakerDev> {
public:
    DSpeakerDev(const std::string &devId, std::shared_ptr<IAudioEventCallback> callback)
        : devId_(devId), audioEventCallback_(callback) {};
    ~DSpeakerDev() override = default;
    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
    int32_t InitSenderEngine(IAVEngineProvider *providerPtr);

    int32_t EnableDSpeaker(const int32_t dhId, const std::string& capability);
    int32_t DisableDSpeaker(const int32_t dhId);

    int32_t OpenDevice(const std::string &devId, const int32_t dhId) override;
    int32_t CloseDevice(const std::string &devId, const int32_t dhId) override;
    int32_t SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param) override;
    int32_t WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override;
    int32_t ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override;
    int32_t NotifyEvent(const std::string &devId, const int32_t dhId, const AudioEvent &event) override;
    int32_t ReadMmapPosition(const std::string &devId, const int32_t dhId,
        uint64_t &frames, CurrentTimeHDF &time) override;
    int32_t RefreshAshmemInfo(const std::string &devId, const int32_t dhId,
        int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans) override;
    int32_t MmapStart();
    int32_t MmapStop();

    int32_t OnStateChange(const AudioEventType type) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;

    int32_t SetUp();
    int32_t Start();
    int32_t Stop();
    int32_t Release();
    bool IsOpened();
    int32_t Pause();
    int32_t Restart();
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId);

    AudioParam GetAudioParam() const;
    int32_t NotifyHdfAudioEvent(const AudioEvent &event);

private:
    int32_t EnableDevice(const int32_t dhId, const std::string &capability);
    int32_t DisableDevice(const int32_t dhId);
    void EnqueueThread();

private:
    static constexpr const char* ENQUEUE_THREAD = "spkEnqueueTh";

    std::string devId_;
    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::mutex channelWaitMutex_;
    std::condition_variable channelWaitCond_;
    std::atomic<bool> isTransReady_ = false;
    std::atomic<bool> isOpened_ = false;
    int32_t curPort_ = 0;
    std::shared_ptr<IAudioDataTransport> speakerTrans_ = nullptr;
    std::set<int32_t> enabledPorts_;

    // Speaker render parameters
    AudioParamHDF paramHDF_;
    AudioParam param_;

    uint32_t timeInterval_ = 5;
    sptr<Ashmem> ashmem_ = nullptr;
    std::atomic<bool> isEnqueueRunning_ = false;
    int32_t ashmemLength_ = -1;
    int32_t lengthPerTrans_ = -1;
    int32_t readIndex_ = -1;
    int64_t frameIndex_ = 0;
    int64_t startTime_ = 0;
    uint64_t readNum_ = 0;
    int64_t readTvSec_ = 0;
    int64_t readTvNSec_ = 0;
    std::thread enqueueDataThread_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_DSPEAKER_DEV_H