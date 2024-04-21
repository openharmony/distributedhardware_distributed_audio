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

#ifndef OHOS_DSPEAKER_DEV_H
#define OHOS_DSPEAKER_DEV_H

#include <condition_variable>
#include <set>
#include <thread>
#include "cJSON.h"

#include "audio_param.h"
#include "ashmem.h"
#include "av_sender_engine_transport.h"
#include "daudio_constants.h"
#include "daudio_hdi_handler.h"
#include "daudio_io_dev.h"
#include "iaudio_event_callback.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DSpeakerDev : public DAudioIoDev,
    public IAudioDataTransCallback,
    public AVSenderTransportCallback,
    public std::enable_shared_from_this<DSpeakerDev> {
public:
    DSpeakerDev(const std::string &devId, std::shared_ptr<IAudioEventCallback> callback)
        : DAudioIoDev(devId), audioEventCallback_(callback) {};
    ~DSpeakerDev() override = default;

    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;

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

    int32_t OnStateChange(const AudioEventType type) override;
    int32_t OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData) override;

    int32_t SetUp() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    bool IsOpened() override;
    int32_t Pause() override;
    int32_t Restart() override;
    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override;

    AudioParam GetAudioParam() const override;
    int32_t NotifyHdfAudioEvent(const AudioEvent &event, const int32_t portId) override;

private:
    void EnqueueThread();

private:
    static constexpr const char* ENQUEUE_THREAD = "spkEnqueueTh";
    const std::string SPK_DEV_FILENAME = DUMP_FILE_PATH + "/source_spk_write_to_trans.pcm";
    const std::string SPK_LOWLATENCY_FILENAME = DUMP_FILE_PATH + "/source_spk_read_from_ashmem.pcm";

    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::mutex channelWaitMutex_;
    std::condition_variable channelWaitCond_;
    std::atomic<bool> isTransReady_ = false;
    std::atomic<bool> isOpened_ = false;
    std::atomic<bool> dumpFlag_ = false;
    int32_t curPort_ = 0;
    std::shared_ptr<IAudioDataTransport> speakerTrans_ = nullptr;

    // Speaker render parameters
    AudioParamHDF paramHDF_;
    AudioParam param_;

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
    int64_t lastwriteStartTime_ = 0;
    int32_t dhId_ = -1;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_DSPEAKER_DEV_H