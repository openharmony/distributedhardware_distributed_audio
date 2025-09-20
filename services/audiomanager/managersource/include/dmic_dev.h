/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <deque>
#include <set>
#include <thread>
#include "cJSON.h"

#include "audio_param.h"
#include "audio_status.h"
#include "av_receiver_engine_transport.h"
#include "ashmem.h"
#include "daudio_constants.h"
#ifdef ECHO_CANNEL_ENABLE
#include "daudio_echo_cannel_manager.h"
#endif
#include "daudio_hdi_handler.h"
#include "daudio_io_dev.h"
#include "daudio_source_ctrl_trans.h"
#include "daudio_ringbuffer.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_event_callback.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DMicDev : public DAudioIoDev,
    public IAudioDataTransCallback,
    public IAudioCtrlTransCallback,
    public AVReceiverTransportCallback,
    public std::enable_shared_from_this<DMicDev> {
public:
    DMicDev(const std::string &devId, std::shared_ptr<IAudioEventCallback> callback)
        : DAudioIoDev(devId), audioEventCallback_(callback) {};
    ~DMicDev() override = default;

    void OnEngineTransEvent(const AVTransEvent &event) override;
    void OnEngineTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
    void OnEngineTransDataAvailable(const std::shared_ptr<AudioData> &audioData) override;

    void OnCtrlTransEvent(const AVTransEvent &event) override;
    void OnCtrlTransMessage(const std::shared_ptr<AVTransMessage> &message) override;

    int32_t InitReceiverEngine(IAVEngineProvider *providerPtr) override;
    int32_t InitSenderEngine(IAVEngineProvider *providerPtr) override;
    int32_t InitCtrlTrans() override;

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
    int32_t UpdateWorkModeParam(const std::string &devId, const std::string &dhId,
        const AudioAsyncParam &param) override;
    int32_t AVsyncRefreshAshmem(int32_t fd, int32_t ashmemLength);
    void AVsyncDeintAshmem();

private:
    void EnqueueThread();
    void FillJitterQueue();
    void ReadFromRingbuffer();
    void SendToProcess(const std::shared_ptr<AudioData> &audioData);
    void GetCodecCaps(const std::string &capability);
    void AddToVec(std::vector<AudioCodecType> &container, const AudioCodecType value);
    bool IsMimeSupported(const AudioCodecType coder);
    int32_t GetAudioDataFromQueue(std::shared_ptr<AudioData> &data);
    int32_t WriteTimeStampToAVsync(const int64_t timePts);
    int32_t ReadTimeStampFromAVsync(int64_t &timePts);
    uint32_t GetQueSize();
    bool IsAVsync();
    int32_t AVsyncMacthScene(std::shared_ptr<AudioData> &data);

private:
    static constexpr uint8_t CHANNEL_WAIT_SECONDS = 5;
    static constexpr uint8_t RINGBUFFER_WAIT_SECONDS = 5;
    static constexpr uint8_t SCENE_WAIT_SECONDS = 5;
    static constexpr size_t DATA_QUEUE_MAX_SIZE = 10;
    static constexpr size_t DATA_QUEUE_HALF_SIZE = DATA_QUEUE_MAX_SIZE >> 1U;
    static constexpr size_t DATA_QUEUE_BROADCAST_SIZE = 20;
    static constexpr size_t DATA_QUEUE_VIDEOCALL_SIZE = 20;
    static constexpr int64_t TIMESTAMP_COMPENSATION = 0;
    static constexpr uint32_t LOW_LATENCY_JITTER_MAX_TIME_MS = 150;
    static constexpr uint32_t LOW_LATENCY_JITTER_TIME_MS = 50;
    static constexpr uint8_t MMAP_NORMAL_PERIOD = 5;
    static constexpr uint8_t MMAP_VOIP_PERIOD = 20;
    static constexpr uint32_t MMAP_WAIT_FRAME_US = 5000;
    static constexpr uint32_t DADUIO_TIME_DIFF_MAX = 5;
    constexpr static int64_t ONE_FRAME_COMPENSATION = 20000;
    static constexpr const char* ENQUEUE_THREAD = "micEnqueueTh";
    const std::string DUMP_DAUDIO_MIC_READ_FROM_BUF_NAME = "dump_source_mic_read_from_trans.pcm";
    const std::string DUMP_DAUDIO_LOWLATENCY_MIC_FROM_BUF_NAME = "dump_source_mic_write_to_ashmem.pcm";
    const int32_t ASHMEM_MAX_LEN = 2 * 4096;

    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::mutex dataQueueMtx_;
    std::mutex channelWaitMutex_;
    std::condition_variable channelWaitCond_;
    int32_t curPort_ = 0;
    int32_t streamId_ = 100;
    std::atomic<bool> isTransReady_ = false;
    std::atomic<bool> isOpened_ = false;
    std::shared_ptr<IAudioDataTransport> micTrans_ = nullptr;
    std::shared_ptr<IAudioCtrlTransport> micCtrlTrans_ = nullptr;
#ifdef ECHO_CANNEL_ENABLE
    std::shared_ptr<DAudioEchoCannelManager> echoManager_ = nullptr;
#endif
    std::deque<std::shared_ptr<AudioData>> dataQueue_;
    AudioStatus curStatus_ = AudioStatus::STATUS_IDLE;
    // Mic capture parameters
    AudioParamHDF paramHDF_;
    AudioParam param_;

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
    bool echoCannelOn_ = false;
    FILE *dumpFileCommn_ = nullptr;
    FILE *dumpFileFast_ = nullptr;
    uint32_t lowLatencyHalfSize_ = 0;
    uint32_t lowLatencyMaxfSize_ = 0;
    std::unique_ptr<DaudioRingBuffer> ringBuffer_ = nullptr;
    uint8_t *frameData_ = nullptr;
    int32_t frameSize_ = 0;
    std::thread ringbufferThread_;
    std::atomic<bool> isRingbufferOn_ = false;
    std::mutex ringbufferMutex_;
    std::vector<AudioCodecType> codec_;

    uint64_t frameInIndex_ = 0;
    uint64_t frameOutIndex_ = 0;
    uint64_t framnum_ = 0;
    uint64_t indexFlag_ = 15;
    uint64_t frameOutIndexFlag_ = 16;
    std::map<uint64_t, int64_t> ptsMap_;
    std::mutex ptsMutex_;
    AudioAsyncParam avSyncParam_ {};
    std::mutex avSyncMutex_;
    uint32_t scene_ = DATA_QUEUE_HALF_SIZE;
    std::atomic<bool> isStartStatus_ = true;
    sptr<Ashmem> avsyncAshmem_ = nullptr;
    constexpr static int64_t TIME_CONVERSION_NTOU = 1000;
    constexpr static int64_t TIME_CONVERSION_STOU = 1000000;
    struct AVsyncShareData {
        volatile int lock = 1;
        uint64_t audio_current_pts = 0;
        uint64_t audio_update_clock = 0;
        float audio_speed = 1.0f;
        uint64_t video_current_pts = 0;
        uint64_t video_update_clock = 0;
        float video_speed = 1.0f;
        uint64_t sync_strategy = 1;
        bool reset = false;
    };
    std::shared_ptr<AVsyncShareData> avsyncShareData_ = nullptr;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_DMIC_DEV_H
