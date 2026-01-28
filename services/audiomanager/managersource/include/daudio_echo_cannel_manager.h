/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_ECHO_CANNEL_MANAGER_H
#define OHOS_DAUDIO_ECHO_CANNEL_MANAGER_H

#include <queue>

#include "dhfwk_single_instance.h"

#include "audio_capturer.h"
#include "audio_info.h"
#include "aec_effector.h"
#include "iaudio_datatrans_callback.h"

#include "audio_data.h"
#include "audio_param.h"
#include "daudio_util.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioEchoCannelManager : public AudioStandard::AudioCapturerReadCallback,
    public std::enable_shared_from_this<DAudioEchoCannelManager> {
public:
    DAudioEchoCannelManager();
    ~DAudioEchoCannelManager();

    int32_t SetUp(const AudioCommonParam param,
        const std::shared_ptr<IAudioDataTransCallback> &callback);
    int32_t Start();
    int32_t Stop();
    int32_t Release();

    int32_t OnMicDataReceived(const std::shared_ptr<AudioData> &pipeInData);

private:
    void OnReadData(size_t length) override;
    void AecProcessData();
    void CircuitStart();
    int32_t ProcessMicData(const std::shared_ptr<AudioData> &pipeInData,
        std::shared_ptr<AudioData> &micOutData);
    
    int32_t AudioCaptureSetUp();
    int32_t AudioCaptureStart();
    int32_t AudioCaptureStop();
    int32_t AudioCaptureRelease();

    int32_t LoadAecProcessor();
    void UnLoadAecProcessor();
    int32_t InitAecProcessor();
    int32_t StartAecProcessor();
    int32_t StopAecProcessor();
    int32_t ReleaseAecProcessor();

private:
    const std::string DUMP_DAUDIO_AEC_REFERENCE_FILENAME = "dump_aec_reference_signal.pcm";
    const std::string DUMP_DAUDIO_AEC_RECORD_FILENAME = "dump_aec_record_signal.pcm";
    const std::string DUMP_DAUDIO_AEC_CIRCUIT_FILENAME = "dump_aec_circuit.pcm";
    const std::string DUMP_DAUDIO_AEC_AFTER_PROCESS_FILENAME = "dump_aec_after_process.pcm";

    std::unique_ptr<AudioStandard::AudioCapturer> audioCapturer_ = nullptr;
    std::atomic<bool> isAecRunning_ = false;
    std::thread aecProcessThread_;
    static constexpr const char* AECTHREADNAME = "AecProcessThread";
    std::atomic<bool> isCircuitStartRunning_ = false;
    std::thread circuitStartThread_;

    std::shared_ptr<IAudioDataTransCallback> devCallback_;
    void *aecHandler_ = nullptr;
    AecEffector *aecProcessor_ = nullptr;
    constexpr static size_t COND_WAIT_TIME_MS = 10;
    constexpr static size_t WAIT_MIC_DATA_TIME_US = 5000;
    constexpr static size_t REF_QUEUE_MAX_SIZE = 4;
    std::queue<std::shared_ptr<AudioData>> refDataQueue_;
    std::queue<std::shared_ptr<AudioData>> outDataQueue_;
    std::mutex refQueueMtx_;
    std::mutex outQueueMtx_;
    std::condition_variable refQueueCond_;
    std::atomic<bool> isStarted = false;
    FILE *dumpFileRef_ = nullptr;
    FILE *dumpFileRec_ = nullptr;
    FILE *dumpFileAft_ = nullptr;
    FILE *dumpFileCir_ = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_DMIC_DEV_H
