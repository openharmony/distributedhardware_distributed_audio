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

#ifndef OHOS_DAUDIO_SINK_DEV_H
#define OHOS_DAUDIO_SINK_DEV_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <initializer_list>

#include "nlohmann/json.hpp"
#include "daudio_sink_dev_ctrl_manager.h"
#include "dmic_client.h"
#include "dspeaker_client.h"
#include "iaudio_event_callback.h"
#include "imic_client.h"
#include "ispk_client.h"
#include "i_av_engine_provider.h"
#include "i_av_receiver_engine_callback.h"
#include "task_queue.h"

#ifdef DAUDIO_SUPPORT_DIRECT
#include "direct_dmic_client.h"
#include "direct_dspeaker_client.h"
#endif

using json = nlohmann::json;

namespace OHOS {
namespace DistributedHardware {
enum class ChannelState {
    SPK_CONTROL_OPENED,
    MIC_CONTROL_OPENED,
    UNKNOWN,
};

class DAudioSinkDev : public IAudioEventCallback, public std::enable_shared_from_this<DAudioSinkDev> {
public:
    explicit DAudioSinkDev(const std::string &networkId);
    ~DAudioSinkDev() override;

    int32_t AwakeAudioDev();
    void SleepAudioDev();
    void NotifyEvent(const AudioEvent &audioEvent) override;
    int32_t InitAVTransEngines(const ChannelState channelState, IAVEngineProvider *providerPtr);

private:
    int32_t TaskOpenCtrlChannel(const std::string &args);
    int32_t TaskCloseCtrlChannel(const std::string &args);
    int32_t TaskOpenDSpeaker(const std::string &args);
    int32_t TaskCloseDSpeaker(const std::string &args);
    int32_t TaskOpenDMic(const std::string &args);
    int32_t TaskCloseDMic(const std::string &args);
    int32_t TaskSetParameter(const std::string &args);
    int32_t TaskVolumeChange(const std::string &args);
    int32_t TaskFocusChange(const std::string &args);
    int32_t TaskRenderStateChange(const std::string &args);
    int32_t TaskSetVolume(const std::string &args);
    int32_t TaskSetMute(const std::string &args);
    int32_t TaskPlayStatusChange(const std::string &args);
    void OnTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName);

    int32_t NotifyOpenCtrlChannel(const AudioEvent &audioEvent);
    int32_t NotifyCloseCtrlChannel(const AudioEvent &audioEvent);
    int32_t NotifyCtrlOpened(const AudioEvent &audioEvent);
    int32_t NotifyCtrlClosed(const AudioEvent &audioEvent);
    int32_t NotifyOpenSpeaker(const AudioEvent &audioEvent);
    int32_t NotifyCloseSpeaker(const AudioEvent &audioEvent);
    int32_t NotifySpeakerOpened(const AudioEvent &audioEvent);
    int32_t NotifySpeakerClosed(const AudioEvent &audioEvent);
    int32_t NotifyOpenMic(const AudioEvent &audioEvent);
    int32_t NotifyCloseMic(const AudioEvent &audioEvent);
    int32_t NotifyMicOpened(const AudioEvent &audioEvent);
    int32_t NotifyMicClosed(const AudioEvent &audioEvent);
    int32_t NotifySetVolume(const AudioEvent &audioEvent);
    int32_t NotifyVolumeChange(const AudioEvent &audioEvent);
    int32_t NotifySetParam(const AudioEvent &audioEvent);
    int32_t NotifySetMute(const AudioEvent &audioEvent);
    int32_t NotifyFocusChange(const AudioEvent &audioEvent);
    int32_t NotifyRenderStateChange(const AudioEvent &audioEvent);
    int32_t NotifyPlayStatusChange(const AudioEvent &audioEvent);
    void NotifySourceDev(const AudioEventType type, const std::string dhId, const int32_t result);
    int32_t from_json(const json &j, AudioParam &audioParam);
    int32_t HandleEngineMessage(uint32_t type, std::string content, std::string devId);
    int32_t SendAudioEventToRemote(const AudioEvent &event);
    void JudgeDeviceStatus();

private:
    std::mutex taskQueueMutex_;
    std::mutex rpcWaitMutex_;
    std::condition_variable rpcWaitCond_;
    std::string devId_;
    std::string spkDhId_;
    std::string micDhId_;
    std::shared_ptr<TaskQueue> taskQueue_ = nullptr;
    std::shared_ptr<ISpkClient> speakerClient_ = nullptr;
    std::shared_ptr<IMicClient> micClient_ = nullptr;
    std::shared_ptr<DAudioSinkDevCtrlMgr> audioCtrlMgr_ = nullptr;

    using DAudioSinkDevFunc = int32_t (DAudioSinkDev::*)(const AudioEvent &audioEvent);
    std::map<AudioEventType, DAudioSinkDevFunc> memberFuncMap_;
    bool engineFlag_ = false;
    std::atomic<bool> isSpkInUse_ = false;
    std::atomic<bool> isMicInUse_ = false;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_DEV_H
