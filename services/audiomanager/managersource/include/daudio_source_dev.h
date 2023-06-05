/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_SOURCE_DEV_H
#define OHOS_DAUDIO_SOURCE_DEV_H

#include <mutex>
#include <initializer_list>
#include "nlohmann/json.hpp"

#include "audio_event.h"
#include "daudio_source_dev_ctrl_manager.h"
#include "daudio_source_mgr_callback.h"
#include "dmic_dev.h"
#include "dspeaker_dev.h"
#include "iaudio_event_callback.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_data_transport.h"
#include "idaudio_ipc_callback.h"
#include "idaudio_hdi_callback.h"
#include "task_queue.h"

using json = nlohmann::json;

namespace OHOS {
namespace DistributedHardware {
class DAudioSourceDev : public IAudioEventCallback, public std::enable_shared_from_this<DAudioSourceDev> {
public:
    DAudioSourceDev(const std::string &devId, const std::shared_ptr<DAudioSourceMgrCallback> &callback);
    ~DAudioSourceDev() override = default;

    int32_t AwakeAudioDev();
    void SleepAudioDev();

    int32_t EnableDAudio(const std::string &dhId, const std::string &attrs);
    int32_t DisableDAudio(const std::string &dhId);
    void NotifyEvent(const AudioEvent &event) override;

private:
    int32_t EnableDSpeaker(const int32_t dhId, const std::string &attrs);
    int32_t EnableDMic(const int32_t dhId, const std::string &attrs);
    int32_t DisableDSpeaker(const int32_t dhId);
    int32_t DisableDMic(const int32_t dhId);

    int32_t TaskEnableDAudio(const std::string &args);
    int32_t TaskDisableDAudio(const std::string &args);
    int32_t TaskOpenCtrlChannel(const std::string &args);
    int32_t TaskCloseCtrlChannel(const std::string &args);
    int32_t TaskOpenDSpeaker(const std::string &args);
    int32_t TaskCloseDSpeaker(const std::string &args);
    int32_t TaskOpenDMic(const std::string &args);
    int32_t TaskCloseDMic(const std::string &args);
    int32_t TaskSetVolume(const std::string &args);
    int32_t TaskChangeVolume(const std::string &args);
    int32_t TaskChangeFocus(const std::string &args);
    int32_t TaskChangeRenderState(const std::string &args);
    int32_t TaskPlayStatusChange(const std::string &args);
    int32_t TaskSpkMmapStart(const std::string &args);
    int32_t TaskSpkMmapStop(const std::string &args);
    int32_t TaskMicMmapStart(const std::string &args);
    int32_t TaskMicMmapStop(const std::string &args);

    void OnDisableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName);
    void OnEnableTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName);
    void OnTaskResult(int32_t resultCode, const std::string &result, const std::string &funcName);

    int32_t HandleOpenDSpeaker(const AudioEvent &event);
    int32_t HandleCloseDSpeaker(const AudioEvent &event);
    int32_t HandleDSpeakerOpened(const AudioEvent &event);
    int32_t HandleDSpeakerClosed(const AudioEvent &event);
    int32_t HandleOpenDMic(const AudioEvent &event);
    int32_t HandleCloseDMic(const AudioEvent &event);
    int32_t HandleDMicOpened(const AudioEvent &event);
    int32_t HandleDMicClosed(const AudioEvent &event);
    int32_t HandleOpenCtrlTrans(const AudioEvent &event);
    int32_t HandleCloseCtrlTrans(const AudioEvent &event);
    int32_t HandleCtrlTransClosed(const AudioEvent &event);
    int32_t HandleNotifyRPC(const AudioEvent &event);
    int32_t WaitForRPC(const AudioEventType type);
    int32_t HandleVolumeSet(const AudioEvent &event);
    int32_t HandleVolumeChange(const AudioEvent &event);
    int32_t HandleFocusChange(const AudioEvent &event);
    int32_t HandleRenderStateChange(const AudioEvent &event);
    int32_t HandlePlayStatusChange(const AudioEvent &event);
    int32_t HandleSpkMmapStart(const AudioEvent &event);
    int32_t HandleSpkMmapStop(const AudioEvent &event);
    int32_t HandleMicMmapStart(const AudioEvent &event);
    int32_t HandleMicMmapStop(const AudioEvent &event);

    int32_t NotifySinkDev(const AudioEventType type, const json Param, const std::string dhId);
    int32_t NotifyHDF(const AudioEventType type, const std::string result);
    int32_t OpenCtrlTrans(const AudioEvent &event);
    int32_t CloseCtrlTrans(const AudioEvent &event, bool isSpk);
    AudioEventType getEventTypeFromArgs(const std::string &args);
    void to_json(json &j, const AudioParam &param);

private:
    static constexpr uint8_t RPC_WAIT_SECONDS = 2;
    static constexpr uint8_t TASK_QUEUE_CAPACITY = 20;
    static constexpr uint8_t EVENT_NOTIFY_OPEN_SPK = 0x01;
    static constexpr uint8_t EVENT_NOTIFY_CLOSE_SPK = 0x02;
    static constexpr uint8_t EVENT_NOTIFY_OPEN_MIC = 0x04;
    static constexpr uint8_t EVENT_NOTIFY_CLOSE_MIC = 0x08;
    static constexpr uint8_t EVENT_NOTIFY_OPEN_CTRL = 0x10;
    static constexpr uint8_t EVENT_NOTIFY_CLOSE_CTRL = 0x20;

    std::string devId_;
    std::shared_ptr<DAudioSourceMgrCallback> mgrCallback_;
    std::shared_ptr<TaskQueue> taskQueue_;
    std::shared_ptr<DSpeakerDev> speaker_;
    std::shared_ptr<DMicDev> mic_;

    std::shared_ptr<DAudioSourceDevCtrlMgr> audioCtrlMgr_;
    std::mutex taskQueueMutex_;

    std::mutex rpcWaitMutex_;
    std::condition_variable rpcWaitCond_;
    bool rpcResult_ = false;
    uint8_t rpcNotify_ = 0;

    using DAudioSourceDevFunc = int32_t (DAudioSourceDev::*)(const AudioEvent &audioEvent);
    std::map<AudioEventType, DAudioSourceDevFunc> memberFuncMap_;
    std::map<AudioEventType, uint8_t> eventNotifyMap_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SOURCE_DEV_H