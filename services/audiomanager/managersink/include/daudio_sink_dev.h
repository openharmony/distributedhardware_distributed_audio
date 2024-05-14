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
#include "cJSON.h"

#include "event_handler.h"

#include "daudio_sink_dev_ctrl_mgr.h"
#include "dmic_client.h"
#include "dspeaker_client.h"
#include "iaudio_event_callback.h"
#include "imic_client.h"
#include "ispk_client.h"
#include "i_av_engine_provider.h"
#include "i_av_receiver_engine_callback.h"
#include "idaudio_sink_ipc_callback.h"

namespace OHOS {
namespace DistributedHardware {
enum class ChannelState {
    SPK_CONTROL_OPENED,
    MIC_CONTROL_OPENED,
    UNKNOWN,
};

class DAudioSinkDev : public IAudioEventCallback, public std::enable_shared_from_this<DAudioSinkDev> {
public:
    explicit DAudioSinkDev(const std::string &networkId, const sptr<IDAudioSinkIpcCallback> &sinkCallback);
    ~DAudioSinkDev() override;

    int32_t AwakeAudioDev();
    void SleepAudioDev();
    void NotifyEvent(const AudioEvent &audioEvent) override;
    int32_t InitAVTransEngines(const ChannelState channelState, IAVEngineProvider *providerPtr);
    int32_t PauseDistributedHardware(const std::string &networkId);
    int32_t ResumeDistributedHardware(const std::string &networkId);
    int32_t StopDistributedHardware(const std::string &networkId);
    void JudgeDeviceStatus();
    void SetDevLevelStatus(bool checkStatus);

private:
    int32_t TaskOpenDSpeaker(const std::string &args);
    int32_t TaskCloseDSpeaker(const std::string &args);
    int32_t TaskStartRender(const std::string &args);
    int32_t TaskOpenDMic(const std::string &args);
    int32_t TaskCloseDMic(const std::string &args);
    int32_t TaskSetParameter(const std::string &args);
    int32_t TaskVolumeChange(const std::string &args);
    int32_t TaskFocusChange(const std::string &args);
    int32_t TaskRenderStateChange(const std::string &args);
    int32_t TaskSetVolume(const std::string &args);
    int32_t TaskSetMute(const std::string &args);
    int32_t TaskPlayStatusChange(const std::string &args);
    int32_t TaskDisableDevice(const std::string &args);

    void NotifySourceDev(const AudioEventType type, const std::string dhId, const int32_t result);
    int32_t from_json(const cJSON *j, AudioParam &audioParam);
    int32_t HandleEngineMessage(uint32_t type, std::string content, std::string devId);
    int32_t SendAudioEventToRemote(const AudioEvent &event);
    void PullUpPage();

    int32_t GetParamValue(const cJSON *j, const char* key, int32_t &value);
    int32_t GetCJsonObjectItems(const cJSON *j, AudioParam &audioParam);
    int32_t ParseDhidFromEvent(std::string args);
    int32_t ParseResultFromEvent(std::string args);
    int32_t ConvertString2Int(std::string val);

private:
    std::mutex rpcWaitMutex_;
    std::condition_variable rpcWaitCond_;
    std::string devId_;
    std::string spkDhId_;
    std::string micDhId_;
    std::mutex spkClientMutex_;
    std::map<int32_t, std::shared_ptr<ISpkClient>> spkClientMap_;
    std::mutex micClientMutex_;
    std::map<int32_t, std::shared_ptr<DMicClient>> micClientMap_;
    std::shared_ptr<DAudioSinkDevCtrlMgr> audioCtrlMgr_ = nullptr;
    static constexpr size_t WAIT_HANDLER_IDLE_TIME_US = 10000;
    const std::string SUBTYPE = "mic";
    sptr<IDAudioSinkIpcCallback> ipcSinkCallback_ = nullptr;
    std::atomic<bool> isPageStatus_ = false;

    std::atomic<bool> isSpkInUse_ = false;
    std::atomic<bool> isMicInUse_ = false;
    bool isDevLevelStatus_ = false;

    class SinkEventHandler : public AppExecFwk::EventHandler {
    public:
        SinkEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
            const std::shared_ptr<DAudioSinkDev> &dev);
        ~SinkEventHandler() override;
        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;

    private:
        void NotifyCtrlOpened(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyCtrlClosed(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyOpenSpeaker(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyCloseSpeaker(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifySpeakerOpened(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifySpeakerClosed(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyOpenMic(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyCloseMic(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyMicOpened(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyMicClosed(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifySetVolume(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyVolumeChange(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifySetParam(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifySetMute(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyFocusChange(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyRenderStateChange(const AppExecFwk::InnerEvent::Pointer &event);
        void NotifyPlayStatusChange(const AppExecFwk::InnerEvent::Pointer &event);
        int32_t GetEventParam(const AppExecFwk::InnerEvent::Pointer &event, std::string &eventParam);

    private:
        using SinkEventFunc = void (SinkEventHandler::*)(const AppExecFwk::InnerEvent::Pointer &event);
        std::map<uint32_t, SinkEventFunc> mapEventFuncs_;
        std::weak_ptr<DAudioSinkDev> sinkDev_;
    };
    std::shared_ptr<SinkEventHandler> handler_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_DEV_H
