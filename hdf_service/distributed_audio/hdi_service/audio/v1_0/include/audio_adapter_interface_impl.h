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

#ifndef OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H
#define OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H

#include <condition_variable>
#include <map>
#include <mutex>

#include <v1_0/iaudio_adapter.h>
#include <v1_0/id_audio_manager.h>
#include <v1_0/audio_types.h>

#include "audio_capture_interface_impl.h"
#include "audio_capture_interface_impl_base.h"
#include "audio_render_interface_impl.h"
#include "audio_render_interface_impl_base.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
using OHOS::HDI::DistributedAudio::Audioext::V1_0::DAudioEvent;
using OHOS::HDI::DistributedAudio::Audioext::V1_0::PortOperationMode;
using OHOS::HDI::DistributedAudio::Audioext::V1_0::AudioParameter;
using OHOS::HDI::DistributedAudio::Audioext::V1_0::IDAudioCallback;

typedef enum {
    STATUS_ONLINE = 0,
    STATUS_OFFLINE,
    STATUS_LOAD,
    STATUS_UNLOAD,
    STATUS_CREATE_RENDER,
} AudioAdapterStatus;

typedef enum {
    EVENT_DEV_CLOSED = 0,
    EVENT_OPEN_SPK,
    EVENT_CLOSE_SPK,
    EVENT_OPEN_MIC,
    EVENT_CLOSE_MIC,
} AudioDeviceEvent;

typedef enum {
    EVENT_GET_VOLUME = 1,
    EVENT_GET_MIN_VOLUME = 2,
    EVENT_GET_MAX_VOLUME = 3,
    EVENT_IS_STREAM_MUTE = 4,
} VolumeEventType;

class AudioAdapterInterfaceImpl : public IAudioAdapter {
public:
    explicit AudioAdapterInterfaceImpl(const AudioAdapterDescriptor &desc);
    ~AudioAdapterInterfaceImpl() override;

    int32_t InitAllPorts() override;
    int32_t CreateRender(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        sptr<IAudioRender> &render) override;
    int32_t DestroyRender(const AudioDeviceDescriptor &desc) override;
    int32_t CreateCapture(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        sptr<IAudioCapture> &capture) override;
    int32_t DestroyCapture(const AudioDeviceDescriptor &desc) override;
    int32_t GetPortCapability(const AudioPort &port, AudioPortCapability &capability) override;
    int32_t SetPassthroughMode(const AudioPort &port, AudioPortPassthroughMode mode) override;
    int32_t GetPassthroughMode(const AudioPort &port, AudioPortPassthroughMode &mode) override;
    int32_t GetDeviceStatus(AudioDeviceStatus& status) override;
    int32_t UpdateAudioRoute(const AudioRoute &route, int32_t &routeHandle) override;
    int32_t ReleaseAudioRoute(int32_t routeHandle) override;
    int32_t SetMicMute(bool mute) override;
    int32_t GetMicMute(bool& mute) override;
    int32_t SetVoiceVolume(float volume) override;
    int32_t SetExtraParams(AudioExtParamKey key, const std::string &condition, const std::string &value) override;
    int32_t GetExtraParams(AudioExtParamKey key, const std::string &condition, std::string &value) override;
    int32_t RegExtraParamObserver(const sptr<IAudioCallback> &audioCallback, int8_t cookie) override;

public:
    void SetSpeakerCallback(const sptr<IDAudioCallback> &speakerCallback);
    void SetMicCallback(const sptr<IDAudioCallback> &micCallback);
    AudioAdapterDescriptor GetAdapterDesc();
    std::string GetDeviceCapabilitys(const uint32_t devId);
    int32_t AdapterLoad();
    int32_t AdapterUnload();
    int32_t Notify(const uint32_t devId, const DAudioEvent &event);
    int32_t AddAudioDevice(const uint32_t devId, const std::string &caps);
    int32_t RemoveAudioDevice(const uint32_t devId);
    int32_t OpenRenderDevice(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs);
    int32_t CloseRenderDevice(const AudioDeviceDescriptor &desc);
    int32_t OpenCaptureDevice(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs);
    int32_t CloseCaptureDevice(const AudioDeviceDescriptor &desc);
    uint32_t GetVolumeGroup(const uint32_t devId);
    uint32_t GetInterruptGroup(const uint32_t devId);
    bool IsPortsNoReg();

private:
    int32_t SetAudioVolume(const std::string& condition, const std::string &param);
    int32_t GetAudioVolume(const std::string& condition, std::string &param);
    int32_t HandleFocusChangeEvent(const DAudioEvent &event);
    int32_t HandleRenderStateChangeEvent(const DAudioEvent &event);
    int32_t HandleVolumeChangeEvent(const DAudioEvent &event);
    int32_t HandleSANotifyEvent(const DAudioEvent &event);
    int32_t WaitForSANotify(const AudioDeviceEvent &event);
    int32_t HandleDeviceClosed(const DAudioEvent &event);
    int32_t getEventTypeFromCondition(const std::string& condition);

private:
    static constexpr uint8_t WAIT_SECONDS = 10;
    static constexpr int32_t TYPE_CONDITION = 11;
    AudioAdapterDescriptor adpDescriptor_;
    AudioAdapterStatus status_ = STATUS_OFFLINE;

    sptr<IDAudioCallback> extSpkCallback_ = nullptr;
    sptr<IDAudioCallback> extMicCallback_ = nullptr;
    sptr<IAudioCallback> paramCallback_ = nullptr;
    sptr<AudioRenderInterfaceImplBase> audioRender_ = nullptr;
    AudioParameter renderParam_;
    sptr<AudioCaptureInterfaceImplBase> audioCapture_ = nullptr;
    AudioParameter captureParam_;

    std::mutex devMapMtx_;
    std::mutex captureOptMtx_;
    std::mutex renderOptMtx_;
    std::map<uint32_t, std::string> mapAudioDevice_;
    std::mutex spkWaitMutex_;
    std::condition_variable spkWaitCond_;
    std::mutex micWaitMutex_;
    std::condition_variable micWaitCond_;

    bool isSpkOpened_ = false;
    bool isMicOpened_ = false;
    bool spkNotifyFlag_ = false;
    bool micNotifyFlag_ = false;

    uint32_t spkPinInUse_ = 0;
    uint32_t micPinInUse_ = 0;
    uint32_t streamMuteStatus_ = 0;
    uint32_t timeInterval_ = 5;

    // mmap param
    PortOperationMode renderFlags_ = Audioext::V1_0::NORMAL_MODE;
    PortOperationMode capturerFlags_ = Audioext::V1_0::NORMAL_MODE;

    const std::string NOT_MUTE_STATUS = "0";
    const std::string IS_MUTE_STATUS = "1";

    AudioCaptureInterfaceImplBase *(*GetCaptureImplExt_)() = nullptr;
    AudioRenderInterfaceImplBase *(*GetRenderImplExt_)() = nullptr;
#ifdef __aarch64__
    char resolvedPath_[100] = "/vendor/lib64/libdaudio_ext_hdf_service.z.so";
#else
    char resolvedPath_[100] = "/vendor/lib/libdaudio_ext_hdf_service.z.so";
#endif
};
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H