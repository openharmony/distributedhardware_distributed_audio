/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DAUDIO_ADAPTER_INTERNAL_TEST_H
#define DAUDIO_ADAPTER_INTERNAL_TEST_H

#include <sys/mman.h>

#include "daudio_adapter_internal.h"
#include "audio_adapter.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#include "audio_types.h"
#include <v1_0/iaudio_adapter.h>
#include <v1_0/iaudio_callback.h>
#include <v1_0/iaudio_capture.h>
#include <v1_0/iaudio_render.h>
namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioAdapter;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioDeviceDescriptor;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioSampleAttributes;
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioRender;
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioCapture;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioPort;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioPortCapability;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioPortPassthroughMode;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioDeviceStatus;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioRoute;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioExtParamKey;
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioCallback;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioAdapterDescriptor;
class MockIAudioAdapter : public IAudioAdapter {
public:
    MockIAudioAdapter() {}
    ~MockIAudioAdapter() {}

    int32_t InitAllPorts() override
    {
        return DH_SUCCESS;
    }

    int32_t CreateRender(const AudioDeviceDescriptor& desc, const AudioSampleAttributes& attrs,
        sptr<IAudioRender>& render) override
    {
        return DH_SUCCESS;
    }

    int32_t DestroyRender(const AudioDeviceDescriptor& desc) override
    {
        return DH_SUCCESS;
    }

    int32_t CreateCapture(const AudioDeviceDescriptor& desc, const AudioSampleAttributes& attrs,
        sptr<IAudioCapture>& capture) override
    {
        return DH_SUCCESS;
    }

    int32_t DestroyCapture(const AudioDeviceDescriptor& desc) override
    {
        return DH_SUCCESS;
    }

    int32_t GetPortCapability(const AudioPort& port, AudioPortCapability& capability) override
    {
        return DH_SUCCESS;
    }

    int32_t SetPassthroughMode(const AudioPort& port, AudioPortPassthroughMode mode) override
    {
        return DH_SUCCESS;
    }

    int32_t GetPassthroughMode(const AudioPort& port, AudioPortPassthroughMode& mode) override
    {
        return DH_SUCCESS;
    }

    int32_t GetDeviceStatus(AudioDeviceStatus& status) override
    {
        return DH_SUCCESS;
    }

    int32_t UpdateAudioRoute(const AudioRoute& route, int32_t& routeHandle) override
    {
        return DH_SUCCESS;
    }

    int32_t ReleaseAudioRoute(int32_t routeHandle) override
    {
        return DH_SUCCESS;
    }

    int32_t SetMicMute(bool mute) override
    {
        return DH_SUCCESS;
    }

    int32_t GetMicMute(bool& mute) override
    {
        return DH_SUCCESS;
    }

    int32_t SetVoiceVolume(float volume) override
    {
        return DH_SUCCESS;
    }

    int32_t SetExtraParams(AudioExtParamKey key, const std::string& condition, const std::string& value) override
    {
        return DH_SUCCESS;
    }

    int32_t GetExtraParams(AudioExtParamKey key, const std::string& condition, std::string& value) override
    {
        return DH_SUCCESS;
    }

    int32_t RegExtraParamObserver(const sptr<IAudioCallback>& audioCallback, int8_t cookie) override
    {
        return DH_SUCCESS;
    }
};
} // DistributedHardware
} // OHOS
#endif