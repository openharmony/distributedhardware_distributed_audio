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

#ifndef OHOS_AUDIO_RENDER_INTERFACE_IMPL_BASE_H
#define OHOS_AUDIO_RENDER_INTERFACE_IMPL_BASE_H

#include <mutex>
#include <string>
#include <cmath>

#include <v1_0/audio_types.h>
#include <v1_0/iaudio_render.h>
#include <v1_0/id_audio_manager.h>

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
typedef enum {
    RENDER_STATUS_OPEN = 0,
    RENDER_STATUS_CLOSE,
    RENDER_STATUS_START,
    RENDER_STATUS_STOP,
    RENDER_STATUS_PAUSE,
} AudioRenderStatus;

class AudioRenderInterfaceImplBase : public IAudioRender {
public:
    AudioRenderInterfaceImplBase(const AudioDeviceDescriptor &desc);
    ~AudioRenderInterfaceImplBase();

    const AudioDeviceDescriptor &GetRenderDesc();
    void SetVolumeInner(const uint32_t vol);
    void SetVolumeRangeInner(const uint32_t volMax, const uint32_t volMin);
    uint32_t GetVolumeInner();
    uint32_t GetMaxVolumeInner();
    uint32_t GetMinVolumeInner();

private:
    AudioDeviceDescriptor baseDevDesc_;
    std::mutex volMtx_;
    uint32_t vol_ = 0;
    uint32_t volMax_ = 0;
    uint32_t volMin_ = 0;
};
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_AUDIO_RENDER_INTERFACE_IMPL_BASE_H
