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

#ifndef DAUDIO_CAPTURE_INTERNAL_H
#define DAUDIO_CAPTURE_INTERNAL_H

#include <mutex>

#include "audio_capture.h"
#include <v1_0/audio_types.h>
#include <v1_0/iaudio_capture.h>

#include "daudio_render_callback_internal.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioDeviceDescriptor;
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioCapture;
struct AudioCaptureContext {
    AudioCaptureContext();
    ~AudioCaptureContext();

    struct AudioCapture instance_;
    struct AudioDeviceDescriptor descHal_;
    sptr<IAudioCapture> proxy_ = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DAUDIO_CAPTURE_INTERNAL_H
