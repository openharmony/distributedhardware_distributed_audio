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

#ifndef DAUDIO_ADAPTER_INTERNAL_H
#define DAUDIO_ADAPTER_INTERNAL_H

#include <map>
#include <mutex>
#include <vector>

#include "audio_adapter.h"
#include "audio_types.h"
#include <v1_0/iaudio_adapter.h>

#include "daudio_capture_internal.h"
#include "daudio_render_internal.h"
#include "daudio_param_callback_internal.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioAdapter;

constexpr int DESCRIPTOR_LENGTH = 32;
struct AudioAdapterContext {
    AudioAdapterContext();
    ~AudioAdapterContext();

    struct AudioAdapter instance_;
    sptr<IAudioAdapter> proxy_ = nullptr;
    std::string adapterName_;
    std::mutex mtx_;

    std::unique_ptr<AudioParamCallbackContext> callbackInternal_ = nullptr;
    ParamCallback callback_ = nullptr;

    std::vector<std::pair<uint32_t, std::unique_ptr<AudioCaptureContext>>> captures_;
    std::vector<std::pair<uint32_t, std::unique_ptr<AudioRenderContext>>> renders_;
    std::map<uint32_t, std::unique_ptr<::AudioPortCapability>> caps_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DAUDIO_ADAPTER_INTERNAL_H
