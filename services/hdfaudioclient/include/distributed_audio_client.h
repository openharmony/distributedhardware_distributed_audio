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

#ifndef HDI_DISTRIBUTED_AUDIO_CLIENT_H
#define HDI_DISTRIBUTED_AUDIO_CLIENT_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <string>

#include "audio_manager.h"
#include <v1_0/iaudio_manager.h>

#include "daudio_adapter_internal.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioManager;

struct AudioManagerContext {
    AudioManagerContext();
    ~AudioManagerContext();
    void ClearDescriptors();

    struct AudioManager instance_;
    sptr<IAudioManager> proxy_ = nullptr;

    std::mutex mtx_;

    std::map<std::string, std::unique_ptr<AudioAdapterContext>> adapters_;
    std::vector<::AudioAdapterDescriptor> descriptors_;
};
} // DistributedHardware
} // OHOS
#endif // HDI_DISTRIBUTED_AUDIO_CLIENT_H
