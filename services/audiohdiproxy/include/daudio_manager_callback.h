/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_MANAGER_CALLBACK_H
#define OHOS_DAUDIO_MANAGER_CALLBACK_H

#include <v2_0/id_audio_callback.h>
#include <v2_0/types.h>

#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioManagerCallback : public OHOS::HDI::DistributedAudio::Audioext::V2_0::IDAudioCallback {
public:
    explicit DAudioManagerCallback(const std::shared_ptr<IDAudioHdiCallback> callback) : callback_(callback) {};
    ~DAudioManagerCallback() override = default;

    int32_t CreateStream(int32_t streamId) override;

    int32_t DestroyStream(int32_t streamId) override;

    int32_t SetParameters(int32_t streamId,
        const OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioParameter &param) override;

    int32_t NotifyEvent(int32_t streamId,
        const OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent &event) override;

    int32_t WriteStreamData(int32_t streamId,
        const OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData &data) override;

    int32_t ReadStreamData(int32_t streamId,
        OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData &data) override;

    int32_t ReadMmapPosition(int32_t streamId, uint64_t &frames,
        OHOS::HDI::DistributedAudio::Audioext::V2_0::CurrentTime &time) override;

    int32_t RefreshAshmemInfo(int32_t streamId, int fd, int32_t ashmemLength, int32_t lengthPerTrans) override;

private:
    int32_t GetAudioParamHDF(const OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioParameter& param,
        AudioParamHDF& paramHDF);

private:
    std::shared_ptr<IDAudioHdiCallback> callback_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_MANAGER_CALLBACK_H
