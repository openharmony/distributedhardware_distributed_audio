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

#ifndef IAUDIO_DATA_TRANSPORT_H
#define IAUDIO_DATA_TRANSPORT_H

#include "audio_data.h"
#include "audio_param.h"
#include "iaudio_datatrans_callback.h"
#include "i_av_engine_provider.h"

namespace OHOS {
namespace DistributedHardware {
class IAudioDataTransport {
public:
    IAudioDataTransport() = default;
    virtual ~IAudioDataTransport() = default;
    virtual int32_t SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
        const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType) = 0;
    virtual int32_t Start() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Release() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Restart(const AudioParam &localParam, const AudioParam &remoteParam) = 0;
    virtual int32_t FeedAudioData(std::shared_ptr<AudioData> &audioData) = 0;
    virtual int32_t CreateCtrl() = 0;
    virtual int32_t InitEngine(IAVEngineProvider *providerPtr) = 0;
    virtual int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // IAUDIO_DATA_TRANSPORT_H
