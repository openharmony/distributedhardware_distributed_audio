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

#ifndef OHOS_ISPK_CLIENT_H
#define OHOS_ISPK_CLIENT_H

#include <memory>

#include "audio_param.h"
#include "i_av_engine_provider.h"

namespace OHOS {
namespace DistributedHardware {
class ISpkClient {
public:
    ISpkClient() = default;
    virtual ~ISpkClient() = default;

    virtual int32_t SetUp(const AudioParam &param) = 0;
    virtual int32_t Release() = 0;
    virtual int32_t StartRender() = 0;
    virtual int32_t StopRender() = 0;
    virtual int32_t SetMute(const AudioEvent &event) = 0;
    virtual int32_t SetAudioParameters(const AudioEvent &event) = 0;
    virtual void PlayStatusChange(const std::string &args) = 0;
    virtual void SetAttrs(const std::string &devId, const std::shared_ptr<IAudioEventCallback> &callback) = 0;
    virtual int32_t InitReceiverEngine(IAVEngineProvider *providerPtr) = 0;
    virtual int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_ISPK_CLIENT_H