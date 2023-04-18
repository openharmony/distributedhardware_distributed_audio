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

#ifndef OHOS_IDAUDIO_HDI_CALLBACK_H
#define OHOS_IDAUDIO_HDI_CALLBACK_H

#include "audio_data.h"
#include "audio_event.h"
#include "audio_param.h"

namespace OHOS {
namespace DistributedHardware {
class IDAudioHdiCallback {
public:
    virtual ~IDAudioHdiCallback() = default;

    virtual int32_t OpenDevice(const std::string &devId, const int32_t dhId) = 0;

    virtual int32_t CloseDevice(const std::string &devId, const int32_t dhId) = 0;

    virtual int32_t SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param) = 0;

    virtual int32_t NotifyEvent(const std::string &devId, const int32_t dhId, const AudioEvent &event) = 0;

    virtual int32_t WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) = 0;

    virtual int32_t ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) = 0;
};
} // DistributedHardware
} // OHOS

#endif // OHOS_IDAUDIO_HDI_CALLBACK_H