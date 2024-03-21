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

#ifndef OHOS_AUDIO_TEST_UTILS_H
#define OHOS_AUDIO_TEST_UTILS_H

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class MockIDAudioHdiCallback : public IDAudioHdiCallback {
public:
    MockIDAudioHdiCallback() {}
    ~MockIDAudioHdiCallback() {}

    int32_t CreateStream(const int32_t streamId) override
    {
        return DH_SUCCESS;
    }

    int32_t DestroyStream(const int32_t streamId) override
    {
        return DH_SUCCESS;
    }

    int32_t SetParameters(const int32_t streamId, const AudioParamHDF &param) override
    {
        return DH_SUCCESS;
    }

    int32_t NotifyEvent(const int32_t streamId, const AudioEvent &event) override
    {
        return DH_SUCCESS;
    }

    int32_t WriteStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data) override
    {
        return DH_SUCCESS;
    }

    int32_t ReadStreamData(const int32_t streamId, std::shared_ptr<AudioData> &data) override
    {
        data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        return DH_SUCCESS;
    }

    int32_t ReadMmapPosition(const int32_t streamId, uint64_t &frames, CurrentTimeHDF &time)
    {
        return DH_SUCCESS;
    }

    int32_t RefreshAshmemInfo(const int32_t streamId, int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans)
    {
        return DH_SUCCESS;
    }
};
} // DistributedHardware
} // OHOS
#endif // OHOS_AUDIO_TEST_UTILS_H