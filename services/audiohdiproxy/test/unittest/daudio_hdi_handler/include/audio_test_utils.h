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

#ifndef OHOS_AUDIO_TEST_UTILS_H
#define OHOS_AUDIO_TEST_UTILS_H

#include <v1_0/id_audio_callback.h>
#include <v1_0/id_audio_manager.h>

#include "daudio_errorcode.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audioext::V1_0::IDAudioCallback;
using OHOS::HDI::DistributedAudio::Audioext::V1_0::IDAudioManager;

class MockIDAudioManager : public IDAudioManager {
public:
    MockIDAudioManager() {}
    ~MockIDAudioManager() {}

    int32_t RegisterAudioDevice(const std::string &adpName, int32_t devId, const std::string &capability,
        const sptr<OHOS::HDI::DistributedAudio::Audioext::V1_0::IDAudioCallback> &callbackObj) override
    {
        return DH_SUCCESS;
    }

    int32_t UnRegisterAudioDevice(const std::string &adpName, int32_t devId) override
    {
        return DH_SUCCESS;
    }

    int32_t NotifyEvent(const std::string &adpName, int32_t devId,
        const OHOS::HDI::DistributedAudio::Audioext::V1_0::DAudioEvent &event) override
    {
        return DH_SUCCESS;
    }
};

class MockIDAudioHdiCallback : public IDAudioHdiCallback {
public:
    MockIDAudioHdiCallback() {}
    ~MockIDAudioHdiCallback() {}

    int32_t OpenDevice(const std::string &devId, const int32_t dhId) override
    {
        return DH_SUCCESS;
    }

    int32_t CloseDevice(const std::string &devId, const int32_t dhId) override
    {
        return DH_SUCCESS;
    }

    int32_t SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param) override
    {
        return DH_SUCCESS;
    }

    int32_t NotifyEvent(const std::string &devId, const int32_t dhId, const AudioEvent &event) override
    {
        return DH_SUCCESS;
    }

    int32_t WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override
    {
        return DH_SUCCESS;
    }

    int32_t ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data) override
    {
        return DH_SUCCESS;
    }

    int32_t ReadMmapPosition(const std::string &devId, const int32_t dhId,
        uint64_t &frames, CurrentTimeHDF &time)
    {
        return DH_SUCCESS;
    }

    int32_t RefreshAshmemInfo(const std::string &devId, const int32_t dhId,
        int32_t fd, int32_t ashmemLength, int32_t lengthPerTrans)
    {
        return DH_SUCCESS;
    }
};
} // DistributedHardware
} // OHOS
#endif // OHOS_AUDIO_TEST_UTILS_H
