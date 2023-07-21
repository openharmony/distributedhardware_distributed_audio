/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_AUDIO_MANAGER_TEST_UTILS
#define OHOS_AUDIO_MANAGER_TEST_UTILS

#include "daudio_errorcode.h"
#include "iaudio_data_transport.h"
#include "iaudio_event_callback.h"

namespace OHOS {
namespace DistributedHardware {
class MockIAudioEventCallback : public IAudioEventCallback {
public:
    MockIAudioEventCallback() = default;
    ~MockIAudioEventCallback() = default;

    void NotifyEvent(const AudioEvent &event) override
    {
        (void) event;
    }
};

class MockIAudioDataTransport : public IAudioDataTransport {
public:
    MockIAudioDataTransport() = default;
    ~MockIAudioDataTransport() = default;

    int32_t SetUp(const AudioParam &localParam, const AudioParam &remoteParam,
        const std::shared_ptr<IAudioDataTransCallback> &callback, const PortCapType capType) override
    {
        return DH_SUCCESS;
    }

    int32_t Start() override
    {
        return DH_SUCCESS;
    }

    int32_t Stop() override
    {
        return DH_SUCCESS;
    }

    int32_t Release() override
    {
        return DH_SUCCESS;
    }

    int32_t Pause() override
    {
        return DH_SUCCESS;
    }

    int32_t Restart(const AudioParam &localParam, const AudioParam &remoteParam) override
    {
        return DH_SUCCESS;
    }

    int32_t FeedAudioData(std::shared_ptr<AudioData> &audioData) override
    {
        return DH_SUCCESS;
    }

    int32_t InitEngine(IAVEngineProvider *providerPtr) override
    {
        return DH_SUCCESS;
    }

    int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) override
    {
        return 0;
    }

    int32_t CreateCtrl() override
    {
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_AUDIO_MANAGER_TEST_UTILS
