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

#include "daudio_param_callback_internal.h"

#include <string>

#include <v1_0/iaudio_callback.h>
#include <v1_0/audio_types.h>

#include "daudio_errorcode.h"

#define HDF_LOG_TAG HDF_AUDIO
namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioCallback;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioCallbackType;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioExtParamKey;

class AudioParamCallbackImpl final : public IAudioCallback {
public:
    AudioParamCallbackImpl(::ParamCallback callback, void *cookie) : callback_(callback), cookie_(cookie) {}
    ~AudioParamCallbackImpl() override {}

    int32_t RenderCallback(AudioCallbackType type, int8_t &reserved, int8_t &cookie) override;
    int32_t ParamCallback(AudioExtParamKey key, const std::string& condition, const std::string& value,
        int8_t &reserved, int8_t cookie) override;
private:
    ::ParamCallback callback_ = nullptr;
    void *cookie_ = nullptr;
};
AudioParamCallbackContext::AudioParamCallbackContext(::ParamCallback callback, void *cookie)
{
    callbackStub_ = new AudioParamCallbackImpl(callback, cookie);
}

int32_t AudioParamCallbackImpl::RenderCallback(AudioCallbackType type, int8_t &reserved, int8_t &cookie)
{
    (void) type;
    (void) reserved;
    (void) cookie;
    return DH_SUCCESS;
}

int32_t AudioParamCallbackImpl::ParamCallback(AudioExtParamKey key, const std::string& condition,
    const std::string& value, int8_t &reserved, int8_t cookie)
{
    (void) cookie;
    if (callback_ != nullptr) {
        callback_(static_cast<::AudioExtParamKey>(key), condition.c_str(),
            value.c_str(), static_cast<void *>(&reserved), cookie_);
        return DH_SUCCESS;
    } else {
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
}
} // namespace DistributedHardware
} // namespace OHOS