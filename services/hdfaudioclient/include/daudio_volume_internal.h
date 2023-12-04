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

#ifndef HDI_DAUDIO_VOLUME_INTERNAL_H
#define HDI_DAUDIO_VOLUME_INTERNAL_H

#include "audio_types.h"

#include "daudio_errorcode.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioVolumeInternal"

namespace OHOS {
namespace DistributedHardware {
template<typename T>
class AudioVolumeInternal final {
public:
    static int32_t SetMute(AudioHandle handle, bool mute);
    static int32_t GetMute(AudioHandle handle, bool *mute);
    static int32_t SetVolume(AudioHandle handle, float volume);
    static int32_t GetVolume(AudioHandle handle, float *volume);
    static int32_t GetGainThreshold(AudioHandle handle, float *min, float *max);
    static int32_t SetGain(AudioHandle handle, float gain);
    static int32_t GetGain(AudioHandle handle, float *gain);
};

template<typename T>
int32_t AudioVolumeInternal<T>::SetMute(AudioHandle handle, bool mute)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->SetMute(mute);
}

template<typename T>
int32_t AudioVolumeInternal<T>::GetMute(AudioHandle handle, bool *mute)
{
    if (handle == nullptr || mute == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetMute(*mute);
}

template<typename T>
int32_t AudioVolumeInternal<T>::SetVolume(AudioHandle handle, float volume)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->SetVolume(volume);
}

template<typename T>
int32_t AudioVolumeInternal<T>::GetVolume(AudioHandle handle, float *volume)
{
    if (handle == nullptr || volume == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetVolume(*volume);
}

template<typename T>
int32_t AudioVolumeInternal<T>::GetGainThreshold(AudioHandle handle, float *min, float *max)
{
    if (handle == nullptr || min == nullptr || max == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetGainThreshold(*min, *max);
}

template<typename T>
int32_t AudioVolumeInternal<T>::SetGain(AudioHandle handle, float gain)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->SetGain(gain);
}

template<typename T>
int32_t AudioVolumeInternal<T>::GetGain(AudioHandle handle, float *gain)
{
    if (handle == nullptr || gain == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetGain(*gain);
}
} // DistributedHardware
} // OHOS
#endif // HDI_DAUDIO_VOLUME_INTERNAL_H
