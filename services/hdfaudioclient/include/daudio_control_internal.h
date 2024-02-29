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

#ifndef HDI_DAUDIO_CONTROL_INTERNAL_H
#define HDI_DAUDIO_CONTROL_INTERNAL_H

#include <cstdint>

#include "audio_types.h"

#include "daudio_errorcode.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioControlInternal"

namespace OHOS {
namespace DistributedHardware {
template<typename T>
class AudioControlInternal final {
public:
    static int32_t Start(AudioHandle handle);
    static int32_t Stop(AudioHandle handle);
    static int32_t Pause(AudioHandle handle);
    static int32_t Resume(AudioHandle handle);
    static int32_t Flush(AudioHandle handle);
    static int32_t TurnStandbyMode(AudioHandle handle);
    static int32_t AudioDevDump(AudioHandle handle, int32_t range, int32_t fd);
};

template<typename T>
int32_t AudioControlInternal<T>::Start(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->Start();
}

template<typename T>
int32_t AudioControlInternal<T>::Stop(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->Stop();
}

template<typename T>
int32_t AudioControlInternal<T>::Pause(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->Pause();
}

template<typename T>
int32_t AudioControlInternal<T>::Resume(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->Resume();
}

template<typename T>
int32_t AudioControlInternal<T>::Flush(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->Flush();
}

template<typename T>
int32_t AudioControlInternal<T>::TurnStandbyMode(AudioHandle handle)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->TurnStandbyMode();
}

template<typename T>
int32_t AudioControlInternal<T>::AudioDevDump(AudioHandle handle, int32_t range, int32_t fd)
{
    if (handle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->AudioDevDump(range, fd);
}
} // DistributedHardware
} // OHOS
#endif // HDI_DAUDIO_CONTROL_INTERNAL_H