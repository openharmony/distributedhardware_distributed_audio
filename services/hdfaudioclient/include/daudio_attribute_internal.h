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

#ifndef HDI_DAUDIO_ATTRIBUTE_INTERNAL_H
#define HDI_DAUDIO_ATTRIBUTE_INTERNAL_H

#include <securec.h>
#include <cstdint>
#include <sys/mman.h>

#include "audio_types.h"
#include <v1_0/audio_types.h>

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioAttributeInternal"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedAudio::Audio::V1_0;

template<typename T>
class AudioAttributeInternal final {
public:
    static int32_t GetFrameSize(AudioHandle handle, uint64_t *size);
    static int32_t GetFrameCount(AudioHandle handle, uint64_t *count);
    static int32_t SetSampleAttributes(AudioHandle handle, const struct ::AudioSampleAttributes *attrs);
    static int32_t GetSampleAttributes(AudioHandle handle, struct ::AudioSampleAttributes *attrs);
    static int32_t GetCurrentChannelId(AudioHandle handle, uint32_t *channelId);
    static int32_t SetExtraParams(AudioHandle handle, const char *keyValueList);
    static int32_t GetExtraParams(AudioHandle handle, char *keyValueList, int32_t listLenth);
    static int32_t ReqMmapBuffer(AudioHandle handle, int32_t reqSize, struct ::AudioMmapBufferDescriptor *desc);
    static int32_t GetMmapPosition(AudioHandle handle, uint64_t *frames, struct ::AudioTimeStamp *time);
};

template<typename T>
int32_t AudioAttributeInternal<T>::GetFrameSize(AudioHandle handle, uint64_t *size)
{
    if (handle == nullptr || size == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetFrameSize(*size);
}

template<typename T>
int32_t AudioAttributeInternal<T>::GetFrameCount(AudioHandle handle, uint64_t *count)
{
    if (handle == nullptr || count == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetFrameCount(*count);
}

template<typename T>
int32_t AudioAttributeInternal<T>::SetSampleAttributes(AudioHandle handle,
    const struct ::AudioSampleAttributes *attrs)
{
    if (handle == nullptr || attrs == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    AudioSampleAttributes attrsHal = {
        .format = static_cast<AudioFormat>(attrs->format),
        .sampleRate = attrs->sampleRate,
        .channelCount = attrs->channelCount,
    };
    DHLOGD("AttrsHal.format = %{public}u", attrsHal.format);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->SetSampleAttributes(attrsHal);
}

template<typename T>
int32_t AudioAttributeInternal<T>::GetSampleAttributes(AudioHandle handle, struct ::AudioSampleAttributes *attrs)
{
    if (handle == nullptr || attrs == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    DHLOGD("Get sample attributes.");
    T *context = reinterpret_cast<T *>(handle);
    if (context == nullptr || context->proxy_ == nullptr) {
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioSampleAttributes attrsHal;
    int32_t ret = context->proxy_->GetSampleAttributes(attrsHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }

    attrs->type = static_cast<::AudioCategory>(attrsHal.type);
    attrs->interleaved = static_cast<bool>(attrsHal.interleaved);
    attrs->format = static_cast<::AudioFormat>(attrsHal.format);
    attrs->sampleRate = attrsHal.sampleRate;
    attrs->channelCount = attrsHal.channelCount;
    attrs->streamId = static_cast<int32_t>(attrsHal.streamId);
    return DH_SUCCESS;
}

template<typename T>
int32_t AudioAttributeInternal<T>::GetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    if (handle == nullptr || channelId == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->GetCurrentChannelId(*channelId);
}

template<typename T>
int32_t AudioAttributeInternal<T>::SetExtraParams(AudioHandle handle, const char *keyValueList)
{
    if (handle == nullptr || keyValueList == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    std::string keyValueListHal(keyValueList);
    return (context == nullptr || context->proxy_ == nullptr) ?
        ERR_DH_AUDIO_HDI_INVALID_PARAM : context->proxy_->SetExtraParams(keyValueListHal);
}

template<typename T>
int32_t AudioAttributeInternal<T>::GetExtraParams(AudioHandle handle, char *keyValueList, int32_t listLenth)
{
    if (handle == nullptr || keyValueList == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    if (listLenth <= 0) {
        DHLOGE("The parameter is invalid.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    if (context == nullptr || context->proxy_ == nullptr) {
        DHLOGE("The context is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    std::string keyValueListHal(keyValueList);
    int32_t ret = context->proxy_->GetExtraParams(keyValueListHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    if (listLenth - 1 < (int)keyValueListHal.length()) {
        keyValueListHal = keyValueListHal.substr(0, listLenth - 1);
    }
    if (strcpy_s(keyValueList, listLenth, keyValueListHal.c_str()) != EOK) {
        DHLOGE("Strcpy_s keyValueList failed.");
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    return DH_SUCCESS;
}

template<typename T>
int32_t AudioAttributeInternal<T>::ReqMmapBuffer(AudioHandle handle, int32_t reqSize,
    struct ::AudioMmapBufferDescriptor *desc)
{
    if (handle == nullptr || desc == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    T *context = reinterpret_cast<T *>(handle);
    if (context == nullptr || context->proxy_ == nullptr) {
        DHLOGE("The context is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioMmapBufferDescriptor descHal;
    int32_t ret = context->proxy_->ReqMmapBuffer(reqSize, descHal);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to request the mmap buffer.");
        return ret;
    }

    desc->memoryFd = descHal.memoryFd;
    desc->totalBufferFrames = descHal.totalBufferFrames;
    desc->transferFrameSize = descHal.transferFrameSize;
    desc->isShareable = descHal.isShareable;
    return DH_SUCCESS;
}

template<typename T>
int32_t AudioAttributeInternal<T>::GetMmapPosition(AudioHandle handle, uint64_t *frames,
    struct ::AudioTimeStamp *time)
{
    if (handle == nullptr || frames == nullptr || time == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }
    DHLOGD("Get mmap position.");

    T *context = reinterpret_cast<T *>(handle);
    if (context == nullptr || context->proxy_ == nullptr) {
        DHLOGE("The context is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioTimeStamp timeHal;
    int32_t ret = context->proxy_->GetMmapPosition(*frames, timeHal);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to get the mmap position.");
        return ret;
    }

    time->tvSec = static_cast<int64_t>(timeHal.tvSec);
    time->tvNSec = static_cast<int64_t>(timeHal.tvNSec);
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
#endif // HDI_DAUDIO_ATTRIBUTE_INTERNAL_H
