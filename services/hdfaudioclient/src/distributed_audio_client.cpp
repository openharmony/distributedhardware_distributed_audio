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

#include "distributed_audio_client.h"

#include <securec.h>

#include <v1_0/audio_types.h>

#include "audio_types.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioAudioClient"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioAdapter;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioAdapterDescriptor;

static int32_t InitDescriptorPort(const AudioAdapterDescriptor &desc, ::AudioAdapterDescriptor &descInternal)
{
    DHLOGI("Init audio adapter descriptor port.");
    ::AudioPort *audioPorts = (::AudioPort *)malloc(desc.ports.size() * sizeof(AudioPort));
    CHECK_NULL_RETURN(audioPorts, ERR_DH_AUDIO_NULLPTR);
    descInternal.ports = audioPorts;

    bool isSuccess = true;
    uint32_t cpyPortNum = 0;
    constexpr uint32_t maxPortNameLen = 1000;
    for (auto port : desc.ports) {
        if (port.portName.length() >= maxPortNameLen) {
            DHLOGE("Audio port name length is too long.");
            continue;
        }
        char* portName = reinterpret_cast<char *>(calloc(port.portName.length() + STR_TERM_LEN, sizeof(char)));
        if (portName == nullptr) {
            DHLOGE("Calloc failed.");
            isSuccess = false;
            break;
        }
        if (strcpy_s(portName, port.portName.length() + STR_TERM_LEN, port.portName.c_str()) != EOK) {
            DHLOGD("Strcpy_s port name failed.");
            free(portName);
            continue;
        }
        audioPorts->dir = static_cast<::AudioPortDirection>(port.dir);
        audioPorts->portId = port.portId;
        audioPorts->portName = portName;
        audioPorts++;
        cpyPortNum++;
    }
    if (isSuccess) {
        return DH_SUCCESS;
    }

    for (uint32_t i = 0; i < cpyPortNum; i++) {
        if (descInternal.ports[i].portName != nullptr) {
            free(const_cast<char *>(descInternal.ports[i].portName));
        }
    }
    free(descInternal.ports);
    descInternal.ports = nullptr;
    return ERR_DH_AUDIO_HDI_CALL_FAILED;
}

static int32_t InitAudioAdapterDescriptor(AudioManagerContext *context,
    std::vector<AudioAdapterDescriptor> &descriptors)
{
    DHLOGI("Init audio adapters descriptor, size is: %zu.", descriptors.size());
    constexpr uint32_t maxAdapterNameLen = 1000;
    constexpr uint32_t maxPortNum = 100;
    constexpr uint32_t minPortNum = 1;
    for (auto desc : descriptors) {
        if (desc.ports.size() < minPortNum || desc.ports.size() > maxPortNum) {
            DHLOGE("The descriptor ports size: %zu.", desc.ports.size());
            continue;
        }
        if (desc.adapterName.length() >= maxAdapterNameLen) {
            DHLOGE("Audio adapter name length is too long.");
            continue;
        }
        char* adapterName = reinterpret_cast<char *>(calloc(desc.adapterName.length() + STR_TERM_LEN, sizeof(char)));
        CHECK_NULL_RETURN(adapterName, ERR_DH_AUDIO_NULLPTR);
        if (strcpy_s(adapterName, desc.adapterName.length() + STR_TERM_LEN, desc.adapterName.c_str()) != EOK) {
            DHLOGD("Strcpy_s adapter name failed.");
            free(adapterName);
            continue;
        }

        ::AudioAdapterDescriptor descInternal = {
            .adapterName = adapterName,
            .portNum = desc.ports.size(),
        };
        int32_t ret = InitDescriptorPort(desc, descInternal);
        if (ret != DH_SUCCESS) {
            DHLOGE("Init audio adapter descriptor port fail.");
            free(adapterName);
            descInternal.adapterName = nullptr;
            return ret;
        }
        context->descriptors_.push_back(descInternal);
    }
    return DH_SUCCESS;
}

static int32_t GetAllAdaptersInternal(struct AudioManager *manager, struct ::AudioAdapterDescriptor **descs,
    int32_t *size)
{
    DHLOGI("Get all adapters.");
    CHECK_NULL_RETURN(manager, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    CHECK_NULL_RETURN(descs, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    CHECK_NULL_RETURN(size, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    AudioManagerContext *context = reinterpret_cast<AudioManagerContext *>(manager);
    CHECK_NULL_RETURN(context->proxy_, ERR_DH_AUDIO_NULLPTR);

    std::lock_guard<std::mutex> lock(context->mtx_);
    std::vector<AudioAdapterDescriptor> descriptors;
    int32_t ret = context->proxy_->GetAllAdapters(descriptors);
    if (ret != DH_SUCCESS) {
        *descs = nullptr;
        *size = 0;
        DHLOGE("Failed to get all adapters.");
        return ret;
    }
    context->ClearDescriptors();
    ret = InitAudioAdapterDescriptor(context, descriptors);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    *descs = context->descriptors_.data();
    *size = context->descriptors_.size();
    return DH_SUCCESS;
}

static int32_t LoadAdapterInternal(struct AudioManager *manager, const struct ::AudioAdapterDescriptor *desc,
    struct AudioAdapter **adapter)
{
    DHLOGI("Load adapter.");
    CHECK_NULL_RETURN(manager, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    CHECK_NULL_RETURN(desc, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    CHECK_NULL_RETURN(desc->adapterName, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    CHECK_NULL_RETURN(adapter, ERR_DH_AUDIO_HDI_INVALID_PARAM);
    AudioManagerContext *context = reinterpret_cast<AudioManagerContext *>(manager);
    std::string adpName = desc->adapterName;
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        if (context->adapters_.find(adpName) != context->adapters_.end()) {
            DHLOGD("Adapter already has been load.");
            *adapter = &(context->adapters_[adpName]->instance_);
            return DH_SUCCESS;
        }
    }

    AudioAdapterDescriptor descriptor = {
        .adapterName = desc->adapterName,
    };
    sptr<IAudioAdapter> adapterProxy = nullptr;
    CHECK_NULL_RETURN(context->proxy_, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = context->proxy_->LoadAdapter(descriptor, adapterProxy);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to load the adapter.");
        *adapter = nullptr;
        return ret;
    }

    auto adapterContext  = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = adapterProxy;
    *adapter = &adapterContext->instance_;
    adapterContext->adapterName_ = descriptor.adapterName;
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        context->adapters_.insert(std::make_pair(adpName, std::move(adapterContext)));
    }
    return DH_SUCCESS;
}

static void UnloadAdapterInternal(struct AudioManager *manager, struct AudioAdapter *adapter)
{
    DHLOGI("Unload adapter.");
    CHECK_NULL_VOID(manager);
    CHECK_NULL_VOID(adapter);
    AudioManagerContext *context = reinterpret_cast<AudioManagerContext *>(manager);
    AudioAdapterContext *adapterContext = reinterpret_cast<AudioAdapterContext *>(adapter);
    CHECK_NULL_VOID(context->proxy_);

    std::lock_guard<std::mutex> lock(context->mtx_);
    for (auto it = context->adapters_.begin(); it != context->adapters_.end(); it++) {
        if ((it->second).get() == adapterContext) {
            int32_t ret = context->proxy_->UnloadAdapter(adapterContext->adapterName_);
            if (ret != DH_SUCCESS) {
                DHLOGE("Failed to unload adapter.");
                return;
            }
            context->adapters_.erase(it);
            break;
        }
    }
    DHLOGI("Unload adapter success.");
}

void AudioManagerContext::ClearDescriptors()
{
    DHLOGI("Clear descriptors enter.");
    for (auto &desc : descriptors_) {
        if (desc.adapterName != nullptr) {
            free(const_cast<char *>(desc.adapterName));
        }
        for (uint32_t i = 0; i < desc.portNum; i++) {
            if (desc.ports[i].portName != nullptr) {
                free(const_cast<char *>(desc.ports[i].portName));
            }
        }
        free(desc.ports);
    }
    descriptors_.clear();
    DHLOGI("Clear descriptors end.");
}

AudioManagerContext::AudioManagerContext()
{
    instance_.GetAllAdapters = GetAllAdaptersInternal;
    instance_.LoadAdapter = LoadAdapterInternal;
    instance_.UnloadAdapter = UnloadAdapterInternal;

    instance_.ReleaseAudioManagerObject = nullptr;
}

AudioManagerContext::~AudioManagerContext()
{
    adapters_.clear();
    ClearDescriptors();
}

AudioManagerContext g_AudioManagerContext;

static bool AudioManagerInit()
{
    std::lock_guard<std::mutex> lock(g_AudioManagerContext.mtx_);

    sptr<IAudioManager> audioMgr = IAudioManager::Get("daudio_primary_service", false);
    CHECK_NULL_RETURN(audioMgr, false);
    g_AudioManagerContext.proxy_ = audioMgr;
    return true;
}
} // DistributedHardware
} // OHOS

#ifdef __cplusplus
extern "C" {
#endif

struct AudioManager *GetAudioManagerFuncs(void)
{
    if (OHOS::DistributedHardware::AudioManagerInit()) {
        return &OHOS::DistributedHardware::g_AudioManagerContext.instance_;
    } else {
        return nullptr;
    }
}

#ifdef __cplusplus
}
#endif
