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

#include "daudio_adapter_internal.h"

#include <securec.h>
#include <string>

#include <v1_0/iaudio_render.h>
#include <v1_0/iaudio_capture.h>
#include <v1_0/audio_types.h>

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioAdapterInternal"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedAudio::Audio::V1_0;

static int32_t InitAllPortsInternal(struct AudioAdapter *adapter)
{
    if (adapter == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }
    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    return context->proxy_->InitAllPorts();
}

static void SetAudioSampleAttributesHAL(const struct ::AudioSampleAttributes *attrs,
    AudioSampleAttributes &attrsHal)
{
    attrsHal.type = static_cast<AudioCategory>(attrs->type);
    attrsHal.interleaved = attrs->interleaved;
    attrsHal.format = static_cast<AudioFormat>(attrs->format);
    attrsHal.sampleRate = attrs->sampleRate;
    attrsHal.channelCount = attrs->channelCount;
    attrsHal.period = attrs->period;
    attrsHal.frameSize = attrs->frameSize;
    attrsHal.isBigEndian = attrs->isBigEndian;
    attrsHal.isSignedData = attrs->isSignedData;
    attrsHal.startThreshold = attrs->startThreshold;
    attrsHal.stopThreshold = attrs->stopThreshold;
    attrsHal.silenceThreshold = attrs->silenceThreshold;
    attrsHal.streamId = attrs->streamId;
}

static int32_t CreateRenderInternal(struct AudioAdapter *adapter, const struct ::AudioDeviceDescriptor *desc,
    const struct ::AudioSampleAttributes *attrs, struct AudioRender **render)
{
    DHLOGI("Create distributed audio render.");
    if (adapter == nullptr || desc == nullptr || attrs == nullptr || render == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    AudioDeviceDescriptor descHal = {
        .portId = desc->portId,
        .pins = static_cast<AudioPortPin>(desc->pins),
    };
    descHal.desc = desc->desc == nullptr ? "" : desc->desc;

    AudioSampleAttributes attrsHal;
    SetAudioSampleAttributesHAL(attrs, attrsHal);
    sptr<IAudioRender> renderProxy = nullptr;
    uint32_t renderId;
    int32_t ret = context->proxy_->CreateRender(descHal, attrsHal, renderProxy, renderId);
    if (ret != DH_SUCCESS) {
        *render = nullptr;
        return ret;
    }
    auto renderContext = std::make_unique<AudioRenderContext>();
    *render = &renderContext->instance_;
    renderContext->proxy_ = renderProxy;
    renderContext->descHal_ = descHal;
    DHLOGI("The render ID: %u.", renderId);
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        context->renders_.push_back(std::make_pair(renderId, std::move(renderContext)));
    }
    return DH_SUCCESS;
}

static int32_t DestroyRenderInternal(struct AudioAdapter *adapter, struct AudioRender *render)
{
    DHLOGI("Destroy distributed audio render.");
    if (adapter == nullptr || render == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *adapterContext = reinterpret_cast<AudioAdapterContext *>(adapter);
    AudioRenderContext *renderContext = reinterpret_cast<AudioRenderContext *>(render);
    if (adapterContext->proxy_ == nullptr) {
        DHLOGE("The adapter context or proxy for the adapter context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    std::lock_guard<std::mutex> lock(adapterContext->mtx_);

    for (auto it = adapterContext->renders_.begin(); it != adapterContext->renders_.end(); ++it) {
        if ((it->second).get() == renderContext) {
            int32_t ret = adapterContext->proxy_->DestroyRender(it->first);
            if (ret != DH_SUCCESS) {
                return ret;
            }
            adapterContext->renders_.erase(it);
            break;
        }
    }
    return DH_SUCCESS;
}

static int32_t CreateCaptureInternal(struct AudioAdapter *adapter, const struct ::AudioDeviceDescriptor *desc,
    const struct ::AudioSampleAttributes *attrs, struct AudioCapture **capture)
{
    DHLOGI("Create distributed audio capture.");
    if (adapter == nullptr || desc == nullptr || attrs == nullptr || capture == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    AudioDeviceDescriptor descHal = {
        .portId = desc->portId,
        .pins = static_cast<AudioPortPin>(desc->pins),
    };
    descHal.desc = desc->desc == nullptr ? "" : desc->desc;
    AudioSampleAttributes attrsHal;
    SetAudioSampleAttributesHAL(attrs, attrsHal);
    sptr<IAudioCapture> captureProxy = nullptr;
    uint32_t captureId;
    int32_t ret = context->proxy_->CreateCapture(descHal, attrsHal, captureProxy, captureId);
    if (ret != DH_SUCCESS) {
        *capture = nullptr;
        return ret;
    }

    auto captureContext = std::make_unique<AudioCaptureContext>();
    *capture = &captureContext->instance_;
    captureContext->proxy_ = captureProxy;
    captureContext->descHal_ = descHal;
    DHLOGI("The capture ID: %u.", captureId);
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        context->captures_.push_back(std::make_pair(captureId, std::move(captureContext)));
    }
    return DH_SUCCESS;
}

static int32_t DestroyCaptureInternal(struct AudioAdapter *adapter, struct AudioCapture *capture)
{
    DHLOGI("Destroy distributed audio capture.");
    if (adapter == nullptr || capture == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *adapterContext = reinterpret_cast<AudioAdapterContext *>(adapter);
    AudioCaptureContext *captureContext = reinterpret_cast<AudioCaptureContext *>(capture);
    if (adapterContext->proxy_ == nullptr) {
        DHLOGE("The adapter context or proxy for the adapter context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    std::lock_guard<std::mutex> lock(adapterContext->mtx_);

    for (auto it = adapterContext->captures_.begin(); it != adapterContext->captures_.end(); ++it) {
        if ((it->second).get() == captureContext) {
            int32_t ret = adapterContext->proxy_->DestroyCapture(it->first);
            if (ret != DH_SUCCESS) {
                return ret;
            }
            adapterContext->captures_.erase(it);
            break;
        }
    }
    return DH_SUCCESS;
}

static int32_t GetPassthroughModeInternal(struct AudioAdapter *adapter, const struct ::AudioPort *port,
    enum ::AudioPortPassthroughMode *mode)
{
    if (adapter == nullptr || port == nullptr || mode == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    AudioPort portHal = {
        .dir = static_cast<AudioPortDirection>(port->dir),
        .portId = port->portId,
        .portName= port->portName,
    };
    return context->proxy_->GetPassthroughMode(portHal, *(reinterpret_cast<AudioPortPassthroughMode *>(mode)));
}

static int32_t InitAudioPortCapability(std::unique_ptr<::AudioPortCapability> &capInternal,
    AudioPortCapability &capabilityHal)
{
    DHLOGI("Init audio port capability internal, formatNum: %zu.", capabilityHal.formatNum);
    constexpr uint32_t maxFormatNum = 100;
    constexpr uint32_t minFormatNum = 1;
    if (capabilityHal.formatNum < minFormatNum || capabilityHal.formatNum > maxFormatNum) {
        DHLOGE("Init audio port capability, formatNum: %zu.", capabilityHal.formatNum);
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }
    ::AudioFormat *audioFormats = (::AudioFormat *)malloc(capabilityHal.formatNum * sizeof(::AudioFormat));
    if (audioFormats == nullptr) {
        DHLOGE("Malloc failed.");
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }

    capInternal->deviceType = capabilityHal.deviceType;
    capInternal->deviceId = capabilityHal.deviceId;
    capInternal->hardwareMode = static_cast<bool>(capabilityHal.hardwareMode);
    capInternal->formatNum = capabilityHal.formatNum;
    capInternal->formats = audioFormats;
    for (auto format : capabilityHal.formats) {
        *audioFormats = static_cast<::AudioFormat>(format);
        audioFormats++;
    }
    capInternal->sampleRateMasks = capabilityHal.sampleRateMasks;
    capInternal->channelMasks = static_cast<::AudioChannelMask>(capabilityHal.channelMasks);
    capInternal->channelCount = capabilityHal.channelCount;
    capInternal->subPortsNum = 0;
    capInternal->subPorts = nullptr;
    return DH_SUCCESS;
}

static int32_t GetPortCapabilityInternal(struct AudioAdapter *adapter, const struct ::AudioPort *port,
    struct ::AudioPortCapability *capability)
{
    if (adapter == nullptr || port == nullptr || port->portName == nullptr || capability == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        auto iter = context->caps_.find(port->portId);
        if (iter != context->caps_.end()) {
            *capability = *(iter->second);
            return DH_SUCCESS;
        }
    }
    AudioPort portHal = {
        .dir = static_cast<AudioPortDirection>(port->dir),
        .portId = port->portId,
        .portName = port->portName,
    };

    AudioPortCapability capabilityHal;
    int32_t ret = context->proxy_->GetPortCapability(portHal, capabilityHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }

    auto capInternal = std::make_unique<::AudioPortCapability>();
    ret = InitAudioPortCapability(capInternal, capabilityHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    *capability = *capInternal;
    {
        std::lock_guard<std::mutex> lock(context->mtx_);
        context->caps_[port->portId] = std::move(capInternal);
    }
    return DH_SUCCESS;
}

static int32_t ReleaseAudioRouteInternal(struct AudioAdapter *adapter, int32_t routeHandle)
{
    if (adapter == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    return context->proxy_->ReleaseAudioRoute(routeHandle);
}

static int32_t SetPassthroughModeInternal(struct AudioAdapter *adapter, const struct ::AudioPort *port,
    enum ::AudioPortPassthroughMode mode)
{
    if (adapter == nullptr || port == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    AudioPort portHal = {
        .dir = static_cast<AudioPortDirection>(port->dir),
        .portId = port->portId,
        .portName = port->portName,
    };
    AudioPortPassthroughMode modeHal = static_cast<AudioPortPassthroughMode>(static_cast<int32_t>(mode));
    return context->proxy_->SetPassthroughMode(portHal, modeHal);
}

static void ConvertAudioRouteNodeToHAL(const ::AudioRouteNode &node, AudioRouteNode &halNode)
{
    halNode.portId = node.portId;
    halNode.role = static_cast<AudioPortRole>(node.role);
    halNode.type = static_cast<AudioPortType>(node.type);
    DHLOGD("Convert audio route node To HAL, portId: %d role: %d type: %d.", halNode.portId, halNode.role,
        halNode.type);

    switch (node.type) {
        case AUDIO_PORT_UNASSIGNED_TYPE:
            break;
        case AUDIO_PORT_DEVICE_TYPE: {
            size_t descLength = DESCRIPTOR_LENGTH;
            halNode.ext.device.moduleId = node.ext.device.moduleId;
            halNode.ext.device.type = static_cast<AudioPortPin>(node.ext.device.type);
            if (node.ext.device.desc != nullptr) {
                size_t length = strlen(node.ext.device.desc);
                length = length < descLength ? length : descLength;
                halNode.ext.device.desc = std::string(node.ext.device.desc, node.ext.device.desc + length);
            }
            break;
        }
        case AUDIO_PORT_MIX_TYPE: {
            halNode.ext.mix.moduleId = node.ext.mix.moduleId;
            halNode.ext.mix.streamId = node.ext.mix.streamId;

            DHLOGD("Convert audio route node To HAL, [Mix] moduleId: %d streamId: %d.",
                halNode.ext.mix.moduleId, halNode.ext.mix.streamId);
            break;
        }
        case AUDIO_PORT_SESSION_TYPE: {
            halNode.ext.session.sessionType = static_cast<AudioSessionType>(node.ext.session.sessionType);
            DHLOGD("Convert audio route node To HAL, [Session] sessionType: %d.", halNode.ext.session.sessionType);
            break;
        }
        default :
            DHLOGD("Unknown node Type");
    }
}
static int32_t UpdateAudioRouteInternal(struct AudioAdapter *adapter, const struct ::AudioRoute *route,
    int32_t *routeHandle)
{
    if (adapter == nullptr || route == nullptr || routeHandle == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRoute audioRoute;
    for (uint32_t i = 0; i < route->sourcesNum; ++i) {
        AudioRouteNode halNode = {0};
        ConvertAudioRouteNodeToHAL(route->sources[i], halNode);
        audioRoute.sources.push_back(halNode);
    }

    for (uint32_t i = 0; i < route->sinksNum; ++i) {
        AudioRouteNode halNode = {0};
        ConvertAudioRouteNodeToHAL(route->sinks[i], halNode);
        audioRoute.sinks.push_back(halNode);
    }

    int32_t handle = -1;
    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    int32_t ret = context->proxy_->UpdateAudioRoute(audioRoute, handle);
    *routeHandle = handle;
    return ret;
}

static int32_t SetExtraParamsInternal(struct AudioAdapter *adapter, enum ::AudioExtParamKey key,
    const char *condition, const char *value)
{
    if (adapter == nullptr || condition == nullptr || value == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    return context->proxy_->SetExtraParams(static_cast<AudioExtParamKey>(key),
        std::string(condition), std::string(value));
}

static int32_t GetExtraParamsInternal(struct AudioAdapter *adapter, enum ::AudioExtParamKey key,
    const char *condition, char *value, int32_t length)
{
    if (adapter == nullptr || condition == nullptr || value == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    std::string valueHal;
    int32_t ret =
        context->proxy_->GetExtraParams(static_cast<AudioExtParamKey>(key),
            std::string(condition), valueHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    ret = strcpy_s(value, length, valueHal.c_str());
    if (ret != EOK) {
        DHLOGE("Strcpy_s failed!, ret: %d", ret);
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    return DH_SUCCESS;
}

static int32_t RegExtraParamObserverInternal(struct AudioAdapter *adapter, ParamCallback callback, void* cookie)
{
    if (adapter == nullptr || callback == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioAdapterContext *context = reinterpret_cast<AudioAdapterContext *>(adapter);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_HDI_NULLPTR;
    }
    std::lock_guard<std::mutex> lock(context->mtx_);
    if (context->callbackInternal_ == nullptr || callback != context->callback_) {
        context->callbackInternal_ = std::make_unique<AudioParamCallbackContext>(callback, cookie);
    } else {
        return DH_SUCCESS;
    }

    if (context->callbackInternal_->callbackStub_ == nullptr) {
        context->callbackInternal_ = nullptr;
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }

    int32_t ret = context->proxy_->RegExtraParamObserver(context->callbackInternal_->callbackStub_, 0);
    if (ret == DH_SUCCESS) {
        context->callback_ = callback;
    } else {
        context->callbackInternal_ = nullptr;
    }

    return ret;
}

AudioAdapterContext::AudioAdapterContext()
{
    instance_.InitAllPorts = InitAllPortsInternal;
    instance_.CreateRender = CreateRenderInternal;
    instance_.DestroyRender = DestroyRenderInternal;
    instance_.CreateCapture = CreateCaptureInternal;
    instance_.DestroyCapture = DestroyCaptureInternal;
    instance_.GetPassthroughMode = GetPassthroughModeInternal;
    instance_.GetPortCapability = GetPortCapabilityInternal;
    instance_.ReleaseAudioRoute = ReleaseAudioRouteInternal;
    instance_.SetPassthroughMode = SetPassthroughModeInternal;
    instance_.UpdateAudioRoute = UpdateAudioRouteInternal;
    instance_.SetExtraParams = SetExtraParamsInternal;
    instance_.GetExtraParams = GetExtraParamsInternal;
    instance_.RegExtraParamObserver = RegExtraParamObserverInternal;

    instance_.SetVoiceVolume = nullptr;
    instance_.GetMicMute = nullptr;
    instance_.SetMicMute = nullptr;
    instance_.GetDeviceStatus = nullptr;
}

AudioAdapterContext::~AudioAdapterContext()
{
    captures_.clear();
    renders_.clear();
    for (auto &cap : caps_) {
        if (cap.second->formats != nullptr) {
            free(cap.second->formats);
        }
    }
    caps_.clear();
}
} // namespace DistributedHardware
} // namespace OHOS
