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
#include "daudio_render_internal.h"

#include <securec.h>

#include "daudio_attribute_internal.h"
#include "daudio_control_internal.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_scene_internal.h"
#include "daudio_volume_internal.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioRenderInternal"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedAudio::Audio::V1_0;

static int32_t GetLatencyInternal(struct AudioRender *render, uint32_t *ms)
{
    if (render == nullptr || ms == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->GetLatency(*ms);
}

static int32_t RenderFrameInternal(struct AudioRender *render, const void *frame, uint64_t requestBytes,
    uint64_t *replyBytes)
{
    DHLOGI("Render frame.");
    if (render == nullptr || frame == nullptr || requestBytes == 0 || replyBytes == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    const uint8_t *uframe = reinterpret_cast<const uint8_t *>(frame);
    std::vector<int8_t> frameHal(requestBytes);
    int32_t ret = memcpy_s(frameHal.data(), requestBytes, uframe, requestBytes);
    if (ret != EOK) {
        DHLOGE("Copy render frame failed, error code %d.", ret);
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    return context->proxy_->RenderFrame(frameHal, *replyBytes);
}

static int32_t GetRenderPositionInternal(struct AudioRender *render, uint64_t *frames,
    struct ::AudioTimeStamp *time)
{
    if (render == nullptr || frames == nullptr || time == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    AudioTimeStamp timeHal;
    int32_t ret = context->proxy_->GetRenderPosition(*frames, timeHal);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    time->tvSec = static_cast<int64_t>(timeHal.tvSec);
    time->tvNSec = static_cast<int64_t>(timeHal.tvNSec);
    return DH_SUCCESS;
}

static int32_t SetRenderSpeedInternal(struct AudioRender *render, float speed)
{
    if (render == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->SetRenderSpeed(speed);
}

static int32_t GetRenderSpeedInternal(struct AudioRender *render, float *speed)
{
    if (render == nullptr || speed == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->GetRenderSpeed(*speed);
}

static int32_t SetChannelModeInternal(struct AudioRender *render, enum ::AudioChannelMode mode)
{
    if (render == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->SetChannelMode(static_cast<AudioChannelMode>(mode));
}

static int32_t GetChannelModeInternal(struct AudioRender *render, enum ::AudioChannelMode *mode)
{
    if (render == nullptr || mode == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->GetChannelMode(*(reinterpret_cast<AudioChannelMode *>(mode)));
}

static int32_t RegCallbackInternal(struct AudioRender *render, ::RenderCallback callback, void *cookie)
{
    if (render == nullptr || callback == nullptr || cookie == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::lock_guard<std::mutex> lock(context->mtx_);
    if (context->callbackInternal_ == nullptr || callback != context->callback_) {
        context->callbackInternal_ = std::make_unique<AudioRenderCallbackContext>(callback, cookie);
    } else {
        return DH_SUCCESS;
    }

    if (context->callbackInternal_->callbackStub_ == nullptr) {
        context->callbackInternal_ = nullptr;
        return ERR_DH_AUDIO_HDI_CALL_FAILED;
    }
    int32_t ret = context->proxy_->RegCallback(context->callbackInternal_->callbackStub_, 0);
    if (ret == DH_SUCCESS) {
        context->callback_ = callback;
    } else {
        context->callbackInternal_ = nullptr;
    }
    return ret;
}

static int32_t DrainBufferInternal(struct AudioRender *render, enum ::AudioDrainNotifyType *type)
{
    if (render == nullptr || type == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_HDI_INVALID_PARAM;
    }

    AudioRenderContext *context = reinterpret_cast<AudioRenderContext *>(render);
    if (context->proxy_ == nullptr) {
        DHLOGE("The context or proxy for the context is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    return context->proxy_->DrainBuffer(*(reinterpret_cast<AudioDrainNotifyType *>(type)));
}

AudioRenderContext::AudioRenderContext()
{
    instance_.GetLatency = GetLatencyInternal;
    instance_.RenderFrame = RenderFrameInternal;
    instance_.GetRenderPosition = GetRenderPositionInternal;
    instance_.SetRenderSpeed = SetRenderSpeedInternal;
    instance_.GetRenderSpeed = GetRenderSpeedInternal;
    instance_.SetChannelMode = SetChannelModeInternal;
    instance_.GetChannelMode = GetChannelModeInternal;
    instance_.RegCallback = RegCallbackInternal;
    instance_.DrainBuffer = DrainBufferInternal;
    instance_.IsSupportsDrain = nullptr;

    instance_.control.Start = AudioControlInternal<AudioRenderContext>::Start;
    instance_.control.Stop = AudioControlInternal<AudioRenderContext>::Stop;
    instance_.control.Pause = AudioControlInternal<AudioRenderContext>::Pause;
    instance_.control.Resume = AudioControlInternal<AudioRenderContext>::Resume;
    instance_.control.Flush = AudioControlInternal<AudioRenderContext>::Flush;
    instance_.control.TurnStandbyMode = AudioControlInternal<AudioRenderContext>::TurnStandbyMode;
    instance_.control.AudioDevDump = AudioControlInternal<AudioRenderContext>::AudioDevDump;

    instance_.attr.GetFrameSize = AudioAttributeInternal<AudioRenderContext>::GetFrameSize;
    instance_.attr.GetFrameCount = AudioAttributeInternal<AudioRenderContext>::GetFrameCount;
    instance_.attr.SetSampleAttributes = AudioAttributeInternal<AudioRenderContext>::SetSampleAttributes;
    instance_.attr.GetSampleAttributes = AudioAttributeInternal<AudioRenderContext>::GetSampleAttributes;
    instance_.attr.GetCurrentChannelId = AudioAttributeInternal<AudioRenderContext>::GetCurrentChannelId;
    instance_.attr.SetExtraParams = AudioAttributeInternal<AudioRenderContext>::SetExtraParams;
    instance_.attr.GetExtraParams = AudioAttributeInternal<AudioRenderContext>::GetExtraParams;
    instance_.attr.ReqMmapBuffer = AudioAttributeInternal<AudioRenderContext>::ReqMmapBuffer;
    instance_.attr.GetMmapPosition = AudioAttributeInternal<AudioRenderContext>::GetMmapPosition;

    instance_.scene.SelectScene = AudioSceneInternal<AudioRenderContext>::SelectScene;
    instance_.scene.CheckSceneCapability = AudioSceneInternal<AudioRenderContext>::CheckSceneCapability;

    instance_.volume.SetMute = AudioVolumeInternal<AudioRenderContext>::SetMute;
    instance_.volume.GetMute = AudioVolumeInternal<AudioRenderContext>::GetMute;
    instance_.volume.SetVolume = AudioVolumeInternal<AudioRenderContext>::SetVolume;
    instance_.volume.GetVolume = AudioVolumeInternal<AudioRenderContext>::GetVolume;
    instance_.volume.GetGainThreshold = AudioVolumeInternal<AudioRenderContext>::GetGainThreshold;
    instance_.volume.SetGain = AudioVolumeInternal<AudioRenderContext>::SetGain;
    instance_.volume.GetGain = AudioVolumeInternal<AudioRenderContext>::GetGain;

    descHal_.portId = 0;
    descHal_.pins = PIN_NONE;
}

AudioRenderContext::~AudioRenderContext() {}
} // namespace DistributedHardware
} // namespace OHOS