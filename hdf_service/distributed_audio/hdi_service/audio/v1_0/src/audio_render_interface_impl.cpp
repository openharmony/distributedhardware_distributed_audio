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

#include "audio_render_interface_impl.h"

#include <hdf_base.h>
#include <unistd.h>
#include "sys/time.h"

#include "daudio_constants.h"
#include "daudio_events.h"
#include "daudio_log.h"
#include "daudio_utils.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioRenderInterfaceImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
AudioRenderInterfaceImpl::AudioRenderInterfaceImpl(const std::string &adpName, const AudioDeviceDescriptor &desc,
    const AudioSampleAttributes &attrs, const sptr<IDAudioCallback> &callback)
    : AudioRenderInterfaceImplBase(desc), adapterName_(adpName), devDesc_(desc),
    devAttrs_(attrs), audioExtCallback_(callback)
{
    devAttrs_.frameSize = CalculateFrameSize(attrs.sampleRate, attrs.channelCount, attrs.format, timeInterval_, false);
    const int32_t sizePerSec = static_cast<int32_t>(attrs.sampleRate * attrs.channelCount) *attrs.format;
    framePeriodNs_ = (static_cast<int64_t>(devAttrs_.frameSize) * AUDIO_NS_PER_SECOND) /sizePerSec;
    DHLOGD("Distributed audio render constructed, period(%d), frameSize(%d), framePeriodNs_(%d).",
        attrs.period, devAttrs_.frameSize, framePeriodNs_);
}

AudioRenderInterfaceImpl::~AudioRenderInterfaceImpl()
{
    DHLOGD("Distributed audio render destructed, id(%d).", devDesc_.pins);
}

int32_t AudioRenderInterfaceImpl::GetLatency(uint32_t &ms)
{
    DHLOGI("Get render device latency, not support yet.");
    ms = 0;
    return HDF_SUCCESS;
}

float AudioRenderInterfaceImpl::GetFadeRate(uint32_t currentIndex, const uint32_t durationIndex)
{
    if (currentIndex > durationIndex) {
        return 1.0f;
    }

    float fadeRate = static_cast<float>(currentIndex) / durationIndex * DAUDIO_FADE_NORMALIZATION_FACTOR;
    if (fadeRate < 1) {
        return pow(fadeRate, DAUDIO_FADE_POWER_NUM) / DAUDIO_FADE_NORMALIZATION_FACTOR;
    }
    return -pow(fadeRate - DAUDIO_FADE_MAXIMUM_VALUE, DAUDIO_FADE_POWER_NUM) /
        DAUDIO_FADE_NORMALIZATION_FACTOR + 1;
}

int32_t AudioRenderInterfaceImpl::FadeInProcess(const uint32_t durationFrame,
    int8_t* frameData, const size_t frameLength)
{
    int16_t* frame = reinterpret_cast<int16_t *>(frameData);
    const size_t newFrameLength = frameLength / 2;

    for (size_t k = 0; k < newFrameLength; ++k) {
        float rate = GetFadeRate(currentFrame_ * newFrameLength + k, durationFrame * newFrameLength);
        frame[k] = currentFrame_ == durationFrame - 1 ? frame[k] : static_cast<int16_t>(rate * frame[k]);
    }
    DHLOGI("Fade-in frame[currentFrame: %d].", currentFrame_);
    ++currentFrame_;
    currentFrame_ = currentFrame_ >= durationFrame ? durationFrame - 1 : currentFrame_;

    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::RenderFrame(const std::vector<int8_t> &frame, uint64_t &replyBytes)
{
    DHLOGI("Render frame[sampleRate: %d, channelCount: %d, format: %d, frameSize: %d].", devAttrs_.sampleRate,
        devAttrs_.channelCount, devAttrs_.format, devAttrs_.frameSize);
    int64_t timeOffset = UpdateTimeOffset(frameIndex_, framePeriodNs_, AUDIO_OFFSET_FRAME_NUM, startTime_);
    DHLOGD("Render frameIndex: %lld, timeOffset: %lld.", frameIndex_, timeOffset);

    std::lock_guard<std::mutex> renderLck(renderMtx_);
    if (renderStatus_ != RENDER_STATUS_START) {
        DHLOGE("Render status wrong, return false.");
        return HDF_FAILURE;
    }

    AudioParameter param = { devAttrs_.format, devAttrs_.channelCount, devAttrs_.sampleRate, 0, devAttrs_.frameSize};
    AudioData data = { param, frame };
    FadeInProcess(DURATION_FRAMES, data.data.data(), frame.size());
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    int32_t ret = audioExtCallback_->WriteStreamData(adapterName_, devDesc_.pins, data);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Write stream data failed.");
        return HDF_FAILURE;
    }

    ++frameIndex_;
    AbsoluteSleep(startTime_ + frameIndex_ * framePeriodNs_ - timeOffset);
    DHLOGD("Render audio frame success.");
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetRenderPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get render position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetRenderSpeed(float speed)
{
    DHLOGI("Set render speed, control render speed is not support yet.");
    renderSpeed_ = speed;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetRenderSpeed(float &speed)
{
    DHLOGI("Get render speed, control render speed is not support yet.");
    speed = renderSpeed_;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetChannelMode(AudioChannelMode mode)
{
    DHLOGI("Set channel mode, control channel mode is not support yet.");
    channelMode_ = mode;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetChannelMode(AudioChannelMode &mode)
{
    DHLOGI("Get channel mode, control channel mode is not support yet.");
    mode = channelMode_;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::RegCallback(const sptr<IAudioCallback> &audioCallback, int8_t cookie)
{
    DHLOGI("Register render callback.");
    (void)cookie;
    renderCallback_ = audioCallback;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::DrainBuffer(AudioDrainNotifyType &type)
{
    DHLOGI("Drain audio buffer, not support yet.");
    (void)type;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::IsSupportsDrain(bool &support)
{
    DHLOGI("Check whether drain is supported, not support yet.");
    (void)support;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::Start()
{
    DHLOGI("Start render.");
    if (firstOpenFlag) {
        firstOpenFlag = false;
    } else {
        DAudioEvent event = { HDF_AUDIO_EVENT_CHANGE_PLAY_STATUS, HDF_EVENT_RESTART };
        int32_t ret = audioExtCallback_->NotifyEvent(adapterName_, devDesc_.pins, event);
        if (ret != HDF_SUCCESS) {
            DHLOGE("Restart failed.");
        }
    }
    std::lock_guard<std::mutex> renderLck(renderMtx_);
    renderStatus_ = RENDER_STATUS_START;
    currentFrame_ = CUR_FRAME_INIT_VALUE;
    frameIndex_ = 0;
    startTime_ = 0;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::Stop()
{
    DHLOGI("Stop render.");
    DAudioEvent event = { HDF_AUDIO_EVENT_CHANGE_PLAY_STATUS, HDF_EVENT_PAUSE };
    int32_t ret = audioExtCallback_->NotifyEvent(adapterName_, devDesc_.pins, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Pause and clear cache streams failed.");
    }
    std::lock_guard<std::mutex> renderLck(renderMtx_);
    renderStatus_ = RENDER_STATUS_STOP;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::Pause()
{
    DHLOGI("Pause render.");
    std::lock_guard<std::mutex> renderLck(renderMtx_);
    renderStatus_ = RENDER_STATUS_PAUSE;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::Resume()
{
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::Flush()
{
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::TurnStandbyMode()
{
    DHLOGI("Turn stand by mode, not support yet.");
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::AudioDevDump(int32_t range, int32_t fd)
{
    DHLOGI("Dump audio info, not support yet.");
    (void)range;
    (void)fd;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::IsSupportsPauseAndResume(bool &supportPause, bool &supportResume)
{
    DHLOGI("Check whether pause and resume is supported, not support yet.");
    (void)supportPause;
    (void)supportResume;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported)
{
    DHLOGI("Check scene capability.");
    (void)scene;
    (void)supported;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SelectScene(const AudioSceneDescriptor &scene)
{
    DHLOGI("Select audio scene, not support yet.");
    (void)scene;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetMute(bool mute)
{
    DHLOGI("Set mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetMute(bool &mute)
{
    DHLOGI("Get mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetVolume(float volume)
{
    DHLOGI("Can not set vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetVolume(float &volume)
{
    DHLOGI("Can not get vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetGainThreshold(float &min, float &max)
{
    DHLOGI("Get gain threshold, not support yet.");
    min = 0;
    max = 0;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetGain(float gain)
{
    DHLOGI("Set gain, not support yet.");
    (void)gain;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetGain(float &gain)
{
    DHLOGI("Get gain, not support yet.");
    gain = 1.0;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetFrameSize(uint64_t &size)
{
    (void)size;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetFrameCount(uint64_t &count)
{
    (void)count;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetSampleAttributes(const AudioSampleAttributes &attrs)
{
    DHLOGI("Set sample attributes.");
    devAttrs_ = attrs;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetSampleAttributes(AudioSampleAttributes &attrs)
{
    DHLOGI("Get sample attributes.");
    attrs = devAttrs_;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetCurrentChannelId(uint32_t &channelId)
{
    DHLOGI("Get current channel id, not support yet.");
    (void)channelId;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::SetExtraParams(const std::string &keyValueList)
{
    DHLOGI("Set extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetExtraParams(std::string &keyValueList)
{
    DHLOGI("Get extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc)
{
    DHLOGI("Request mmap buffer, not support yet.");
    (void)reqSize;
    (void)desc;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetMmapPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get mmap position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::AddAudioEffect(uint64_t effectid)
{
    DHLOGI("Add audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::RemoveAudioEffect(uint64_t effectid)
{
    DHLOGI("Remove audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioRenderInterfaceImpl::GetFrameBufferSize(uint64_t &bufferSize)
{
    DHLOGI("Get frame buffer size, not support yet.");
    (void)bufferSize;
    return HDF_SUCCESS;
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS
