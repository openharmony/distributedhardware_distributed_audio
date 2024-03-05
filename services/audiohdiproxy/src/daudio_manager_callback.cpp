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

#include "daudio_manager_callback.h"

#include <cstdint>
#include <hdf_base.h>
#include <securec.h>

#include "audio_types.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioManagerCallback"

using OHOS::HDI::DistributedAudio::Audioext::V1_0::AudioParameter;

namespace OHOS {
namespace DistributedHardware {
int32_t DAudioManagerCallback::OpenDevice(const std::string& adpName, int32_t devId)
{
    DHLOGI("Open device.");
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->OpenDevice(adpName, devId) != DH_SUCCESS) {
        DHLOGE("Call hdi callback failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::CloseDevice(const std::string& adpName, int32_t devId)
{
    DHLOGI("Close device.");
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->CloseDevice(adpName, devId) != DH_SUCCESS) {
        DHLOGE("Rall hdi callback failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::GetAudioParamHDF(const AudioParameter& param, AudioParamHDF& paramHDF)
{
    paramHDF.sampleRate = static_cast<AudioSampleRate>(param.sampleRate);
    paramHDF.channelMask = static_cast<AudioChannel>(param.channelCount);
    switch (static_cast<AudioFormat>(param.format)) {
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            paramHDF.bitFormat = AudioSampleFormat::SAMPLE_U8;
            break;
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            paramHDF.bitFormat = AudioSampleFormat::SAMPLE_S16LE;
            break;
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
            paramHDF.bitFormat = AudioSampleFormat::SAMPLE_S24LE;
            break;
        default:
            DHLOGE("Format [%" PRIu32"] does not support conversion.", param.format);
            return HDF_FAILURE;
    }
    switch (static_cast<AudioCategory>(param.streamUsage)) {
        case AUDIO_IN_MEDIA:
            paramHDF.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
            break;
        case AUDIO_IN_COMMUNICATION:
            paramHDF.streamUsage = StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
            break;
        case AUDIO_IN_RINGTONE:
            paramHDF.streamUsage = StreamUsage::STREAM_USAGE_NOTIFICATION_RINGTONE;
            break;
        case AUDIO_MMAP_NOIRQ:
            paramHDF.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
            break;
        default:
            DHLOGE("Stream usage [%" PRIu32"] does not support conversion.", param.streamUsage);
            return HDF_FAILURE;
    }
    paramHDF.frameSize = param.frameSize;
    paramHDF.period = param.period;
    paramHDF.ext = param.ext;
    paramHDF.renderFlags = static_cast<OHOS::DistributedHardware::PortOperationMode>(param.renderFlags);
    paramHDF.capturerFlags = static_cast<OHOS::DistributedHardware::PortOperationMode>(param.capturerFlags);
    DHLOGI("HDF Param: sample rate %d, channel %d, bit format %d, stream usage %d, frame size %" PRIu32
        ", period %" PRIu32", renderFlags %d, capturerFlags %d, ext {%s}.", paramHDF.sampleRate, paramHDF.channelMask,
        paramHDF.bitFormat, paramHDF.streamUsage, paramHDF.frameSize, paramHDF.period, paramHDF.renderFlags,
        paramHDF.capturerFlags, paramHDF.ext.c_str());
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::SetParameters(const std::string& adpName, int32_t devId, const AudioParameter& param)
{
    DHLOGD("Set Parameters.");
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    AudioParamHDF paramHDF;
    int32_t ret = GetAudioParamHDF(param, paramHDF);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio HDF param failed.");
        return HDF_FAILURE;
    }
    ret = callback_->SetParameters(adpName, devId, paramHDF);
    if (ret != DH_SUCCESS) {
        DHLOGE("Call hdi callback failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::NotifyEvent(const std::string& adpName, int32_t devId,
    const OHOS::HDI::DistributedAudio::Audioext::V1_0::DAudioEvent& event)
{
    DHLOGI("Notify event.");
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    AudioEvent newEvent(AudioEventType::EVENT_UNKNOWN, event.content);
    switch (event.type) {
        case AudioEventHDF::AUDIO_EVENT_VOLUME_SET:
            newEvent.type = AudioEventType::VOLUME_SET;
            break;
        case AudioEventHDF::AUDIO_EVENT_MUTE_SET:
            newEvent.type = AudioEventType::VOLUME_MUTE_SET;
            break;
        case AudioEventHDF::AUDIO_EVENT_CHANGE_PLAY_STATUS:
            newEvent.type = AudioEventType::CHANGE_PLAY_STATUS;
            break;
        case AudioEventHDF::AUDIO_EVENT_MMAP_START_SPK:
            newEvent.type = AudioEventType::MMAP_SPK_START;
            break;
        case AudioEventHDF::AUDIO_EVENT_MMAP_STOP_SPK:
            newEvent.type = AudioEventType::MMAP_SPK_STOP;
            break;
        case AudioEventHDF::AUDIO_EVENT_MMAP_START_MIC:
            newEvent.type = AudioEventType::MMAP_MIC_START;
            break;
        case AudioEventHDF::AUDIO_EVENT_MMAP_STOP_MIC:
            newEvent.type = AudioEventType::MMAP_MIC_STOP;
            break;
        case AudioEventHDF::AUDIO_EVENT_START:
            newEvent.type = AudioEventType::AUDIO_START;
            break;
        case AudioEventHDF::AUDIO_EVENT_STOP:
            newEvent.type = AudioEventType::AUDIO_STOP;
            break;
        default:
            DHLOGE("Unsupport event tpye.");
            break;
    }

    int32_t ret = callback_->NotifyEvent(adpName, devId, newEvent);
    if (ret != DH_SUCCESS) {
        DHLOGE("Call hdi callback failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::WriteStreamData(const std::string &adpName, int32_t devId,
    const OHOS::HDI::DistributedAudio::Audioext::V1_0::AudioData &data)
{
    DHLOGD("Write Stream Data, audio data param frameSize is %d.", data.param.frameSize);
    if (data.param.frameSize == 0 || data.param.frameSize > DEFAULT_AUDIO_DATA_SIZE) {
        DHLOGE("Audio data param frameSize is 0. or > 4096");
        return HDF_FAILURE;
    }

    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(data.param.frameSize);
    int32_t ret = memcpy_s(audioData->Data(), audioData->Capacity(), data.data.data(), data.data.size());
    if (ret != EOK) {
        DHLOGE("Copy audio data failed, error code %d.", ret);
        return HDF_FAILURE;
    }

    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->WriteStreamData(adpName, devId, audioData) != DH_SUCCESS) {
        DHLOGE("WriteStreamData failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::ReadStreamData(const std::string &adpName, int32_t devId,
    OHOS::HDI::DistributedAudio::Audioext::V1_0::AudioData &data)
{
    DHLOGD("Read stream data.");
    std::shared_ptr<AudioData> audioData = nullptr;
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->ReadStreamData(adpName, devId, audioData) != DH_SUCCESS) {
        DHLOGE("Read stream data failed.");
        return HDF_FAILURE;
    }

    CHECK_NULL_RETURN(audioData, HDF_FAILURE);
    data.data.assign(audioData->Data(), audioData->Data()+audioData->Capacity());
    DHLOGD("Read stream data success.");
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::ReadMmapPosition(const std::string &adpName, int32_t devId,
    uint64_t &frames, OHOS::HDI::DistributedAudio::Audioext::V1_0::CurrentTime &time)
{
    DHLOGD("Read mmap position");
    CurrentTimeHDF timeHdf;
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->ReadMmapPosition(adpName, devId, frames, timeHdf) != DH_SUCCESS) {
        DHLOGE("Read mmap position failed.");
        return HDF_FAILURE;
    }
    time.tvSec = timeHdf.tvSec;
    time.tvNSec = timeHdf.tvNSec;
    DHLOGD("Read mmap position success.");
    return HDF_SUCCESS;
}

int32_t DAudioManagerCallback::RefreshAshmemInfo(const std::string &adpName, int32_t devId,
    int fd, int32_t ashmemLength, int32_t lengthPerTrans)
{
    DHLOGD("Refresh ashmem info.");
    CHECK_NULL_RETURN(callback_, HDF_FAILURE);
    if (callback_->RefreshAshmemInfo(adpName, devId, fd, ashmemLength, lengthPerTrans) != DH_SUCCESS) {
        DHLOGE("Refresh ashmem info failed.");
        return HDF_FAILURE;
    }
    DHLOGD("Refresh ashmem info success.");
    return HDF_SUCCESS;
}
} // DistributedHardware
} // OHOS
