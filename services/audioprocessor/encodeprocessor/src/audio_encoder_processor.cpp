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

#include "audio_encoder_processor.h"

#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "audio_encoder.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioEncoderProcessor"

namespace OHOS {
namespace DistributedHardware {
AudioEncoderProcessor::~AudioEncoderProcessor()
{
    if (audioEncoder_ != nullptr) {
        DHLOGD("Release audio processor.");
        StopAudioProcessor();
        ReleaseAudioProcessor();
    }
}

int32_t AudioEncoderProcessor::ConfigureAudioProcessor(const AudioCommonParam &localDevParam,
    const AudioCommonParam &remoteDevParam, const std::shared_ptr<IAudioProcessorCallback> &procCallback)
{
    DHLOGI("Configure audio processor.");
    if (procCallback == nullptr) {
        DHLOGE("Processor callback is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    localDevParam_ = localDevParam;
    remoteDevParam_ = remoteDevParam;
    procCallback_ = procCallback;

    audioEncoder_ = std::make_shared<AudioEncoder>();
    int32_t ret = audioEncoder_->ConfigureAudioCodec(localDevParam, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Configure encoder fail. Error code: %d.", ret);
        ReleaseAudioProcessor();
        return ret;
    }
    return DH_SUCCESS;
}

int32_t AudioEncoderProcessor::ReleaseAudioProcessor()
{
    DHLOGI("Release audio processor.");
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return DH_SUCCESS;
    }

    int32_t ret = audioEncoder_->ReleaseAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release encoder fail. Error code: %d.", ret);
    }

    audioEncoder_ = nullptr;
    return DH_SUCCESS;
}

int32_t AudioEncoderProcessor::StartAudioProcessor()
{
    DHLOGI("Start audio processor.");
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_BAD_VALUE,
            "daudio encoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    int32_t ret = audioEncoder_->StartAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start encoder fail. Error code: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio start encoder fail.");
        return ret;
    }

    return DH_SUCCESS;
}

int32_t AudioEncoderProcessor::StopAudioProcessor()
{
    DHLOGI("Stop audio processor.");
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_BAD_VALUE,
            "daudio encoder is null.");
        return DH_SUCCESS;
    }

    int32_t ret = audioEncoder_->StopAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop encoder fail. Error code: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio stop decoder fail.");
        return ret;
    }

    return DH_SUCCESS;
}

int32_t AudioEncoderProcessor::FeedAudioProcessor(const std::shared_ptr<AudioData> &inputData)
{
    DHLOGD("Feed audio processor.");
    if (inputData == nullptr) {
        DHLOGE("Input data is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    return audioEncoder_->FeedAudioData(inputData);
}

void AudioEncoderProcessor::OnCodecDataDone(const std::shared_ptr<AudioData> &outputData)
{
    if (outputData == nullptr) {
        DHLOGE("Output data is null.");
        return;
    }
    DHLOGD("Codec done. Output data size %zu.", outputData->Size());

    auto cbObj = procCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Processor callback is null.");
        return;
    }
    cbObj->OnAudioDataDone(outputData);
}

void AudioEncoderProcessor::OnCodecStateNotify(const AudioEvent &event)
{
    DHLOGD("Codec state notify.");
    auto cbObj = procCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Processor callback is null.");
        return;
    }
    cbObj->OnStateNotify(event);
}
} // namespace DistributedHardware
} // namespace OHOS