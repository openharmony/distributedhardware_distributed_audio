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

#include "audio_decoder_processor.h"

#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "audio_decoder.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDecoderProcessor"

namespace OHOS {
namespace DistributedHardware {
AudioDecoderProcessor::~AudioDecoderProcessor()
{
    if (audioDecoder_ != nullptr) {
        DHLOGI("Release audio processor.");
        StopAudioProcessor();
        ReleaseAudioProcessor();
    }
}

int32_t AudioDecoderProcessor::ConfigureAudioProcessor(const AudioCommonParam &localDevParam,
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

    audioDecoder_ = std::make_shared<AudioDecoder>();
    int32_t ret = audioDecoder_->ConfigureAudioCodec(localDevParam, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Configure decoder fail. Error code: %d.", ret);
        ReleaseAudioProcessor();
        return ret;
    }
    return DH_SUCCESS;
}

int32_t AudioDecoderProcessor::ReleaseAudioProcessor()
{
    DHLOGI("Release audio processor.");
    if (audioDecoder_ == nullptr) {
        DHLOGE("Decoder is null.");
        return DH_SUCCESS;
    }

    int32_t ret = audioDecoder_->ReleaseAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release decoder fail. Error code: %d.", ret);
    }

    audioDecoder_ = nullptr;
    return DH_SUCCESS;
}

int32_t AudioDecoderProcessor::StartAudioProcessor()
{
    DHLOGI("Start audio processor.");
    if (audioDecoder_ == nullptr) {
        DHLOGE("Decoder is null.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_BAD_VALUE,
            "daudio decoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    int32_t ret = audioDecoder_->StartAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Start decoder fail. Error code: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio start decoder fail.");
        return ret;
    }

    DHLOGI("Start audio processor success.");
    return DH_SUCCESS;
}

int32_t AudioDecoderProcessor::StopAudioProcessor()
{
    DHLOGI("Stop audio processor.");
    if (audioDecoder_ == nullptr) {
        DHLOGE("Decoder is null.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_BAD_VALUE,
            "daudio decoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    int32_t ret = audioDecoder_->StopAudioCodec();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop decoder fail. Error code: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio stop decoder fail.");
        return ret;
    }

    return DH_SUCCESS;
}

int32_t AudioDecoderProcessor::FeedAudioProcessor(const std::shared_ptr<AudioData> &inputData)
{
    DHLOGD("Feed audio processor.");
    if (inputData == nullptr) {
        DHLOGE("Input data is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    if (audioDecoder_ == nullptr) {
        DHLOGE("Decoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    return audioDecoder_->FeedAudioData(inputData);
}

void AudioDecoderProcessor::OnCodecDataDone(const std::shared_ptr<AudioData> &outputData)
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

void AudioDecoderProcessor::OnCodecStateNotify(const AudioEvent &event)
{
    DHLOGI("Codec state notify.");
    auto cbObj = procCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Processor callback is null.");
        return;
    }
    cbObj->OnStateNotify(event);
}
} // namespace DistributedHardware
} // namespace OHOS