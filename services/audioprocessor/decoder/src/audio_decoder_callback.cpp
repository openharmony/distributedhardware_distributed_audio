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

#include "audio_decoder_callback.h"

#include "daudio_log.h"
#include "audio_event.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDecoderCallback"

namespace OHOS {
namespace DistributedHardware {
void AudioDecoderCallback::OnError(Media::AVCodecErrorType errorType, int32_t errorCode)
{
    DHLOGE("On error. Error type: %d, Error code: %d ", errorType, errorCode);
    std::shared_ptr<AudioDecoder> decObj = audioDecoder_.lock();
    if (decObj == nullptr) {
        DHLOGE("Decoder is nullptr.");
        return;
    }
    AudioEvent decoderErr = {AUDIO_DECODER_ERR, ""};
    decObj->OnError(decoderErr);
}

void AudioDecoderCallback::OnInputBufferAvailable(uint32_t index)
{
    DHLOGD("On input buffer available. index %u.", index);
    std::shared_ptr<AudioDecoder> decObj = audioDecoder_.lock();
    if (decObj == nullptr) {
        DHLOGE("Decoder is nullptr.");
        return;
    }
    decObj->OnInputBufferAvailable(index);
}

void AudioDecoderCallback::OnOutputFormatChanged(const Media::Format &format)
{
    DHLOGD("On output format changed.");
    std::shared_ptr<AudioDecoder> decObj = audioDecoder_.lock();
    if (decObj == nullptr) {
        DHLOGE("Decoder is nullptr.");
        return;
    }
    decObj->OnOutputFormatChanged(format);
}

void AudioDecoderCallback::OnOutputBufferAvailable(uint32_t index, Media::AVCodecBufferInfo info,
    Media::AVCodecBufferFlag flag)
{
    DHLOGD("On output buffer available. index %u.", index);
    std::shared_ptr<AudioDecoder> decObj = audioDecoder_.lock();
    if (decObj == nullptr) {
        DHLOGE("Decoder is nullptr.");
        return;
    }
    decObj->OnOutputBufferAvailable(index, info, flag);
}
} // namespace DistributedHardware
} // namespace OHOS
