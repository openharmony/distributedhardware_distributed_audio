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

#include "audio_encoder.h"

#include "audio_info.h"
#include "avsharedmemory.h"
#include "media_errors.h"
#include "securec.h"

#include "audio_encoder_callback.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioEncoder"

namespace OHOS {
namespace DistributedHardware {
const std::string AudioEncoder::ENCODE_MIME_AAC = "audio/mp4a-latm";

AudioEncoder::~AudioEncoder()
{
    if (audioEncoder_ != nullptr) {
        DHLOGD("Release audio codec.");
        StopAudioCodec();
        ReleaseAudioCodec();
    }
}

int32_t AudioEncoder::ConfigureAudioCodec(const AudioCommonParam &codecParam,
    const std::shared_ptr<IAudioCodecCallback> &codecCallback)
{
    DHLOGD("Configure audio codec.");
    if (!IsInEncodeRange(codecParam) || codecCallback == nullptr) {
        DHLOGE("Codec param error or callback is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    codecParam_ = codecParam;
    codecCallback_ = codecCallback;

    int32_t ret = InitAudioEncoder(codecParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Init audio encoder fail. Error code %d.", ret);
        return ret;
    }

    ret = SetEncoderFormat(codecParam);
    if (ret != DH_SUCCESS) {
        DHLOGE("Set encoder format fail. Error code %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

bool AudioEncoder::IsInEncodeRange(const AudioCommonParam &codecParam)
{
    if (codecParam.channelMask >= CHANNEL_MASK_MIN && codecParam.channelMask <= CHANNEL_MASK_MAX &&
        codecParam.sampleRate >= SAMPLE_RATE_MIN && codecParam.sampleRate <= SAMPLE_RATE_MAX &&
        codecParam.bitFormat == SAMPLE_S16LE && codecParam.codecType == AUDIO_CODEC_AAC) {
        return true;
    }

    DHLOGE("Param error, codec type %d, channel count %d, sample rate %d, sample format %d.",
        codecParam.codecType, codecParam.channelMask, codecParam.sampleRate, codecParam.bitFormat);
    return false;
}

int32_t AudioEncoder::InitAudioEncoder(const AudioCommonParam &codecParam)
{
    DHLOGI("Init audio encoder.");
    audioEncoder_ = Media::AudioEncoderFactory::CreateByMime(ENCODE_MIME_AAC);
    if (audioEncoder_ == nullptr) {
        DHLOGE("Create audio encoder fail.");
        return ERR_DH_AUDIO_CODEC_CONFIG;
    }

    encoderCallback_ = std::make_shared<AudioEncoderCallback>(shared_from_this());
    int32_t ret = audioEncoder_->SetCallback(encoderCallback_);
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Set encoder callback fail. Error code %d.", ret);
        encoderCallback_ = nullptr;
        return ERR_DH_AUDIO_CODEC_CONFIG;
    }
    return DH_SUCCESS;
}

int32_t AudioEncoder::SetEncoderFormat(const AudioCommonParam &codecParam)
{
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    DHLOGI("Set encoder format, codec type %d, channel count %d, sample rate %d, sample format %d.",
        codecParam.codecType, codecParam.channelMask, codecParam.sampleRate, codecParam.bitFormat);
    cfgFormat_.PutIntValue("channel_count", codecParam.channelMask);
    cfgFormat_.PutIntValue("sample_rate", codecParam.sampleRate);
    cfgFormat_.PutIntValue("audio_sample_format",
        static_cast<AudioStandard::AudioSampleFormat>(codecParam.bitFormat));

    int32_t ret = audioEncoder_->Configure(cfgFormat_);
    if (ret != Media::MSERR_OK) {
        DHLOGE("Configure encoder format fail. Error code %d.", ret);
        return ERR_DH_AUDIO_CODEC_CONFIG;
    }

    ret = audioEncoder_->Prepare();
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Encoder prepare fail. Error code %d.", ret);
        return ERR_DH_AUDIO_CODEC_CONFIG;
    }
    return DH_SUCCESS;
}

int32_t AudioEncoder::ReleaseAudioCodec()
{
    DHLOGI("Release audio codec.");
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return DH_SUCCESS;
    }

    int32_t ret = audioEncoder_->Release();
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Encoder release fail. Error type: %d.", ret);
        return ERR_DH_AUDIO_CODEC_RELEASE;
    }
    encoderCallback_ = nullptr;
    audioEncoder_ = nullptr;
    DHLOGI("Release audio codec end.");
    return DH_SUCCESS;
}

int32_t AudioEncoder::StartAudioCodec()
{
    DHLOGI("Start audio codec.");
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    int32_t ret = audioEncoder_->Start();
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Encoder start fail. Error code %d.", ret);
        return ERR_DH_AUDIO_CODEC_START;
    }
    StartInputThread();
    return DH_SUCCESS;
}

void AudioEncoder::StartInputThread()
{
    DHLOGI("Start input thread.");
    isEncoderRunning_.store(true);
    encodeThread_ = std::thread(&AudioEncoder::InputEncodeAudioData, this);
    if (pthread_setname_np(encodeThread_.native_handle(), ENCODE_THREAD) != DH_SUCCESS) {
        DHLOGE("Encode thread setname failed.");
    }
}

int32_t AudioEncoder::StopAudioCodec()
{
    DHLOGI("Stop audio codec.");
    StopInputThread();
    if (audioEncoder_ == nullptr) {
        DHLOGE("Encoder is null.");
        return DH_SUCCESS;
    }

    bool isSuccess = true;
    int32_t ret = audioEncoder_->Flush();
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Encoder flush fail. Error type: %d.", ret);
        isSuccess = false;
    }
    ret = audioEncoder_->Stop();
    if (ret != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Encoder stop fail. Error type: %d.", ret);
        isSuccess = false;
    }
    if (!isSuccess) {
        return ERR_DH_AUDIO_CODEC_STOP;
    }

    firstInputTimeUs_ = 0;
    inputTimeStampUs_ = 0;
    outputTimeStampUs_ = 0;
    waitOutputCount_ = 0;
    DHLOGI("Stop audio codec end.");
    return DH_SUCCESS;
}

void AudioEncoder::StopInputThread()
{
    isEncoderRunning_.store(false);
    encodeCond_.notify_all();
    if (encodeThread_.joinable()) {
        encodeThread_.join();
    }

    std::lock_guard<std::mutex> dataLock(mtxData_);
    std::queue<uint32_t>().swap(bufIndexQueue_);
    std::queue<std::shared_ptr<AudioData>>().swap(inputBufQueue_);
    DHLOGI("Stop input thread success.");
}

int32_t AudioEncoder::FeedAudioData(const std::shared_ptr<AudioData> &inputData)
{
    DHLOGD("Feed audio data.");
    if (!isEncoderRunning_.load()) {
        DHLOGE("Encoder is stopped.");
        return ERR_DH_AUDIO_CODEC_INPUT;
    }
    if (inputData == nullptr) {
        DHLOGE("Input data is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    std::lock_guard<std::mutex> dataLock(mtxData_);
    while (inputBufQueue_.size() > AUDIO_ENCODER_QUEUE_MAX) {
        DHLOGE("Input data queue overflow.");
        inputBufQueue_.pop();
    }
    inputBufQueue_.push(inputData);
    encodeCond_.notify_all();

    return DH_SUCCESS;
}

void AudioEncoder::InputEncodeAudioData()
{
    DHLOGI("Input encode audio data thread start.");
    while (isEncoderRunning_.load()) {
        std::shared_ptr<AudioData> audioData;
        int32_t bufferIndex = 0;
        {
            std::unique_lock<std::mutex> lock(mtxData_);
            encodeCond_.wait_for(lock, std::chrono::milliseconds(ENCODE_WAIT_MILLISECONDS),
                [this]() {
                    return (!inputBufQueue_.empty() && !bufIndexQueue_.empty()) || !isEncoderRunning_.load();
                });

            if (inputBufQueue_.empty() || bufIndexQueue_.empty()) {
                continue;
            }
            bufferIndex = (int32_t)bufIndexQueue_.front();
            bufIndexQueue_.pop();
            audioData = inputBufQueue_.front();
            inputBufQueue_.pop();
        }

        int32_t ret = ProcessData(audioData, bufferIndex);
        if (ret == ERR_DH_AUDIO_BAD_VALUE) {
            DHLOGE("Encoder is stopped or null.");
            return;
        } else if (ret != DH_SUCCESS) {
            DHLOGE("Process data fail. Error type: %d.", ret);
            continue;
        }
    }
}

int32_t AudioEncoder::ProcessData(const std::shared_ptr<AudioData> &audioData, const int32_t bufferIndex)
{
    if (!isEncoderRunning_.load() || audioEncoder_ == nullptr) {
        DHLOGE("Encoder is stopped or null, isRunning %d.", isEncoderRunning_.load());
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    auto inMem = audioEncoder_->GetInputBuffer(bufferIndex);
    if (inMem == nullptr) {
        DHLOGE("Get input buffer fail.");
        return ERR_DH_AUDIO_CODEC_INPUT;
    }
    if (inMem->GetSize() == INVALID_MEMORY_SIZE || static_cast<size_t>(inMem->GetSize()) < audioData->Size()) {
        DHLOGE("Input buffer size error. Memory size %d, data size %zu.",
            inMem->GetSize(), audioData->Size());
        return ERR_DH_AUDIO_CODEC_INPUT;
    }

    errno_t err = memcpy_s(inMem->GetBase(), inMem->GetSize(), audioData->Data(), audioData->Size());
    if (err != EOK) {
        DHLOGE("Copy input data fail. Error code %d. Memory size %d, data size %zu.",
            err, inMem->GetSize(), audioData->Size());
        return ERR_DH_AUDIO_BAD_OPERATE;
    }

    inputTimeStampUs_ = GetEncoderTimeStamp();
    Media::AVCodecBufferInfo bufferInfo = {inputTimeStampUs_, static_cast<int32_t>(audioData->Size()), 0};
    DHLOGD("Queue input buffer. AVCodec info: input time stamp %lld, data size %zu.",
        (long long)bufferInfo.presentationTimeUs, audioData->Size());
    int32_t ret = audioEncoder_->QueueInputBuffer(bufferIndex, bufferInfo, Media::AVCODEC_BUFFER_FLAG_NONE);
    if (ret != Media::MSERR_OK) {
        DHLOGE("Queue input buffer fail. Error code %d.", ret);
        return ERR_DH_AUDIO_CODEC_INPUT;
    }

    IncreaseWaitEncodeCnt();
    return DH_SUCCESS;
}

int64_t AudioEncoder::GetEncoderTimeStamp()
{
    int64_t TimeIntervalStampUs = 0;
    int64_t nowTimeUs = GetNowTimeUs();
    if (firstInputTimeUs_ == 0) {
        firstInputTimeUs_ = nowTimeUs;
        return TimeIntervalStampUs;
    }

    TimeIntervalStampUs = nowTimeUs - firstInputTimeUs_;
    return TimeIntervalStampUs;
}

void AudioEncoder::IncreaseWaitEncodeCnt()
{
    std::lock_guard<std::mutex> lck(mtxCnt_);
    waitOutputCount_++;
    DHLOGD("Wait encoder output frames number is %d.", waitOutputCount_);
}

void AudioEncoder::ReduceWaitEncodeCnt()
{
    std::lock_guard<std::mutex> lck(mtxCnt_);
    if (waitOutputCount_ <= 0) {
        DHLOGE("Wait encoder output count %d.", waitOutputCount_);
    }
    waitOutputCount_--;
    DHLOGD("Wait encoder output frames number is %d.", waitOutputCount_);
}

void AudioEncoder::OnInputBufferAvailable(uint32_t index)
{
    std::lock_guard<std::mutex> lck(mtxData_);
    while (bufIndexQueue_.size() > AUDIO_ENCODER_QUEUE_MAX) {
        DHLOGE("Index queue overflow.");
        bufIndexQueue_.pop();
    }

    bufIndexQueue_.push(index);
    encodeCond_.notify_all();
}

void AudioEncoder::OnOutputBufferAvailable(uint32_t index, Media::AVCodecBufferInfo info,
    Media::AVCodecBufferFlag flag)
{
    if (!isEncoderRunning_.load() || audioEncoder_ == nullptr) {
        DHLOGE("Encoder is stopped or null, isRunning %d.", isEncoderRunning_.load());
        return;
    }

    auto outMem = audioEncoder_->GetOutputBuffer(index);
    if (outMem == nullptr) {
        DHLOGE("Get output buffer fail. index %u.", index);
        return;
    }
    if (info.size <= 0 || info.size > outMem->GetSize()) {
        DHLOGE("Codec output info error. AVCodec info: size %d, memory size %d.",
            info.size, outMem->GetSize());
        return;
    }

    auto outBuf = std::make_shared<AudioData>(static_cast<size_t>(info.size));
    errno_t err = memcpy_s(outBuf->Data(), outBuf->Size(), outMem->GetBase(), info.size);
    if (err != EOK) {
        DHLOGE("Copy output data fail. Error code %d. Output Buffer Size %zu, AVCodec info: size %d.",
            err, outBuf->Size(), info.size);
        return;
    }
    outBuf->SetInt64("timeUs", info.presentationTimeUs);
    outputTimeStampUs_ = info.presentationTimeUs;
    DHLOGD("Get output buffer. AVCodec info: output time stamp %lld, data size %zu.",
        (long long)info.presentationTimeUs, outBuf->Size());

    ReduceWaitEncodeCnt();
    err = EncodeDone(outBuf);
    if (err != DH_SUCCESS) {
        DHLOGE("Encode done fail. Error code: %d.", err);
        return;
    }

    err = audioEncoder_->ReleaseOutputBuffer(index);
    if (err != Media::MediaServiceErrCode::MSERR_OK) {
        DHLOGE("Release output buffer fail. Error code: %d, index %u.", err, index);
    }
}

void AudioEncoder::OnOutputFormatChanged(const Media::Format &format)
{
    if (format.GetFormatMap().empty()) {
        DHLOGE("The first changed output data format is null.");
        return;
    }
    outputFormat_ = format;
}

void AudioEncoder::OnError(const AudioEvent &event)
{
    DHLOGE("Encoder error.");
    std::shared_ptr<IAudioCodecCallback> cbObj = codecCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Codec callback is null.");
        return;
    }
    cbObj->OnCodecStateNotify(event);
}

int32_t AudioEncoder::EncodeDone(const std::shared_ptr<AudioData> &outputData)
{
    DHLOGD("Encode done.");
    std::shared_ptr<IAudioCodecCallback> cbObj = codecCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Codec callback is null.");
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    cbObj->OnCodecDataDone(outputData);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
