/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "daudio_echo_cannel_manager.h"

#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#include <securec.h>

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioEchoCannelManager"

using namespace OHOS::AudioStandard;
namespace OHOS {
namespace DistributedHardware {
using AecEffectProcessorProvider = AecEffector *(*)();

const std::string ECHOCANNEL_SO_NAME = "libdaudio_aec_effect_processor.z.so";
const std::string GET_AEC_EFFECT_PROCESSOR_FUNC = "GetAecEffector";
const int32_t FRAME_SIZE_NORMAL = 3840;

DAudioEchoCannelManager::DAudioEchoCannelManager()
{
    DHLOGD("Distributed audio echo cannel manager constructed.");
}

DAudioEchoCannelManager::~DAudioEchoCannelManager()
{
    DHLOGD("Distributed audio echo cannel manager destructed.");
}

int32_t DAudioEchoCannelManager::SetUp(const AudioCommonParam param,
    const std::shared_ptr<IAudioDataTransCallback> &callback)
{
    (void) param;
    devCallback_ = callback;
    DHLOGI("SetUp EchoCannel.");

    if (!isCircuitStartRunning_.load()) {
        isCircuitStartRunning_.store(true);
        circuitStartThread_ = std::thread([this]() { this->CircuitStart(); });
        circuitStartThread_.detach();
        DHLOGI("circuitStartThread_ is on.");
    }
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_AEC_REFERENCE_FILENAME, &dumpFileRef_);
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_AEC_RECORD_FILENAME, &dumpFileRec_);
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_AEC_CIRCUIT_FILENAME, &dumpFileCir_);
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, DUMP_DAUDIO_AEC_AFTER_PROCESS_FILENAME, &dumpFileAft_);
    return DH_SUCCESS;
}

void DAudioEchoCannelManager::CircuitStart()
{
    DHLOGI("Start CircuitStart thread.");
    int32_t ret = AudioCaptureSetUp();
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "Init Get Reference error. ret: %{public}d.", ret);
    ret = AudioCaptureStart();
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "Start Get Reference error. ret: %{public}d.", ret);
    ret = LoadAecProcessor();
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "LoadAECProcessor error.");
    ret = InitAecProcessor();
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "Init Aec Processor error. ret: %{public}d.", ret);
    ret = StartAecProcessor();
    CHECK_AND_RETURN_LOG(ret != DH_SUCCESS, "Start Aec Processor error. ret: %{public}d.", ret);
    DHLOGI("CircuitStart thread end success.");
}

int32_t DAudioEchoCannelManager::Start()
{
    DHLOGI("Start EchoCannel.");
    int32_t ret = StartAecProcessor();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Start Aec Processor error. ret: %{public}d.", ret);

    isStarted.store(true);
    DHLOGI("Start EchoCannel success.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::Stop()
{
    DHLOGI("Stop EchoCannel.");
    isStarted.store(false);
    int32_t ret = StopAecProcessor();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Stop Aec Processor error. ret: %{public}d.", ret);
    ret = AudioCaptureStop();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Stop Get Reference error. ret: %{public}d.", ret);
    DHLOGI("Stop EchoCannel success.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::Release()
{
    DHLOGI("Release EchoCannel.");
    int32_t ret = AudioCaptureRelease();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Release Get Reference error. ret: %{public}d.", ret);

    ret = ReleaseAecProcessor();
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Release Aec Processor error. ret: %{public}d.", ret);
    UnLoadAecProcessor();
    DumpFileUtil::CloseDumpFile(&dumpFileRef_);
    DumpFileUtil::CloseDumpFile(&dumpFileRec_);
    DumpFileUtil::CloseDumpFile(&dumpFileAft_);
    DumpFileUtil::CloseDumpFile(&dumpFileCir_);
    isStarted.store(false);
    isCircuitStartRunning_.store(false);
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::OnMicDataReceived(const std::shared_ptr<AudioData> &pipeInData)
{
    DHLOGD("GetMicDataBeforeAec.");
    CHECK_AND_RETURN_RET_LOG(devCallback_ == nullptr, ERR_DH_AUDIO_NULLPTR, "callback is nullptr.");
    if (isStarted.load()) {
        CHECK_AND_RETURN_RET_LOG(pipeInData == nullptr, ERR_DH_AUDIO_NULLPTR, "pipeInData is nullptr.");
        auto micOutData = std::make_shared<AudioData>(pipeInData->Size());
        int32_t ret = ProcessMicData(pipeInData, micOutData);
        if (ret != DH_SUCCESS) {
            DHLOGE("Mic data call processor error. ret : %{public}d.", ret);
            devCallback_->OnDecodeTransDataDone(pipeInData);
            return ERR_DH_AUDIO_FAILED;
        }
        DumpFileUtil::WriteDumpFile(dumpFileRec_, static_cast<void *>(pipeInData->Data()), pipeInData->Size());
        DumpFileUtil::WriteDumpFile(dumpFileAft_, static_cast<void *>(micOutData->Data()), micOutData->Size());
        devCallback_->OnDecodeTransDataDone(micOutData);
    } else {
        devCallback_->OnDecodeTransDataDone(pipeInData);
    }
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::ProcessMicData(const std::shared_ptr<AudioData> &pipeInData,
    std::shared_ptr<AudioData> &micOutData)
{
    DHLOGD("Process mic data.");
    uint8_t *micOutDataExt = nullptr;
    CHECK_AND_RETURN_RET_LOG(pipeInData == nullptr, ERR_DH_AUDIO_NULLPTR, "pipeInData is nullptr.");
    CHECK_AND_RETURN_RET_LOG(micOutData == nullptr, ERR_DH_AUDIO_NULLPTR, "micOutData is nullptr.");
    CHECK_AND_RETURN_RET_LOG(aecProcessor_ == nullptr, ERR_DH_AUDIO_NULLPTR, "aec processor is nullptr.");
    int32_t ret = aecProcessor_->OnSendOriginData(aecProcessor_, pipeInData->Data(),
        pipeInData->Size(), StreamType::MIC1, &micOutDataExt);
    if (ret != DH_SUCCESS || micOutDataExt == nullptr) {
        DHLOGI("aec effect process pipeInReferenceData fail. errocode:%{public}d", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    if (memcpy_s(micOutData->Data(), micOutData->Size(), micOutDataExt, pipeInData->Size()) != EOK) {
        DHLOGE("copy mic data after aec error.");
        ret = ERR_DH_AUDIO_FAILED;
    } else {
        ret = DH_SUCCESS;
    }
    if (micOutDataExt != nullptr) {
        free(micOutDataExt);
        micOutDataExt = nullptr;
    }
    return ret;
}

void DAudioEchoCannelManager::AecProcessData()
{
    DHLOGI("Start the aec process thread.");
    if (pthread_setname_np(pthread_self(), AECTHREADNAME) != DH_SUCCESS) {
        DHLOGE("aec process thread setname failed.");
    }
    DHLOGI("Begin the aec process thread. refDataQueueSize: %{public}zu.", refDataQueue_.size());
    while (aecProcessor_ != nullptr && isAecRunning_.load()) {
        std::shared_ptr<AudioData> refInData = nullptr;
        uint8_t *refOutDataExt = nullptr;
        {
            std::unique_lock<std::mutex> refLck(refQueueMtx_);
            refQueueCond_.wait_for(refLck, std::chrono::milliseconds(COND_WAIT_TIME_MS),
                [this]() { return !refDataQueue_.empty(); });
            if (refDataQueue_.empty()) {
                DHLOGD("refDataQueue is Empty.");
                continue;
            }
            refInData = refDataQueue_.front();
            refDataQueue_.pop();
            DHLOGD("Pop new echo ref data, ref dataqueue size: %{public}zu.", refDataQueue_.size());
        }
        DumpFileUtil::WriteDumpFile(dumpFileRef_, static_cast<void *>(refInData->Data()), refInData->Size());
        int32_t ret = aecProcessor_->OnSendOriginData(aecProcessor_, refInData->Data(), refInData->Size(),
            StreamType::REF, &refOutDataExt);
        if (ret != DH_SUCCESS) {
            DHLOGE("aec effect process pipeInReferenceData fail. errocode:%{public}d", ret);
        }
        if (!isStarted.load()) {
            isStarted.store(true);
        }
        if (refOutDataExt != nullptr) {
            free(refOutDataExt);
            refOutDataExt = nullptr;
        }
    }
    DHLOGI("the aec process thread exit.");
    return;
}

void DAudioEchoCannelManager::OnReadData(size_t length)
{
    BufferDesc bufDesc;
    if (audioCapturer_ == nullptr) {
        DHLOGE("audioCapturer is nullptr.");
        return;
    }
    int32_t ret = audioCapturer_->GetBufferDesc(bufDesc);
    if (ret != 0 || bufDesc.buffer == nullptr || bufDesc.bufLength == 0) {
        DHLOGE("Get buffer desc failed. On read data.");
        return;
    }
    DHLOGD("Get echo ref data. size: %{public}zu.", bufDesc.bufLength);
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufDesc.bufLength);
    if (audioData->Capacity() != bufDesc.bufLength) {
        DHLOGE("Audio data length is not equal to buflength. datalength: %{public}zu, bufLength: %{public}zu",
            audioData->Capacity(), bufDesc.bufLength);
    }
    if (memcpy_s(audioData->Data(), audioData->Capacity(), bufDesc.buffer, bufDesc.bufLength) != EOK) {
        DHLOGE("Copy audio data failed.");
    }

    audioCapturer_->Enqueue(bufDesc);
    DumpFileUtil::WriteDumpFile(dumpFileCir_, static_cast<void *>(audioData->Data()), audioData->Size());
    std::lock_guard<std::mutex> lock(refQueueMtx_);
    while (refDataQueue_.size() > REF_QUEUE_MAX_SIZE) {
        DHLOGE("Ref Data queue overflow. max size : 10");
        refDataQueue_.pop();
    }
    refDataQueue_.push(audioData);
    DHLOGD("Push new echo ref data, buf len: %{public}zu.", refDataQueue_.size());
    refQueueCond_.notify_all();
}

int32_t DAudioEchoCannelManager::AudioCaptureSetUp()
{
    if (audioCapturer_ != nullptr) {
        DHLOGI("Audio capture has been created. no need to setup.");
        return DH_SUCCESS;
    }
    AudioStandard::AudioCapturerOptions capturerOptions = {
        {
            AudioStandard::AudioSamplingRate::SAMPLE_RATE_48000,
            AudioStandard::AudioEncodingType::ENCODING_PCM,
            AudioStandard::AudioSampleFormat::SAMPLE_S16LE,
            AudioStandard::AudioChannel::STEREO,
        },
        {
            AudioStandard::SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE,
            AudioStandard::STREAM_FLAG_NORMAL,
        }
    };
    capturerOptions.playbackCaptureConfig.filterOptions.usages.push_back(AudioStandard::
        StreamUsage::STREAM_USAGE_MEDIA);
    capturerOptions.playbackCaptureConfig.filterOptions.usages.push_back(AudioStandard::
        StreamUsage::STREAM_USAGE_UNKNOWN);
    capturerOptions.playbackCaptureConfig.filterOptions.usages.push_back(AudioStandard::
        StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION);
    capturerOptions.playbackCaptureConfig.filterOptions.usages.push_back(AudioStandard::
        StreamUsage::STREAM_USAGE_MOVIE);

    audioCapturer_ = AudioStandard::AudioCapturer::Create(capturerOptions);
    CHECK_AND_RETURN_RET_LOG(audioCapturer_ == nullptr, ERR_DH_AUDIO_FAILED, "Audio capture create failed.");

    int32_t ret = audioCapturer_->SetCaptureMode(CAPTURE_MODE_CALLBACK);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Set capture mode callback fail, ret %{public}d.", ret);
    ret = audioCapturer_->SetCapturerReadCallback(shared_from_this());
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "Set capture data callback fail, ret %{public}d.", ret);
    DHLOGI("Audio capturer create success");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::AudioCaptureStart()
{
    if (audioCapturer_ == nullptr) {
        DHLOGE("Audio capturer is nullptr start.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (!audioCapturer_->Start()) {
        DHLOGE("Audio capturer start failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::AudioCaptureStop()
{
    if (audioCapturer_ == nullptr) {
        DHLOGE("Audio capturer is nullptr stop.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (!audioCapturer_->Stop()) {
        DHLOGE("Audio capturer stop failed.");
    }
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::AudioCaptureRelease()
{
    if (audioCapturer_ != nullptr && !audioCapturer_->Release()) {
        DHLOGE("Audio capturer release failed.");
    }
    audioCapturer_ = nullptr;
    DHLOGI("Audio capturer release end.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::LoadAecProcessor()
{
    DHLOGI("LoadAecEffectProcessor enter");
    if (ECHOCANNEL_SO_NAME.length() > PATH_MAX) {
        DHLOGE("File open failed");
        return ERR_DH_AUDIO_NULLPTR;
    }
    aecHandler_ = dlopen(ECHOCANNEL_SO_NAME.c_str(), RTLD_LAZY | RTLD_NODELETE);
    CHECK_AND_RETURN_RET_LOG(aecHandler_ == nullptr, ERR_DH_AUDIO_NULLPTR, "dlOpen error.");
    AecEffectProcessorProvider getAecEffectProcessorFunc = (AecEffectProcessorProvider)dlsym(aecHandler_,
        GET_AEC_EFFECT_PROCESSOR_FUNC.c_str());
    if (getAecEffectProcessorFunc == nullptr) {
        DHLOGE("AecEffectProcessor function handler is null, failed reason : %s", dlerror());
        dlclose(aecHandler_);
        aecHandler_ = nullptr;
        return ERR_DH_AUDIO_NULLPTR;
    }
    aecProcessor_ = getAecEffectProcessorFunc();
    DHLOGI("LoadAecEffectProcessor exit");
    return DH_SUCCESS;
}

void DAudioEchoCannelManager::UnLoadAecProcessor()
{
    if (aecHandler_ != nullptr) {
        dlclose(aecHandler_);
        aecHandler_ = nullptr;
    }
    aecProcessor_ = nullptr;
}

int32_t DAudioEchoCannelManager::InitAecProcessor()
{
    AudioCommonParam param;
    param.sampleRate = SAMPLE_RATE_48000;
    param.channelMask = STEREO;
    param.bitFormat = SAMPLE_S16LE;
    param.frameSize = FRAME_SIZE_NORMAL;
    if (aecProcessor_ == nullptr) {
        DHLOGE("Aec processor is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = aecProcessor_->Init(aecProcessor_, param);
    if (ret != DH_SUCCESS) {
        DHLOGE("Aec effect processor init fail. errorcode: %{public}d", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Aec effect process init success.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::StartAecProcessor()
{
    if (aecProcessor_ == nullptr) {
        DHLOGE("Aec process is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = aecProcessor_->StartUp(aecProcessor_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Aec effect process start fail. errorcode:%{public}d", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    if (!isAecRunning_.load()) {
        isAecRunning_.store(true);
        aecProcessThread_ = std::thread([this]() { this->AecProcessData(); });
    }
    DHLOGI("Aec effect process start success.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::StopAecProcessor()
{
    if (aecProcessor_ == nullptr) {
        DHLOGE("Aec processor is nullptr.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = aecProcessor_->ShutDown(aecProcessor_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Aec effect process stop fail. errorcode:%{public}d", ret);
        return ERR_DH_AUDIO_FAILED;
    }
    if (isAecRunning_.load()) {
        DHLOGI("Stop the aec process thread.");
        isAecRunning_.store(false);
        if (aecProcessThread_.joinable()) {
            aecProcessThread_.join();
        }
    }
    DHLOGI("Aec effect process stop success.");
    return DH_SUCCESS;
}

int32_t DAudioEchoCannelManager::ReleaseAecProcessor()
{
    if (isAecRunning_.load()) {
        DHLOGI("Stop the aec process thread.");
        isAecRunning_.store(false);
        if (aecProcessThread_.joinable()) {
            aecProcessThread_.join();
        }
    }
    if (aecProcessor_ != nullptr) {
        if (aecProcessor_->Release(aecProcessor_) != DH_SUCCESS) {
            DHLOGE("Aec effect process release fail.");
        }
        aecProcessor_ = nullptr;
    }
    DHLOGI("Aec effect process release success.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
