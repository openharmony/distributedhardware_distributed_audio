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

#include "dspeaker_dev.h"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <securec.h>

#include "audio_encode_transport.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DSpeakerDev"

namespace OHOS {
namespace DistributedHardware {
int32_t DSpeakerDev::EnableDSpeaker(const int32_t dhId, const std::string &capability)
{
    DHLOGI("Enable speaker device dhId: %d.", dhId);
    if (enabledPorts_.empty()) {
        if (EnableDevice(PIN_OUT_DAUDIO_DEFAULT, capability) != DH_SUCCESS) {
            return ERR_DH_AUDIO_FAILED;
        }
    }
    int32_t ret = EnableDevice(dhId, capability);

    DaudioFinishAsyncTrace(DAUDIO_REGISTER_AUDIO, DAUDIO_REGISTER_AUDIO_TASKID);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUIDO_REGISTER, devId_, std::to_string(dhId),
        "daudio spk enable success.");
    return ret;
}

int32_t DSpeakerDev::EnableDevice(const int32_t dhId, const std::string &capability)
{
    int32_t ret = DAudioHdiHandler::GetInstance().RegisterAudioDevice(devId_, dhId, capability, shared_from_this());
    if (ret != DH_SUCCESS) {
        DHLOGE("Register speaker device failed, ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_REGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio register speaker device failed.");
        return ret;
    }
    enabledPorts_.insert(dhId);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::DisableDSpeaker(const int32_t dhId)
{
    DHLOGI("Disable distributed speaker.");
    if (dhId == curPort_) {
        isOpened_.store(false);
    }
    int32_t ret = DisableDevice(dhId);
    if (ret != DH_SUCCESS) {
        return ret;
    }
    if (enabledPorts_.size() == SINGLE_ITEM && enabledPorts_.find(PIN_OUT_DAUDIO_DEFAULT) != enabledPorts_.end()) {
        ret = DisableDevice(PIN_OUT_DAUDIO_DEFAULT);
        if (ret != DH_SUCCESS) {
            return ret;
        }
    }

    DaudioFinishAsyncTrace(DAUDIO_UNREGISTER_AUDIO, DAUDIO_UNREGISTER_AUDIO_TASKID);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_UNREGISTER, devId_, std::to_string(dhId),
        "daudio spk disable success.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::DisableDevice(const int32_t dhId)
{
    int32_t ret = DAudioHdiHandler::GetInstance().UnRegisterAudioDevice(devId_, dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("UnRegister speaker device failed, ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_UNREGISTER_FAIL, devId_, std::to_string(dhId), ret,
            "daudio unregister speaker device failed.");
        return ret;
    }
    enabledPorts_.erase(dhId);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::OpenDevice(const std::string &devId, const int32_t dhId)
{
    DHLOGI("Open speaker device devId: %s, dhId: %d.", GetAnonyString(devId).c_str(), dhId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is null");
        return ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL;
    }

    json jParam = { { KEY_DH_ID, std::to_string(dhId) } };
    AudioEvent event(AudioEventType::OPEN_SPEAKER, jParam.dump());
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_OPEN, devId, std::to_string(dhId),
        "daudio spk device open success.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::CloseDevice(const std::string &devId, const int32_t dhId)
{
    DHLOGI("Close speaker device devId: %s, dhId: %d.", GetAnonyString(devId).c_str(), dhId);
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is null");
        return ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL;
    }

    json jParam = { { KEY_DH_ID, std::to_string(dhId) } };
    AudioEvent event(AudioEventType::CLOSE_SPEAKER, jParam.dump());
    cbObj->NotifyEvent(event);
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_CLOSE, devId, std::to_string(dhId),
        "daudio spk device close success.");
    curPort_ = 0;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::SetParameters(const std::string &devId, const int32_t dhId, const AudioParamHDF &param)
{
    DHLOGI("Set speaker parameters {samplerate: %d, channelmask: %d, format: %d, streamusage: %d, period: %d, "
        "framesize: %d, renderFlags: %d, ext{%s}}.",
        param.sampleRate, param.channelMask, param.bitFormat, param.streamUsage, param.period, param.frameSize,
        param.renderFlags, param.ext.c_str());
    curPort_ = dhId;
    paramHDF_ = param;

    param_.comParam.sampleRate = paramHDF_.sampleRate;
    param_.comParam.channelMask = paramHDF_.channelMask;
    param_.comParam.bitFormat = paramHDF_.bitFormat;
    param_.comParam.codecType = AudioCodecType::AUDIO_CODEC_AAC;
    param_.comParam.frameSize = paramHDF_.frameSize;
    param_.renderOpts.contentType = CONTENT_TYPE_MUSIC;
    param_.renderOpts.renderFlags = paramHDF_.renderFlags;
    param_.renderOpts.streamUsage = paramHDF_.streamUsage;
    return DH_SUCCESS;
}

int32_t DSpeakerDev::NotifyEvent(const std::string &devId, int32_t dhId, const AudioEvent &event)
{
    DHLOGI("Notify speaker event.");
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is null");
        return ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL;
    }
    AudioEvent audioEvent(event.type, event.content);
    cbObj->NotifyEvent(audioEvent);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::SetUp()
{
    DHLOGI("Set up speaker device.");
    if (speakerTrans_ == nullptr) {
        speakerTrans_ = std::make_shared<AudioEncodeTransport>(devId_);
    }

    int32_t ret = speakerTrans_->SetUp(param_, param_, shared_from_this(), CAP_SPK);
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans set up failed. ret:%d", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Start()
{
    DHLOGI("Start speaker device.");
    if (speakerTrans_ == nullptr) {
        DHLOGE("Speaker trans is null.");
        return ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL;
    }

    int32_t ret = speakerTrans_->Start();
    if (ret != DH_SUCCESS) {
        DHLOGE("Speaker trans start failed, ret: %d.", ret);
        return ret;
    }

    std::unique_lock<std::mutex> lck(channelWaitMutex_);
    auto status = channelWaitCond_.wait_for(lck, std::chrono::seconds(CHANNEL_WAIT_SECONDS),
        [this]() { return isTransReady_.load(); });
    if (!status) {
        DHLOGE("Wait channel open timeout(%ds).", CHANNEL_WAIT_SECONDS);
        return ERR_DH_AUDIO_SA_SPEAKER_CHANNEL_WAIT_TIMEOUT;
    }
    isOpened_.store(true);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Stop()
{
    DHLOGI("Stop speaker device.");
    if (speakerTrans_ == nullptr) {
        DHLOGE("Speaker trans is null.");
        return DH_SUCCESS;
    }

    isOpened_.store(false);
    isTransReady_.store(false);
    int32_t ret = speakerTrans_->Stop();
    if (ret != DH_SUCCESS) {
        DHLOGE("Stop speaker trans failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Release()
{
    DHLOGI("Release speaker device.");
    if (speakerTrans_ == nullptr) {
        DHLOGE("Speaker trans is null.");
        return DH_SUCCESS;
    }

    int32_t ret = speakerTrans_->Release();
    if (ret != DH_SUCCESS) {
        DHLOGE("Release speaker trans failed, ret: %d.", ret);
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Pause()
{
    DHLOGI("Pause.");
    if (speakerTrans_ == nullptr) {
        DHLOGE("Speaker trans is null.");
        return ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL;
    }

    int32_t ret = speakerTrans_->Pause();
    if (ret != DH_SUCCESS) {
        DHLOGE("Pause speaker trans failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Pause success.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::Restart()
{
    DHLOGI("Restart.");
    if (speakerTrans_ == nullptr) {
        DHLOGE("Speaker trans is null.");
        return ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL;
    }

    int32_t ret = speakerTrans_->Restart(param_, param_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Restart speaker trans failed, ret: %d.", ret);
        return ret;
    }
    DHLOGI("Restart success.");
    return DH_SUCCESS;
}

bool DSpeakerDev::IsOpened()
{
    return isOpened_.load();
}

int32_t DSpeakerDev::ReadStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data)
{
    (void)devId;
    (void)dhId;
    (void)data;
    DHLOGI("Dspeaker dev not support read stream data.");
    return DH_SUCCESS;
}

int32_t DSpeakerDev::WriteStreamData(const std::string &devId, const int32_t dhId, std::shared_ptr<AudioData> &data)
{
    DHLOGD("Write stream data, dhId:%d", dhId);
    if (speakerTrans_ == nullptr) {
        DHLOGE("Read stream data, speaker trans is null.");
        return ERR_DH_AUDIO_SA_SPEAKER_TRANS_NULL;
    }
    int32_t ret = speakerTrans_->FeedAudioData(data);
    if (ret != DH_SUCCESS) {
        DHLOGE("Write stream data failed, ret: %d.", ret);
        return ret;
    }
    return DH_SUCCESS;
}

AudioParam DSpeakerDev::GetAudioParam() const
{
    return param_;
}

int32_t DSpeakerDev::NotifyHdfAudioEvent(const AudioEvent &event)
{
    int32_t ret = DAudioHdiHandler::GetInstance().NotifyEvent(devId_, curPort_, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify event: %d, result: %s.", event.type, event.content.c_str());
    }
    return DH_SUCCESS;
}

int32_t DSpeakerDev::OnStateChange(const AudioEventType type)
{
    DHLOGI("On speaker device state change, type: %d.", type);
    AudioEvent event;
    switch (type) {
        case AudioEventType::DATA_OPENED:
            isTransReady_.store(true);
            channelWaitCond_.notify_all();
            event.type = AudioEventType::SPEAKER_OPENED;
            break;
        case AudioEventType::DATA_CLOSED:
            isOpened_.store(false);
            isTransReady_.store(false);
            event.type = AudioEventType::SPEAKER_CLOSED;
            break;
        default:
            break;
    }
    std::shared_ptr<IAudioEventCallback> cbObj = audioEventCallback_.lock();
    if (cbObj == nullptr) {
        DHLOGE("Event callback is null");
        return ERR_DH_AUDIO_SA_EVENT_CALLBACK_NULL;
    }
    cbObj->NotifyEvent(event);
    return DH_SUCCESS;
}

int32_t DSpeakerDev::OnDecodeTransDataDone(const std::shared_ptr<AudioData> &audioData)
{
    (void) audioData;
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS