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

#include "audio_ctrl_channel.h"

#include <securec.h>

#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioCtrlChannel"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioCtrlChannel::CreateSession(const std::shared_ptr<IAudioChannelListener> &listener,
    const std::string &sessionName)
{
    DHLOGI("Create session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_TRANS_NULL_VALUE,
            "daudio channel listener is null.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }

    DAUDIO_SYNC_TRACE(DAUDIO_CREATE_CTRL_SESSION);
    int32_t ret =
        SoftbusAdapter::GetInstance().CreateSoftbusSessionServer(PKG_NAME, sessionName, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Create softbus session failed ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio create softbus session failed.");
        return ret;
    }

    ret = SoftbusAdapter::GetInstance().RegisterSoftbusListener(shared_from_this(), sessionName, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register softbus adapter listener failed ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio register softbus adapter listener failed.");
        return ret;
    }

    channelListener_ = listener;
    sessionName_ = sessionName;
    DHLOGI("Create softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::ReleaseSession()
{
    DHLOGI("Release session, peerDevId: %s", GetAnonyString(peerDevId_).c_str());
    DAUDIO_SYNC_TRACE(DAUDIO_RELEASE_CTRL_SESSION);
    int32_t ret = SoftbusAdapter::GetInstance().RemoveSoftbusSessionServer(PKG_NAME, sessionName_, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Release softbus session failed ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio release softbus session failed.");
        return ret;
    }

    ret = SoftbusAdapter::GetInstance().UnRegisterSoftbusListener(sessionName_, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("UnRegister softbus adapter listener failed ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio unRegister softbus adapter listener failed.");
        return ret;
    }
    channelListener_.reset();

    DHLOGI("Release softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::OpenSession()
{
    DHLOGI("Open session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    DaudioStartAsyncTrace(DAUDIO_OPEN_CTRL_SESSION, DAUDIO_OPEN_CTRL_SESSION_TASKID);
    int32_t sessionId =
        SoftbusAdapter::GetInstance().OpenSoftbusSession(sessionName_, sessionName_, peerDevId_);
    if (sessionId < 0) {
        DHLOGE("Open ctrl session failed, ret: %d.", sessionId);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ERR_DH_AUDIO_TRANS_ERROR,
            "daudio open ctrl session failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    sessionId_ = sessionId;

    DHLOGI("Open ctrl session success, sessionId: %d.", sessionId_);
    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::CloseSession()
{
    DHLOGI("Close session, sessionId: %d.", sessionId_);
    if (sessionId_ == 0) {
        DHLOGD("Session is already closed.");
        return DH_SUCCESS;
    }

    DAUDIO_SYNC_TRACE(DAUDIO_CLOSE_CTRL_SESSION);
    int32_t ret = SoftbusAdapter::GetInstance().CloseSoftbusSession(sessionId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Close ctrl session failed, ret: %d.", ret);
        DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_OPT_FAIL, ret,
            "daudio close ctrl session failed.");
        return ret;
    }
    sessionId_ = 0;

    DHLOGI("Close ctrl session success.");
    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::SendData(const std::shared_ptr<AudioData> &data)
{
    (void) data;

    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::SendEvent(const AudioEvent &audioEvent)
{
    DHLOGD("Send event, sessionId: %d.", sessionId_);
    json jAudioEvent;
    jAudioEvent[KEY_TYPE] = audioEvent.type;
    jAudioEvent[KEY_EVENT_CONTENT] = audioEvent.content;
    std::string message = jAudioEvent.dump();
    int ret = SendMsg(message);
    if (ret != DH_SUCCESS) {
        DHLOGE("Send audio event failed ret: %d.", ret);
        return ret;
    }

    return DH_SUCCESS;
}

int32_t AudioCtrlChannel::SendMsg(string &message)
{
    DHLOGD("Start send messages.");
    uint8_t *buf = reinterpret_cast<uint8_t *>(calloc((MSG_MAX_SIZE), sizeof(uint8_t)));
    if (buf == nullptr) {
        DHLOGE("Malloc memory failed.");
        return ERR_DH_AUDIO_CTRL_CHANNEL_SEND_MSG_FAIL;
    }
    int32_t outLen = 0;
    if (memcpy_s(buf, MSG_MAX_SIZE, reinterpret_cast<const uint8_t *>(message.c_str()), message.size()) != EOK) {
        DHLOGE("Copy audio event failed.");
        free(buf);
        return ERR_DH_AUDIO_CTRL_CHANNEL_SEND_MSG_FAIL;
    }
    outLen = static_cast<int32_t>(message.size());
    int32_t ret = SoftbusAdapter::GetInstance().SendSoftbusBytes(sessionId_, buf, outLen);
    free(buf);
    return ret;
}

void AudioCtrlChannel::OnSessionOpened(int32_t sessionId, int32_t result)
{
    DHLOGI("On control session opened, sessionId: %d, result: %d.", sessionId, result);
    if (result != 0) {
        DHLOGE("Session open failed.");
        return;
    }

    auto listener = channelListener_.lock();
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return;
    }
    listener->OnSessionOpened();
    DaudioFinishAsyncTrace(DAUDIO_OPEN_CTRL_SESSION, DAUDIO_OPEN_CTRL_SESSION_TASKID);
    sessionId_ = sessionId;
}

void AudioCtrlChannel::OnSessionClosed(int32_t sessionId)
{
    DHLOGI("On control session closed, sessionId: %d.", sessionId);
    if (sessionId_ == 0) {
        DHLOGD("Session already closed.");
        return;
    }
    auto listener = channelListener_.lock();
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return;
    }
    listener->OnSessionClosed();
    sessionId_ = 0;
}

void AudioCtrlChannel::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    DHLOGI("On bytes received, sessionId: %d, dataLen: %d.", sessionId, dataLen);
    if (sessionId < 0 || data == nullptr || dataLen == 0 || dataLen > MSG_MAX_SIZE) {
        DHLOGE("Param check failed");
        return;
    }
    auto listener = channelListener_.lock();
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return;
    }

    uint8_t *buf = reinterpret_cast<uint8_t *>(calloc(dataLen + STR_TERM_LEN, sizeof(uint8_t)));
    if (buf == nullptr) {
        DHLOGE("Malloc memory failed.");
        return;
    }

    if (memcpy_s(buf, dataLen + STR_TERM_LEN, reinterpret_cast<const uint8_t *>(data), dataLen) != EOK) {
        DHLOGE("Received bytes data copy failed.");
        free(buf);
        return;
    }

    std::string message(buf, buf + dataLen);
    DHLOGI("On bytes received message: %s.", message.c_str());
    AudioEvent audioEvent;
    json jParam = json::parse(message, nullptr, false);
    if (from_audioEventJson(jParam, audioEvent) != DH_SUCCESS) {
        DHLOGE("Get audioEvent from json failed.");
        return;
    }
    free(buf);
    DHLOGI("On bytes received end");

    listener->OnEventReceived(audioEvent);
}

void AudioCtrlChannel::OnStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *streamFrameInfo)
{
    (void) sessionId;
    (void) data;
    (void) ext;
    (void) streamFrameInfo;

    DHLOGI("Ctrl channel not support yet.");
}

int from_audioEventJson(const json &j, AudioEvent &audioEvent)
{
    if (!JsonParamCheck(j, {KEY_TYPE, KEY_EVENT_CONTENT})) {
        DHLOGE("Json data is illegal.");
        return ERR_DH_AUDIO_TRANS_NULL_VALUE;
    }

    j.at(KEY_TYPE).get_to(audioEvent.type);
    j.at(KEY_EVENT_CONTENT).get_to(audioEvent.content);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
