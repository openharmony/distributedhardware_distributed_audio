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

#include "audio_data_channel.h"

#include <securec.h>

#include "daudio_hitrace.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDataChannel"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioDataChannel::CreateSession(const std::shared_ptr<IAudioChannelListener> &listener,
    const std::string &sessionName)
{
    DHLOGI("Create session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    int32_t ret =
        SoftbusAdapter::GetInstance().CreateSoftbusSessionServer(PKG_NAME, sessionName, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Create softbus session failed ret.");
        return ret;
    }

    ret = SoftbusAdapter::GetInstance().RegisterSoftbusListener(shared_from_this(), sessionName, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register softbus adapter listener failed ret: %d.", ret);
        return ret;
    }

    channelListener_ = listener;
    sessionName_ = sessionName;
    DHLOGI("Create softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::ReleaseSession()
{
    DHLOGI("Release session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    int32_t ret = SoftbusAdapter::GetInstance().RemoveSoftbusSessionServer(PKG_NAME, sessionName_, peerDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Release softbus session failed ret: %d.", ret);
        return ret;
    }

    SoftbusAdapter::GetInstance().UnRegisterSoftbusListener(sessionName_, peerDevId_);
    channelListener_.reset();

    DHLOGI("Release softbus session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::OpenSession()
{
    DHLOGI("Open session, peerDevId: %s.", GetAnonyString(peerDevId_).c_str());
    int32_t sessionId =
        SoftbusAdapter::GetInstance().OpenSoftbusSession(sessionName_, sessionName_, peerDevId_);
    if (sessionId < 0) {
        DHLOGE("Open audio session failed, ret: %d.", sessionId);
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    sessionId_ = sessionId;

    DHLOGI("Open audio session success, sessionId: %d.", sessionId_);
    return DH_SUCCESS;
}

int32_t AudioDataChannel::CloseSession()
{
    DHLOGI("Close session, sessionId: %d.", sessionId_);
    if (sessionId_ == 0) {
        DHLOGD("Session is already close.");
        return DH_SUCCESS;
    }

    SoftbusAdapter::GetInstance().CloseSoftbusSession(sessionId_);
    sessionId_ = 0;

    DHLOGI("Close audio session success.");
    return DH_SUCCESS;
}

int32_t AudioDataChannel::SendEvent(const AudioEvent &audioEvent)
{
    (void) audioEvent;
    return DH_SUCCESS;
}

int32_t AudioDataChannel::SendData(const std::shared_ptr<AudioData> &audioData)
{
    DHLOGD("Send data, sessionId: %d.", sessionId_);
    return SoftbusAdapter::GetInstance().SendSoftbusStream(sessionId_, audioData);
}

void AudioDataChannel::OnSessionOpened(int32_t sessionId, int32_t result)
{
    DHLOGD("On audio session opened, sessionId: %d, result: %d.", sessionId, result);
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
    sessionId_ = sessionId;
}

void AudioDataChannel::OnSessionClosed(int32_t sessionId)
{
    DHLOGI("On audio session closed, sessionId: %d.", sessionId);
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
}

void AudioDataChannel::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void) sessionId;
    (void) data;
    (void) dataLen;

    DHLOGI("Data channel not support yet.");
}

void AudioDataChannel::OnStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *streamFrameInfo)
{
    (void) ext;
    (void) streamFrameInfo;

    auto listener = channelListener_.lock();
    if (listener == nullptr) {
        DHLOGE("Channel listener is null.");
        return;
    }

    if (data == nullptr) {
        DHLOGE("Received stream data is nullptr.");
        return;
    }
    DHLOGI("On audio stream received, sessionId: %d dataSize: %zu.", sessionId, data->bufLen);
    auto audioData = std::make_shared<AudioData>(data->bufLen);
    if (memcpy_s(audioData->Data(), audioData->Capacity(), reinterpret_cast<uint8_t *>(data->buf), data->bufLen)
        != EOK) {
        DHLOGE("Received stream data copy failed.");
        return;
    }
    listener->OnDataReceived(audioData);
}
} // namespace DistributedHardware
} // namespace OHOS
