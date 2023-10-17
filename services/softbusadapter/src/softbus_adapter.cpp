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

#include "softbus_adapter.h"
#include "softbus_error_code.h"

#include <securec.h>

#undef DH_LOG_TAG
#define DH_LOG_TAG "SoftbusAdapter"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);
static int32_t AudioOnSoftbusSessionOpened(int32_t sessionId, int32_t result)
{
    return SoftbusAdapter::GetInstance().OnSoftbusSessionOpened(sessionId, result);
}

static void AudioOnSoftbusSessionClosed(int32_t sessionId)
{
    SoftbusAdapter::GetInstance().OnSoftbusSessionClosed(sessionId);
}

static void AudioOnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    SoftbusAdapter::GetInstance().OnBytesReceived(sessionId, data, dataLen);
}

static void AudioOnStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *frameInfo)
{
    SoftbusAdapter::GetInstance().OnStreamReceived(sessionId, data, ext, frameInfo);
}

static void AudioOnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    SoftbusAdapter::GetInstance().OnMessageReceived(sessionId, data, dataLen);
}

static void AudioOnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    SoftbusAdapter::GetInstance().OnQosEvent(sessionId, eventId, tvCount, tvList);
}

SoftbusAdapter::SoftbusAdapter()
{
    DHLOGD("Softbus adapter constructed.");
    sessListener_.OnSessionOpened = AudioOnSoftbusSessionOpened;
    sessListener_.OnSessionClosed = AudioOnSoftbusSessionClosed;
    sessListener_.OnBytesReceived = AudioOnBytesReceived;
    sessListener_.OnStreamReceived = AudioOnStreamReceived;
    sessListener_.OnMessageReceived = AudioOnMessageReceived;
    sessListener_.OnQosEvent = AudioOnQosEvent;
}

SoftbusAdapter::~SoftbusAdapter()
{
    DHLOGD("Softbus adapter destructed.");
}

int32_t SoftbusAdapter::CreateSoftbusSessionServer(const std::string &pkgName, const std::string &sessionName,
    const std::string &peerDevId)
{
    DHLOGI("Create server, sessName: %s peerDevId: %s.", sessionName.c_str(), GetAnonyString(peerDevId).c_str());
    std::lock_guard<std::mutex> setLock(sessSetMtx_);
    if (mapSessionSet_.find(sessionName) == mapSessionSet_.end()) {
        int32_t ret = CreateSessionServer(pkgName.c_str(), sessionName.c_str(), &sessListener_);
        if (ret != SOFTBUS_OK) {
            DHLOGE("Create session server failed, ret %d.", ret);
            return ret;
        }
    } else {
        DHLOGD("Session is already created.");
        return DH_SUCCESS;
    }

    mapSessionSet_[sessionName].insert(peerDevId);
    DHLOGI("Create session server success.");
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::RemoveSoftbusSessionServer(const std::string &pkgName, const std::string &sessionName,
    const std::string &peerDevId)
{
    DHLOGI("Remove server, sessName: %s peerDevId: %s.", sessionName.c_str(), GetAnonyString(peerDevId).c_str());
    std::lock_guard<std::mutex> setLock(sessSetMtx_);
    if (mapSessionSet_.find(sessionName) == mapSessionSet_.end()) {
        DHLOGE("Session server already removed.");
        return DH_SUCCESS;
    }
    mapSessionSet_[sessionName].erase(peerDevId);
    if (mapSessionSet_[sessionName].empty()) {
        mapSessionSet_.erase(sessionName);
        int32_t ret = RemoveSessionServer(pkgName.c_str(), sessionName.c_str());
        if (ret != SOFTBUS_OK) {
            DHLOGE("Remove session server failed. Error code %d.", ret);
        }
    }
    DHLOGI("Remove session server success.");
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::OpenSoftbusSession(const std::string &localSessionName, const std::string &peerSessionName,
    const std::string &peerDevId)
{
    DHLOGI("Open softbus session, localSess: %s peerSess: %s peerDevId: %s.", localSessionName.c_str(),
        peerSessionName.c_str(), GetAnonyString(peerDevId).c_str());
    int dataType = TYPE_BYTES;
    int streamType = -1;
    if (localSessionName != CTRL_SESSION_NAME) {
        dataType = TYPE_STREAM;
        streamType = RAW_STREAM;
    }

    SessionAttribute attr = { 0 };
    attr.dataType = dataType;
    attr.linkTypeNum = LINK_TYPE_MAX;
    LinkType linkTypeList[LINK_TYPE_MAX] = {
        LINK_TYPE_WIFI_P2P,
        LINK_TYPE_WIFI_WLAN_5G,
        LINK_TYPE_WIFI_WLAN_2G,
        LINK_TYPE_BR,
    };
    if (memcpy_s(attr.linkType, sizeof(attr.linkType), linkTypeList, sizeof(linkTypeList)) != EOK) {
        DHLOGE("Softbus open session params copy failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    attr.attr.streamAttr.streamType = streamType;
    int32_t sessionId = OpenSession(localSessionName.c_str(), peerSessionName.c_str(), peerDevId.c_str(), "0", &attr);
    if (sessionId < 0) {
        DHLOGE("Open softbus session failed sessionId: %d.", sessionId);
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Open softbus session success.");
    return sessionId;
}

int32_t SoftbusAdapter::CloseSoftbusSession(int32_t sessionId)
{
    DHLOGI("Close softbus session: %d.", sessionId);
    CloseSession(sessionId);
    std::lock_guard<std::mutex> LisLock(listenerMtx_);
    mapListenersI_.erase(sessionId);
    StopSendDataThread();
    DHLOGI("Close softbus session success.");
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::SendSoftbusBytes(int32_t sessionId, const void *data, int32_t dataLen)
{
    DHLOGI("Send audio event, sessionId: %d.", sessionId);
    int32_t ret = SendBytes(sessionId, data, dataLen);
    if (ret != SOFTBUS_OK) {
        DHLOGE("Send bytes failed, ret:%d.", ret);
        return ERR_DH_AUDIO_TRANS_ERROR;
    }
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::SendSoftbusStream(int32_t sessionId, const std::shared_ptr<AudioData> &audioData)
{
    DHLOGI("Send audio data, sessionId: %d.", sessionId);
    if (audioData == nullptr) {
        DHLOGE("Audio data is null.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::lock_guard<std::mutex> lck(dataQueueMtx_);
    while (audioDataQueue_.size() >= DATA_QUEUE_MAX_SIZE) {
        DHLOGE("Softbus data queue overflow. data queue size: %d", audioDataQueue_.size());
        audioDataQueue_.pop();
    }
    auto data = std::make_shared<SoftbusStreamData>(audioData, sessionId);
    audioDataQueue_.push(data);
    sendDataCond_.notify_all();
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::RegisterSoftbusListener(const std::shared_ptr<ISoftbusListener> &listener,
    const std::string &sessionName, const std::string &peerDevId)
{
    DHLOGI("Register listener sess: %s peerDevId: %s.", sessionName.c_str(), GetAnonyString(peerDevId).c_str());
    std::string strListenerKey = sessionName + "_" + peerDevId;
    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    if (mapListenersN_.find(strListenerKey) != mapListenersN_.end()) {
        DHLOGD("Session listener already register.");
        return DH_SUCCESS;
    }
    mapListenersN_.insert(std::make_pair(strListenerKey, listener));
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::UnRegisterSoftbusListener(const std::string &sessionName, const std::string &peerDevId)
{
    DHLOGI("Unregister listener sess: %s peerDevId: %s.", sessionName.c_str(), GetAnonyString(peerDevId).c_str());
    std::string strListenerKey = sessionName + "_" + peerDevId;
    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    mapListenersN_.erase(strListenerKey);
    return DH_SUCCESS;
}

int32_t SoftbusAdapter::OnSoftbusSessionOpened(int32_t sessionId, int32_t result)
{
    DHLOGI("On session opened, sessionId: %d, result: %d.", sessionId, result);
    if (result != SOFTBUS_OK) {
        DHLOGE("Session open failed.");
        return ERR_DH_AUDIO_FAILED;
    }
    auto &listener = GetSoftbusListenerByName(sessionId);
    if (!listener) {
        DHLOGE("Get softbus listener failed.");
        return ERR_DH_AUDIO_TRANS_ERROR;
    }

    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    if (mapListenersI_.empty()) {
        DHLOGD("Start softbus send thread.");
        isSessionOpened_.store(true);
        sendDataThread_ = std::thread(&SoftbusAdapter::SendAudioData, this);
        if (pthread_setname_np(sendDataThread_.native_handle(), SENDDATA_THREAD) != DH_SUCCESS) {
            DHLOGE("Send data thread setname failed.");
        }
    }
    mapListenersI_.insert(std::make_pair(sessionId, listener));
    listener->OnSessionOpened(sessionId, result);
    return DH_SUCCESS;
}

void SoftbusAdapter::OnSoftbusSessionClosed(int32_t sessionId)
{
    DHLOGI("On session closed, sessionId: %d.", sessionId);
    auto &listener = GetSoftbusListenerById(sessionId);
    if (!listener) {
        DHLOGE("Get softbus listener failed.");
        return;
    }
    listener->OnSessionClosed(sessionId);

    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    mapListenersI_.erase(sessionId);
    StopSendDataThread();
}

void SoftbusAdapter::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    DHLOGI("On audio event received from session: %d.", sessionId);
    if (data == nullptr) {
        DHLOGE("Bytes data is null.");
        return;
    } else if (dataLen == 0 || dataLen > DAUDIO_MAX_RECV_DATA_LEN) {
        DHLOGE("Stream data length is illegal, dataLen: %d.", dataLen);
        return;
    }

    auto &listener = GetSoftbusListenerById(sessionId);
    if (listener == nullptr) {
        DHLOGE("Get softbus listener failed.");
        return;
    }
    listener->OnBytesReceived(sessionId, data, dataLen);
}

void SoftbusAdapter::OnStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *streamFrameInfo)
{
    DHLOGI("On audio data received from session: %d.", sessionId);
    if (data == nullptr) {
        DHLOGE("Stream data is null.");
        return;
    } else if (data->bufLen <= 0 || (uint32_t)(data->bufLen) > DAUDIO_MAX_RECV_DATA_LEN) {
        DHLOGE("Stream data length is illegal, dataLen: %d.", data->bufLen);
        return;
    }

    auto &listener = GetSoftbusListenerById(sessionId);
    if (!listener) {
        DHLOGE("Get softbus listener failed.");
        return;
    }
    listener->OnStreamReceived(sessionId, data, ext, streamFrameInfo);
}

void SoftbusAdapter::OnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    DHLOGD("On message received, sessionId: %d.", sessionId);
}

void SoftbusAdapter::OnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    DHLOGD("On qos event received, sessionId: %d.", sessionId);
}

std::shared_ptr<ISoftbusListener> &SoftbusAdapter::GetSoftbusListenerByName(int32_t sessionId)
{
    char sessionName[DAUDIO_MAX_SESSION_NAME_LEN] = "";
    char peerDevId[DAUDIO_MAX_DEVICE_ID_LEN] = "";
    int32_t ret = GetPeerSessionName(sessionId, sessionName, sizeof(sessionName));
    if (ret != SOFTBUS_OK) {
        DHLOGE("Get peer session name failed ret: %d.", ret);
        return nullListener_;
    }
    ret = GetPeerDeviceId(sessionId, peerDevId, sizeof(peerDevId));
    if (ret != SOFTBUS_OK) {
        DHLOGE("Get peer deviceId failed ret: %d.", ret);
        return nullListener_;
    }
    std::string sessionNameStr(sessionName);
    std::string peerDevIdStr(peerDevId);
    std::string strListenerKey = sessionNameStr + "_" + peerDevIdStr;

    DHLOGI("Get listener sess: %s, peerDevId: %s.", sessionNameStr.c_str(), GetAnonyString(peerDevIdStr).c_str());
    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    if (mapListenersN_.find(strListenerKey) == mapListenersN_.end()) {
        DHLOGE("Find listener failed.");
        return nullListener_;
    }
    return mapListenersN_[strListenerKey];
}

std::shared_ptr<ISoftbusListener> &SoftbusAdapter::GetSoftbusListenerById(int32_t sessionId)
{
    std::lock_guard<std::mutex> lisLock(listenerMtx_);
    if (mapListenersI_.find(sessionId) == mapListenersI_.end()) {
        DHLOGE("Find listener failed.");
        return nullListener_;
    }
    return mapListenersI_[sessionId];
}

void SoftbusAdapter::SendAudioData()
{
    constexpr uint8_t DATA_WAIT_TIME = 20;
    while (isSessionOpened_.load()) {
        std::shared_ptr<SoftbusStreamData> audioData;
        {
            std::unique_lock<std::mutex> lock(dataQueueMtx_);
            sendDataCond_.wait_for(lock, std::chrono::milliseconds(DATA_WAIT_TIME),
                [this]() { return !audioDataQueue_.empty(); });
            if (audioDataQueue_.empty()) {
                continue;
            }
            audioData = audioDataQueue_.front();
            audioDataQueue_.pop();
        }
        if (audioData == nullptr || audioData->data_ == nullptr) {
            DHLOGE("Audio data is null.");
            continue;
        }

        StreamData data = { reinterpret_cast<char *>(audioData->data_->Data()), audioData->data_->Capacity() };
        StreamData ext;
        StreamFrameInfo frameInfo;
        DHLOGI("Send audio data, sessionId: %d.", audioData->sessionId_);
        int32_t ret = SendStream(audioData->sessionId_, &data, &ext, &frameInfo);
        if (ret != SOFTBUS_OK) {
            DHLOGE("Send data failed. ret: %d.", ret);
        } else {
            DHLOGI("Send audio data successs.");
        }
    }
}

void SoftbusAdapter::StopSendDataThread()
{
    if (mapListenersI_.empty()) {
        DHLOGI("Stop softbus send thread.");
        isSessionOpened_.store(false);
        if (sendDataThread_.joinable()) {
            sendDataThread_.join();
        }
    }
}
} // namespace DistributedHardware
} // namespace OHOS