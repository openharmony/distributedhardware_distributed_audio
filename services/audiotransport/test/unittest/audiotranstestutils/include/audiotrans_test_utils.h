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

#ifndef OHOS_AUDIO_TRANS_TEST_UTILS_H
#define OHOS_AUDIO_TRANS_TEST_UTILS_H

#include "iaudio_channel_listener.h"
#include "iaudio_channel.h"

namespace OHOS {
namespace DistributedHardware {
constexpr size_t DATA_LEN = 128;

class MockIAudioChannelListener : public IAudioChannelListener {
public:
    MockIAudioChannelListener() {}
    ~MockIAudioChannelListener() {}
    void OnSessionOpened() override {};
    void OnSessionClosed() override {};
    void OnDataReceived(const std::shared_ptr<AudioData> &data) override {};
    void OnEventReceived(const AudioEvent &event) override {};
};

class MockAudioCtrlChannel : public IAudioChannel {
public:
    explicit MockAudioCtrlChannel(std::string peerDevId) : peerDevId_(peerDevId) {}
    ~MockAudioCtrlChannel() {}

    int32_t CreateSession(const std::shared_ptr<IAudioChannelListener> &listener,
        const std::string &sessionName) override
    {
        return 0;
    }
    int32_t ReleaseSession() override
    {
        return 0;
    }
    int32_t OpenSession() override
    {
        return 0;
    }
    int32_t CloseSession() override
    {
        return 0;
    }
    int32_t SendData(const std::shared_ptr<AudioData> &audioData) override
    {
        return 0;
    }
    int32_t SendEvent(const AudioEvent &audioEvent) override
    {
        return 0;
    }

private:
    const std::string peerDevId_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_AUDIO_TRANS_TEST_UTILS_H