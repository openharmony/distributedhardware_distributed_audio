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

#ifndef OHOS_DAUDIO_SOURCE_CTRL_TRANS_H
#define OHOS_DAUDIO_SOURCE_CTRL_TRANS_H

#include <mutex>
#include <string>

#include "iaudio_ctrl_transport.h"

namespace OHOS {
namespace DistributedHardware {
class DaudioSourceCtrlTrans : public IAudioCtrlTransport,
    public ISoftbusChannelListener {
public:
    DaudioSourceCtrlTrans(const std::string &devId, const std::string &sessionName,
        const std::string &peerSessName, const std::shared_ptr<IAudioCtrlTransCallback> &callback)
        : ctrlTransCallback_(callback), devId_(devId), sessionName_(sessionName), peerSessName_(peerSessName) {};
    ~DaudioSourceCtrlTrans() override {};

    int32_t SetUp(const std::shared_ptr<IAudioCtrlTransCallback> &callback) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t SendAudioEvent(uint32_t type, const std::string &content, const std::string &dstDevId) override;

    void OnChannelEvent(const AVTransEvent &event) override;
    void OnStreamReceived(const StreamData *data, const StreamData *ext) override;
private:
    int32_t WaitForChannelCreated();

private:
    std::weak_ptr<IAudioCtrlTransCallback> ctrlTransCallback_;
    std::string devId_;
    std::string sessionName_;
    std::string peerSessName_;
    std::mutex chnCreatedMtx_;
    std::condition_variable chnCreatedCondVar_;
    std::atomic<bool> chnCreateSuccess_ = false;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif