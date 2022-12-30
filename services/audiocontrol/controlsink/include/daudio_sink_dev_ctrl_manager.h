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

#ifndef OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_H
#define OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_H

#include <atomic>
#include <map>
#include <mutex>

#include "audio_event.h"
#include "iaudio_ctrl_transport.h"
#include "iaudio_event_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkDevCtrlMgr : public IAudioCtrlTransCallback, public std::enable_shared_from_this<DAudioSinkDevCtrlMgr> {
public:
    DAudioSinkDevCtrlMgr(const std::string &networkId, std::shared_ptr<IAudioEventCallback> audioEventCallback);
    ~DAudioSinkDevCtrlMgr() override;

    void OnStateChange(int32_t type) override;
    void OnEventReceived(const AudioEvent &event) override;
    int32_t SetUp();
    int32_t Start();
    int32_t Stop();
    int32_t Release();
    bool IsOpened();
    int32_t SendAudioEvent(const AudioEvent &event);

private:
    std::string devId_;
    std::weak_ptr<IAudioEventCallback> audioEventCallback_;
    std::shared_ptr<IAudioCtrlTransport> audioCtrlTrans_ = nullptr;
    std::atomic<bool> isOpened_ = false;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_SINK_DEV_CTRL_MANAGER_H
