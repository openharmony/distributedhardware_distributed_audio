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

#ifndef OHOS_DAUDIO_SOURCE_HANDLER_H
#define OHOS_DAUDIO_SOURCE_HANDLER_H

#include "daudio_ipc_callback.h"
#include "idaudio_source.h"
#include "idistributed_hardware_source.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSourceHandler : public IDistributedHardwareSource {
DECLARE_SINGLE_INSTANCE_BASE(DAudioSourceHandler);

public:
    int32_t InitSource(const std::string &params) override;
    int32_t ReleaseSource() override;
    int32_t RegisterDistributedHardware(const std::string &devId, const std::string &dhId, const EnableParam &param,
        std::shared_ptr<RegisterCallback> callback) override;
    int32_t UnregisterDistributedHardware(const std::string &devId, const std::string &dhId,
        std::shared_ptr<UnregisterCallback> callback) override;
    int32_t ConfigDistributedHardware(const std::string &devId, const std::string &dhId, const std::string &key,
        const std::string &value) override;
    void RegisterDistributedHardwareStateListener(std::shared_ptr<DistributedHardwareStateListener> listener) override;
    void UnregisterDistributedHardwareStateListener() override;
    void RegisterDataSyncTriggerListener(std::shared_ptr<DataSyncTriggerListener> listener) override;
    void UnregisterDataSyncTriggerListener() override;
    void OnRemoteSourceSvrDied(const wptr<IRemoteObject> &remote);
    void FinishStartSA(const std::string &param, const sptr<IRemoteObject> &remoteObject);

private:
    class DAudioSourceSvrRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    DAudioSourceHandler();
    ~DAudioSourceHandler();

    std::mutex sourceProxyMutex_;
    std::condition_variable sourceProxyConVar_;
    sptr<IDAudioSource> dAudioSourceProxy_ = nullptr;
    sptr<DAudioIpcCallback> dAudioIpcCallback_ = nullptr;
    sptr<DAudioSourceSvrRecipient> sourceSvrRecipient_ = nullptr;
};

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) IDistributedHardwareSource *GetSourceHardwareHandler();
#ifdef __cplusplus
}
#endif
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SOURCE_HANDLER_H