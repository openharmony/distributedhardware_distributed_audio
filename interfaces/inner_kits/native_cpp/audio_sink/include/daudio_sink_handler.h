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

#ifndef OHOS_DAUDIO_SINK_HANDLER_H
#define OHOS_DAUDIO_SINK_HANDLER_H

#include "idistributed_hardware_sink.h"
#include "daudio_sink_ipc_callback.h"
#include "single_instance.h"

#include "idaudio_sink.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkHandler : public IDistributedHardwareSink {
DECLARE_SINGLE_INSTANCE_BASE(DAudioSinkHandler);
public:
    int32_t InitSink(const std::string &params) override;
    int32_t ReleaseSink() override;
    int32_t SubscribeLocalHardware(const std::string &dhId, const std::string &param) override;
    int32_t UnsubscribeLocalHardware(const std::string &dhId) override;
    void OnRemoteSinkSvrDied(const wptr<IRemoteObject> &remote);
    void FinishStartSA(const std::string &param, const sptr<IRemoteObject> &remoteObject);
    int32_t RegisterPrivacyResources(std::shared_ptr<PrivacyResourcesListener> listener) override;
    int32_t PauseDistributedHardware(const std::string &networkId) override;
    int32_t ResumeDistributedHardware(const std::string &networkId) override;
    int32_t StopDistributedHardware(const std::string &networkId) override;

private:
    class DAudioSinkSvrRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    DAudioSinkHandler();
    ~DAudioSinkHandler();

    std::mutex sinkProxyMutex_;
    std::condition_variable sinkProxyConVar_;
    sptr<IDAudioSink> dAudioSinkProxy_ = nullptr;
    sptr<DAudioSinkSvrRecipient> sinkSvrRecipient_ = nullptr;
    sptr<DAudioSinkIpcCallback> dAudioSinkIpcCallback_ = nullptr;
};

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) IDistributedHardwareSink *GetSinkHardwareHandler();
#ifdef __cplusplus
}
#endif
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SINK_HANDLER_H