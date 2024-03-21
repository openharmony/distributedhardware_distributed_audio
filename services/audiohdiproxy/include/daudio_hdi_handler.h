/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_HDI_HANDLER_H
#define OHOS_DAUDIO_HDI_HANDLER_H

#include <map>
#include <mutex>
#include <set>

#include <v2_0/id_audio_callback.h>
#include <v2_0/id_audio_manager.h>
#include "iremote_object.h"

#include "audio_event.h"
#include "daudio_manager_callback.h"
#include "idaudio_hdi_callback.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent;
using OHOS::HDI::DistributedAudio::Audioext::V2_0::IDAudioCallback;
using OHOS::HDI::DistributedAudio::Audioext::V2_0::IDAudioManager;
class DAudioHdiHandler {
    DECLARE_SINGLE_INSTANCE_BASE(DAudioHdiHandler);

public:
    int32_t InitHdiHandler();

    int32_t UninitHdiHandler();

    int32_t RegisterAudioDevice(const std::string &devId, const int32_t dhId, const std::string &capability,
        const std::shared_ptr<IDAudioHdiCallback> &callbackObjParam);

    int32_t UnRegisterAudioDevice(const std::string &devId, const int32_t dhId);

    int32_t NotifyEvent(const std::string &devId, const int32_t dhId,
        const int32_t streamId, const AudioEvent &audioEvent);

private:
    DAudioHdiHandler();
    ~DAudioHdiHandler();
    void ProcessEventMsg(const AudioEvent &audioEvent, DAudioEvent &newEvent);

    class AudioHdiRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    sptr<AudioHdiRecipient> audioHdiRecipient_;

    const std::string HDF_AUDIO_SERVICE_NAME = "daudio_ext_service";
    std::mutex devMapMtx_;
    sptr<IDAudioManager> audioSrvHdf_;
    std::map<std::string, sptr<DAudioManagerCallback>> mapAudioMgrCallback_;
    std::map<std::string, std::set<int32_t>> mapAudioMgrDhIds_;
    sptr<IRemoteObject> remote_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_HDI_HANDLER_H
