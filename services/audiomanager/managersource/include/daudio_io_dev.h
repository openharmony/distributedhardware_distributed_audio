/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_IO_DEV_H
#define OHOS_DAUDIO_IO_DEV_H

#include <queue>
#include <set>
#include <thread>

#include "audio_param.h"
#include "audio_status.h"
#include "av_receiver_engine_transport.h"
#include "ashmem.h"
#include "daudio_hdi_handler.h"
#include "iaudio_data_transport.h"
#include "iaudio_datatrans_callback.h"
#include "iaudio_event_callback.h"
#include "idaudio_hdi_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioIoDev : public IDAudioHdiCallback {
public:
    explicit DAudioIoDev(const std::string &devId)
        : devId_(devId) {};
    ~DAudioIoDev() override = default;
    virtual int32_t InitReceiverEngine(IAVEngineProvider *providerPtr) = 0;
    virtual int32_t InitSenderEngine(IAVEngineProvider *providerPtr) = 0;

    virtual int32_t EnableDevice(const int32_t dhId, const std::string &capability) = 0;
    virtual int32_t DisableDevice(const int32_t dhId) = 0;

    virtual int32_t MmapStart() = 0;
    virtual int32_t MmapStop() = 0;

    virtual int32_t SetUp() = 0;
    virtual int32_t Start() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Restart() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Release() = 0;
    virtual bool IsOpened() = 0;
    virtual int32_t SendMessage(uint32_t type, std::string content, std::string dstDevId) = 0;

    virtual AudioParam GetAudioParam() const = 0;
    virtual int32_t NotifyHdfAudioEvent(const AudioEvent &event, const int32_t portId) = 0;

protected:
    const std::string devId_;
};
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_IO_DEV_H