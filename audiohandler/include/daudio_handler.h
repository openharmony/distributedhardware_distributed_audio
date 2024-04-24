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

#ifndef OHOS_DAUDIO_HANDLER_H
#define OHOS_DAUDIO_HANDLER_H

#include <set>
#include "cJSON.h"

#include "ihardware_handler.h"
#include "single_instance.h"
#include "audio_param.h"
#include "audio_capturer.h"
#include "audio_info.h"
#include "audio_renderer.h"

namespace OHOS {
namespace DistributedHardware {
typedef struct {
    std::vector<AudioStandard::AudioSamplingRate> sampleRates;
    std::vector<AudioStandard::AudioChannel> channels;
    std::vector<AudioStandard::AudioSampleFormat> formats;
} AudioInfo;

class DAudioHandler : public IHardwareHandler {
DECLARE_SINGLE_INSTANCE_BASE(DAudioHandler);

public:
    int32_t Initialize() override;
    std::vector<DHItem> QueryMeta() override;
    std::vector<DHItem> Query() override;
    std::map<std::string, std::string> QueryExtraInfo() override;
    bool IsSupportPlugin() override;
    void RegisterPluginListener(std::shared_ptr<PluginListener> listener) override;
    void UnRegisterPluginListener() override;
    std::vector<DHItem> ablityForDump();
    std::vector<DHItem> ablityForDumpVec_;
private:
    DAudioHandler();
    ~DAudioHandler();
    int32_t QueryAudioInfo();
    bool AddItemsToObject(DHItem &dhItem, cJSON *infoJson, const int32_t &dhId);
private:
    AudioInfo spkInfos_;
    AudioInfo micInfos_;
    std::shared_ptr<PluginListener> listener_ = nullptr;
};

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) IHardwareHandler *GetHardwareHandler();
#ifdef __cplusplus
}
#endif
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_HANDLER_H
