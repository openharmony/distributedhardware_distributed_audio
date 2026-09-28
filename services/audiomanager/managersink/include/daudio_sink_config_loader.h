/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_SINK_CONFIG_LOADER_H
#define OHOS_DAUDIO_SINK_CONFIG_LOADER_H

#include <string>

#include "cJSON.h"
#include "dhfwk_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioSinkConfigLoader {
    FWK_DECLARE_SINGLE_INSTANCE_BASE(DAudioSinkConfigLoader);
public:
    int32_t Init();
    bool IsMicSinkEnabled() const;
    bool IsSpeakerSinkEnabled() const;

private:
    DAudioSinkConfigLoader() = default;
    ~DAudioSinkConfigLoader() = default;
    std::string ReadConfigFile();
    void ParseAudioEnableConfig(const cJSON *root);

private:
    bool micSinkEnabled_ = true;
    bool speakerSinkEnabled_ = true;
    bool isInitialized_ = false;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SINK_CONFIG_LOADER_H
