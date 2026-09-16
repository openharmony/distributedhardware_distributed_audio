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

#include "daudio_sink_config_loader.h"

#include <climits>
#include <fstream>

#include "config_policy_utils.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkCfgLoader"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr const char *COMPONENTSLOAD_PROFILE_PATH =
    "etc/distributedhardware/distributed_hardware_components_cfg.json";
constexpr const char *COMPONENT_ENABLE_CONFIG = "component_enable_config";
constexpr const char *AUDIO_TYPE_NAME = "AUDIO";
constexpr const char *ROLE_SINK = "sink";
}

FWK_IMPLEMENT_SINGLE_INSTANCE(DAudioSinkConfigLoader);

std::string DAudioSinkConfigLoader::ReadConfigFile()
{
    char buf[MAX_PATH_LEN] = {0};
    char *profilePath = GetOneCfgFile(COMPONENTSLOAD_PROFILE_PATH, buf, MAX_PATH_LEN);
    if (profilePath == nullptr || strlen(profilePath) == 0 || strlen(profilePath) > PATH_MAX) {
        DHLOGE("Get config file path failed.");
        return "";
    }
    char path[PATH_MAX] = {0x00};
    if (realpath(profilePath, path) == nullptr) {
        DHLOGE("Get config file path failed.");
        return "";
    }
    std::ifstream infile(path);
    if (!infile.is_open()) {
        DHLOGE("Open config file failed.");
        return "";
    }
    std::string sLine;
    std::string sAll;
    while (getline(infile, sLine)) {
        sAll.append(sLine);
    }
    infile.close();
    return sAll;
}

void DAudioSinkConfigLoader::ParseAudioEnableConfig(const cJSON *root)
{
    if (root == nullptr) {
        return;
    }
    cJSON *enableConfig = cJSON_GetObjectItem(root, COMPONENT_ENABLE_CONFIG);
    if (enableConfig == nullptr || !cJSON_IsObject(enableConfig)) {
        DHLOGI("component_enable_config not found, use default (all enabled).");
        return;
    }
    cJSON *audioEntry = cJSON_GetObjectItem(enableConfig, AUDIO_TYPE_NAME);
    if (audioEntry == nullptr || !cJSON_IsObject(audioEntry)) {
        DHLOGI("AUDIO entry not found in component_enable_config, use default (all enabled).");
        return;
    }
    cJSON *micEntry = cJSON_GetObjectItem(audioEntry, MIC.c_str());
    if (micEntry != nullptr) {
        if (cJSON_IsBool(micEntry)) {
            micSinkEnabled_ = cJSON_IsTrue(micEntry);
        } else if (cJSON_IsObject(micEntry)) {
            cJSON *sinkItem = cJSON_GetObjectItem(micEntry, ROLE_SINK);
            if (sinkItem != nullptr && cJSON_IsBool(sinkItem)) {
                micSinkEnabled_ = cJSON_IsTrue(sinkItem);
            }
        }
    }
    cJSON *spkEntry = cJSON_GetObjectItem(audioEntry, SPEAKER.c_str());
    if (spkEntry != nullptr) {
        if (cJSON_IsBool(spkEntry)) {
            speakerSinkEnabled_ = cJSON_IsTrue(spkEntry);
        } else if (cJSON_IsObject(spkEntry)) {
            cJSON *sinkItem = cJSON_GetObjectItem(spkEntry, ROLE_SINK);
            if (sinkItem != nullptr && cJSON_IsBool(sinkItem)) {
                speakerSinkEnabled_ = cJSON_IsTrue(sinkItem);
            }
        }
    }
    DHLOGI("Parse audio enable config: micSink=%{public}d, speakerSink=%{public}d.",
        micSinkEnabled_, speakerSinkEnabled_);
}

int32_t DAudioSinkConfigLoader::Init()
{
    if (isInitialized_) {
        return DH_SUCCESS;
    }
    std::string jsonStr = ReadConfigFile();
    if (jsonStr.empty()) {
        DHLOGW("Config file is empty, use default (all enabled).");
        isInitialized_ = true;
        return DH_SUCCESS;
    }
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        DHLOGE("Parse config json failed, use default (all enabled).");
        isInitialized_ = true;
        return DH_SUCCESS;
    }
    ParseAudioEnableConfig(root);
    cJSON_Delete(root);
    isInitialized_ = true;
    return DH_SUCCESS;
}

bool DAudioSinkConfigLoader::IsMicSinkEnabled() const
{
    return micSinkEnabled_;
}

bool DAudioSinkConfigLoader::IsSpeakerSinkEnabled() const
{
    return speakerSinkEnabled_;
}
} // namespace DistributedHardware
} // namespace OHOS
