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

#ifndef OHOS_DISTRIBUTED_AUDIO_HIDUMPER_H
#define OHOS_DISTRIBUTED_AUDIO_HIDUMPER_H

#include <string>
#include <vector>
#include "sys/stat.h"

#include "audio_capturer.h"
#include "audio_info.h"

#include "audio_adapter.h"
#include "audio_manager.h"
#include "daudio_handler.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
enum class HidumpFlag {
    UNKNOWN = 0,
    GET_HELP,
    GET_SOURCE_DEVID,
    GET_SINK_INFO,
    GET_ABILITY,
    DUMP_AUDIO_DATA_START,
    DUMP_AUDIO_DATA_STOP,
};
class DaudioHidumper {
    DECLARE_SINGLE_INSTANCE_BASE(DaudioHidumper);

public:
    bool Dump(const std::vector<std::string> &args, std::string &result);
    bool GetFlagStatus();
    DaudioHidumper();
    ~DaudioHidumper();

private:
    void ShowHelp(std::string &result);
    int32_t ShowIllegalInfomation(std::string &result);
    int32_t ProcessDump(const std::string &args, std::string &result);

    int32_t GetSourceDevId(std::string &result);
    int32_t GetSinkInfo(std::string &result);
    int32_t GetAbilityInfo(std::string &result);
    int32_t StartDumpData(std::string &result);
    int32_t StopDumpData(std::string &result);

private:
    std::string g_sourceDevId_ = "";
    AudioManager *g_manager = nullptr;
    AudioAdapterDescriptor *g_devices = nullptr;
    bool HidumperFlag_ = false;
    int32_t g_deviceNum = 0;
    std::string spkDefault = "1";
    std::string micDefault = "134217729";
    const std::string FILE_PATH = "/data/data/daudio";
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_AUDIO_HIDUMPER_H