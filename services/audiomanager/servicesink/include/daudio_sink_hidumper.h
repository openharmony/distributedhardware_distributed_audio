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

#ifndef OHOS_DISTRIBUTED_AUDIO_SINK_HIDUMPER_H
#define OHOS_DISTRIBUTED_AUDIO_SINK_HIDUMPER_H

#include <map>
#include <string>
#include <vector>
#include "sys/stat.h"

#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
enum class HidumpFlag {
    UNKNOWN = 0,
    GET_HELP,
    DUMP_AUDIO_DATA_START,
    DUMP_AUDIO_DATA_STOP,
};
class DaudioSinkHidumper {
    DECLARE_SINGLE_INSTANCE_BASE(DaudioSinkHidumper);

public:
    bool Dump(const std::vector<std::string> &args, std::string &result);
    bool QueryDumpDataFlag();
    DaudioSinkHidumper();
    ~DaudioSinkHidumper();

private:
    void ShowHelp(std::string &result);
    int32_t ShowIllegalInfomation(std::string &result);
    int32_t ProcessDump(const std::string &args, std::string &result);

    int32_t StartDumpData(std::string &result);
    int32_t StopDumpData(std::string &result);

private:
    bool dumpAudioDataFlag_ = false;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_AUDIO_SINK_HIDUMPER_H