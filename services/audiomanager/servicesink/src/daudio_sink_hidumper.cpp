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

#include "daudio_sink_hidumper.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DaudioSinkHidumper"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DaudioSinkHidumper);

namespace {
const std::string ARGS_HELP = "-h";
const std::string ARGS_DUMP_SINK_AUDIO_DATA = "--dumpSinkAudioData";

const std::map<std::string, HidumpFlag> ARGS_MAP = {
    { ARGS_HELP, HidumpFlag::GET_HELP },
    { ARGS_DUMP_SINK_AUDIO_DATA, HidumpFlag::DUMP_SINK_AUDIO_DATA },
};
}

DaudioSinkHidumper::DaudioSinkHidumper()
{
    DHLOGI("Distributed audio hidumper constructed.");
}

DaudioSinkHidumper::~DaudioSinkHidumper()
{
    DHLOGI("Distributed audio hidumper deconstructed.");
}

bool DaudioSinkHidumper::Dump(const std::vector<std::string> &args, std::string &result)
{
    DHLOGI("Distributed audio hidumper dump args.size():%d.", args.size());
    result.clear();
    int32_t argsSize = static_cast<int32_t>(args.size());
    for (int32_t i = 0; i < argsSize; i++) {
        DHLOGI("Distributed audio hidumper dump args[%d]: %s.", i, args.at(i).c_str());
    }

    if (args.empty()) {
        ShowHelp(result);
        return true;
    } else if (args.size() > 1) {
        ShowIllegalInfomation(result);
        return true;
    }

    return ProcessDump(args[0], result) == DH_SUCCESS;
}

int32_t DaudioSinkHidumper::ProcessDump(const std::string &args, std::string &result)
{
    DHLOGI("Process dump.");
    HidumpFlag hf = HidumpFlag::UNKNOWN;
    auto operatorIter = ARGS_MAP.find(args);
    if (operatorIter != ARGS_MAP.end()) {
        hf = operatorIter->second;
    }

    if (hf == HidumpFlag::GET_HELP) {
        ShowHelp(result);
        return DH_SUCCESS;
    }
    result.clear();
    switch (hf) {
        case HidumpFlag::DUMP_SINK_AUDIO_DATA: {
            return DumpAudioData(result);
        }
        default: {
            return ShowIllegalInfomation(result);
        }
    }
}

int32_t DaudioSinkHidumper::DumpAudioData(std::string &result)
{
    DHLOGI("Dump audio data.");
    result.append("Dump...");
    HidumperFlag_ = true;
    return DH_SUCCESS;
}

bool DaudioSinkHidumper::GetFlagStatus()
{
    return HidumperFlag_;
}

void DaudioSinkHidumper::ShowHelp(std::string &result)
{
    DHLOGI("Show help.");
    result.append("Usage:dump  <command> [options]\n")
        .append("Description:\n")
        .append("-h            ")
        .append(": show help\n")
        .append("--dumpSinkAudioData     ")
        .append(": dump sink audio data\n");
}

int32_t DaudioSinkHidumper::ShowIllegalInfomation(std::string &result)
{
    DHLOGI("Show illegal information.");
    result.append("unknown command, -h for help.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS