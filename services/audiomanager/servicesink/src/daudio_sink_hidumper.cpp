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

#include <unistd.h>

#include "daudio_sink_hidumper.h"

#include "daudio_constants.h"
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
const std::string ARGS_DUMP_AUDIO_DATA_START = "--startDump";
const std::string ARGS_DUMP_AUDIO_DATA_STOP = "--stopDump";

const std::map<std::string, HidumpFlag> ARGS_MAP = {
    { ARGS_HELP, HidumpFlag::GET_HELP },
    { ARGS_DUMP_AUDIO_DATA_START, HidumpFlag::DUMP_AUDIO_DATA_START },
    { ARGS_DUMP_AUDIO_DATA_STOP, HidumpFlag::DUMP_AUDIO_DATA_STOP },
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
    result.clear();
    int32_t argsSize = static_cast<int32_t>(args.size());
    DHLOGI("Distributed audio hidumper dump args.size():%{public}d", argsSize);
    for (int32_t i = 0; i < argsSize; i++) {
        DHLOGI("Distributed audio hidumper dump args[%{public}d]: %{public}s.", i, args.at(i).c_str());
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
        case HidumpFlag::DUMP_AUDIO_DATA_START: {
            return StartDumpData(result);
        }
        case HidumpFlag::DUMP_AUDIO_DATA_STOP: {
            return StopDumpData(result);
        }
        default: {
            return ShowIllegalInfomation(result);
        }
    }
}

int32_t DaudioSinkHidumper::StartDumpData(std::string &result)
{
    if (access(DUMP_FILE_PATH.c_str(), 0) < 0) {
        if (mkdir(DUMP_FILE_PATH.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
            DHLOGE("Create dir error");
            return ERR_DH_AUDIO_FAILED;
        }
    }
    DHLOGI("start dump audio data.");
    result.append("start dump...");
    dumpAudioDataFlag_ = true;
    return DH_SUCCESS;
}

int32_t DaudioSinkHidumper::StopDumpData(std::string &result)
{
    DHLOGI("stop dump audio data.");
    result.append("stop dump...");
    dumpAudioDataFlag_ = false;
    return DH_SUCCESS;
}

bool DaudioSinkHidumper::QueryDumpDataFlag()
{
    return dumpAudioDataFlag_;
}

void DaudioSinkHidumper::ShowHelp(std::string &result)
{
    DHLOGI("Show help.");
    result.append("Usage:dump  <command> [options]\n")
        .append("Description:\n")
        .append("-h            ")
        .append(": show help\n")
        .append("--startDump")
        .append(": start dump audio data in the system /data/data/daudio\n")
        .append("--stopDump")
        .append(": stop dump audio data in the system\n");
}

int32_t DaudioSinkHidumper::ShowIllegalInfomation(std::string &result)
{
    DHLOGI("Show illegal information.");
    result.append("unknown command, -h for help.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS