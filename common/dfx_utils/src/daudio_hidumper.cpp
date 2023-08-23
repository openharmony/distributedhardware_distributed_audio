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

#include "daudio_hidumper.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DaudioHidumper"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DaudioHidumper);

namespace {
const std::string ARGS_HELP = "-h";
const std::string ARGS_SOURCE_DEVID = "--sourceDevId";
const std::string ARGS_SINK_INFO = "--sinkInfo";
const std::string ARGS_ABILITY = "--ability";
const std::string ARGS_DUMP_AUDIO_DATA = "--dumpAudioData";

const std::map<std::string, HidumpFlag> ARGS_MAP = {
    { ARGS_HELP, HidumpFlag::GET_HELP },
    { ARGS_SOURCE_DEVID, HidumpFlag::GET_SOURCE_DEVID },
    { ARGS_SINK_INFO, HidumpFlag::GET_SINK_INFO },
    { ARGS_ABILITY, HidumpFlag::GET_ABILITY },
    { ARGS_DUMP_AUDIO_DATA, HidumpFlag::DUMP_AUDIO_DATA },
};
}

DaudioHidumper::DaudioHidumper()
{
    DHLOGI("Distributed audio hidumper constructed.");
}

DaudioHidumper::~DaudioHidumper()
{
    DHLOGI("Distributed audio hidumper deconstructed.");
}

bool DaudioHidumper::Dump(const std::vector<std::string> &args, std::string &result)
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

int32_t DaudioHidumper::ProcessDump(const std::string &args, std::string &result)
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
        case HidumpFlag::GET_SOURCE_DEVID: {
            return GetSourceDevId(result);
        }
        case HidumpFlag::GET_SINK_INFO: {
            return GetSinkInfo(result);
        }
        case HidumpFlag::GET_ABILITY: {
            return GetAbilityInfo(result);
        }
        case HidumpFlag::DUMP_AUDIO_DATA: {
            return DumpAudioData(result);
        }
        default: {
            return ShowIllegalInfomation(result);
        }
    }
}

int32_t DaudioHidumper::GetSourceDevId(std::string &result)
{
    DHLOGI("Get source devId dump.");
    int32_t ret = GetLocalDeviceNetworkId(g_sourceDevId_);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get local network id failed.");
        result.append("sourceDevId: ").append("");
        return ret;
    }
    result.append("sourceDevId: ").append(GetAnonyString(g_sourceDevId_));
    return DH_SUCCESS;
}

int32_t DaudioHidumper::GetSinkInfo(std::string &result)
{
    DHLOGI("Get sink info dump.");
    g_manager = GetAudioManagerFuncs();
    if (g_manager == nullptr) {
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t ret = g_manager->GetAllAdapters(g_manager, &g_devices, &g_deviceNum);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get all adapters failed.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    for (int32_t index = 0; index < g_deviceNum; index++) {
        AudioAdapterDescriptor &desc = g_devices[index];
        result.append("sinkDevId: ").append(GetAnonyString(desc.adapterName)).append("    portId: ");
        for (uint32_t i = 0; i < desc.portNum; i++) {
            result.append(std::to_string(desc.ports[i].portId)).append(" ");
        }
    }

    return DH_SUCCESS;
}

int32_t DaudioHidumper::GetAbilityInfo(std::string &result)
{
    DHLOGI("Obtaining capability information.");
    std::vector<DHItem> abilityInfo = DAudioHandler::GetInstance().ablityForDump();
    for (DHItem dhItem : abilityInfo) {
        if (dhItem.dhId == spkDefault) {
            result.append("spkAbilityInfo:").append(dhItem.attrs).append("      ");
        }
        if (dhItem.dhId == micDefault) {
            result.append("micAbilityInfo:").append(dhItem.attrs).append("      ");
        }
    }
    return DH_SUCCESS;
}

int32_t DaudioHidumper::DumpAudioData(std::string &result)
{
    DHLOGI("Dump audio data.");
    result.append("dump...");
    HidumperFlag_ = true;
    return DH_SUCCESS;
}

bool DaudioHidumper::GetFlagStatus()
{
    return HidumperFlag_;
}

void DaudioHidumper::ShowHelp(std::string &result)
{
    DHLOGI("Show help.");
    result.append("Usage:dump  <command> [options]\n")
        .append("Description:\n")
        .append("-h            ")
        .append(": show help\n")
        .append("--sourceDevId ")
        .append(": dump audio sourceDevId in the system\n")
        .append("--sinkInfo    ")
        .append(": dump sink info in the system\n")
        .append("--ability     ")
        .append(": dump current ability of the audio in the system\n")
        .append("--dumpAudioData")
        .append(": dump audio data in the system\n");
}

int32_t DaudioHidumper::ShowIllegalInfomation(std::string &result)
{
    DHLOGI("Show illegal information.");
    result.append("unknown command, -h for help.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS