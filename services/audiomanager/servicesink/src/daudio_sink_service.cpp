/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "daudio_sink_service.h"

#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_log.h"
#include "daudio_sink_manager.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkService"

namespace OHOS {
namespace DistributedHardware {
REGISTER_SYSTEM_ABILITY_BY_ID(DAudioSinkService, DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, true);

DAudioSinkService::DAudioSinkService(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
    DHLOGD("Distributed audio sink service constructed.");
}

void DAudioSinkService::OnStart()
{
    DHLOGI("Distributed audio service on start.");
    if (!Init()) {
        DHLOGE("Init service failed.");
        return;
    }
    DHLOGI("Start distributed audio service success.");
}

void DAudioSinkService::OnStop()
{
    DHLOGI("Distributed audio service on stop.");
    isServiceStarted_ = false;
}

bool DAudioSinkService::Init()
{
    DHLOGI("Start init distributed audio service.");
    if (!isServiceStarted_) {
        bool ret = Publish(this);
        if (!ret) {
            DHLOGE("Publish service failed.");
            return false;
        }
        isServiceStarted_ = true;
    }
    DHLOGI("Init distributed audio service success.");
    return true;
}

int32_t DAudioSinkService::InitSink(const std::string &params, const sptr<IDAudioSinkIpcCallback> &sinkCallback)
{
    DAudioSinkManager::GetInstance().Init(sinkCallback);
    return DH_SUCCESS;
}

int32_t DAudioSinkService::ReleaseSink()
{
    DHLOGI("Release sink service.");
    DAudioSinkManager::GetInstance().UnInit();
    DHLOGI("Audio sink service process exit.");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_NULL_RETURN(systemAbilityMgr, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = systemAbilityMgr->UnloadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (ret != DH_SUCCESS) {
        DHLOGE("Sink systemabilitymgr unloadsystemability failed, ret: %{public}d", ret);
        return ERR_DH_AUDIO_SA_LOAD_FAILED;
    }
    DHLOGI("Sink systemabilitymgr unloadsystemability successfully!");
    return DH_SUCCESS;
}

int32_t DAudioSinkService::SubscribeLocalHardware(const std::string &dhId, const std::string &param)
{
    DHLOGI("Subscribe local hardware.");
    return DH_SUCCESS;
}

int32_t DAudioSinkService::UnsubscribeLocalHardware(const std::string &dhId)
{
    DHLOGI("Unsubscribe local hardware.");
    return DH_SUCCESS;
}

void DAudioSinkService::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGI("DAudioNotify devId:%{public}s, dhId:%{public}s, eventType:%{public}d.", GetAnonyString(devId).c_str(),
        dhId.c_str(), eventType);
    DAudioSinkManager::GetInstance().HandleDAudioNotify(devId, dhId, eventType, eventContent);
}

int DAudioSinkService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    DHLOGD("Distributed audio sink service dump.");
    std::string result;
    std::vector<std::string> argsStr;

    std::transform(args.cbegin(), args.cend(), std::back_inserter(argsStr),
        [](const std::u16string& item) { return Str16ToStr8(item); });

    if (!DaudioSinkHidumper::GetInstance().Dump(argsStr, result)) {
        DHLOGE("Hidump error");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        DHLOGE("Dprintf error");
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    return DH_SUCCESS;
}

int32_t DAudioSinkService::PauseDistributedHardware(const std::string &networkId)
{
    DHLOGI("PauseDistributedHardware networkId:%{public}s.", GetAnonyString(networkId).c_str());
    DAudioSinkManager::GetInstance().PauseDistributedHardware(networkId);
    return DH_SUCCESS;
}

int32_t DAudioSinkService::ResumeDistributedHardware(const std::string &networkId)
{
    DHLOGI("ResumeDistributedHardware networkId:%{public}s.", GetAnonyString(networkId).c_str());
    DAudioSinkManager::GetInstance().ResumeDistributedHardware(networkId);
    return DH_SUCCESS;
}

int32_t DAudioSinkService::StopDistributedHardware(const std::string &networkId)
{
    DHLOGI("StopDistributedHardware networkId:%{public}s.", GetAnonyString(networkId).c_str());
    DAudioSinkManager::GetInstance().StopDistributedHardware(networkId);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS