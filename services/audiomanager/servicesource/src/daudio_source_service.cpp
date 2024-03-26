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

#include "daudio_source_service.h"

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
#include "daudio_source_manager.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceService"

namespace OHOS {
namespace DistributedHardware {
REGISTER_SYSTEM_ABILITY_BY_ID(DAudioSourceService, DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID, true);
void DAudioSourceService::OnStart()
{
    DHLOGI("Distributed audio service on start.");
    if (!Init()) {
        DHLOGE("Init service failed.");
        return;
    }
    DHLOGI("Start distributed audio service success.");
}

void DAudioSourceService::OnStop()
{
    DHLOGI("Distributed audio service on stop.");
    isServiceStarted_ = false;
}

bool DAudioSourceService::Init()
{
    if (!isServiceStarted_) {
        DHLOGI("Publish distributed audio service.");
        bool ret = Publish(this);
        if (!ret) {
            DHLOGE("Publish service failed.");
            return false;
        }
        isServiceStarted_ = true;
    }
    return true;
}

int32_t DAudioSourceService::InitSource(const std::string &params, const sptr<IDAudioIpcCallback> &callback)
{
    DHLOGI("Init source service.");
    (void)params;
    int32_t ret = DAudioSourceManager::GetInstance().Init(callback);
    if (ret != DH_SUCCESS) {
        DHLOGE("Distributed audio source manager init failed.");
        return ret;
    }
    return DH_SUCCESS;
}

int32_t DAudioSourceService::ReleaseSource()
{
    DHLOGI("Release source service.");
    DAudioHisysevent::GetInstance().SysEventWriteBehavior(DAUDIO_EXIT, "daudio source sa exit success.");
    DAudioSourceManager::GetInstance().UnInit();
    DHLOGI("Audio source service process exit.");
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_NULL_RETURN(systemAbilityMgr, ERR_DH_AUDIO_NULLPTR);
    int32_t ret = systemAbilityMgr->UnloadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SOURCE_SA_ID);
    if (ret != DH_SUCCESS) {
        DHLOGE("Source systemabilitymgr unloadsystemability failed, ret: %{public}d", ret);
        return ERR_DH_AUDIO_SA_LOAD_FAILED;
    }
    DHLOGI("Source systemabilitymgr unloadsystemability successfully!");
    return DH_SUCCESS;
}

int32_t DAudioSourceService::RegisterDistributedHardware(const std::string &devId, const std::string &dhId,
    const EnableParam &param, const std::string &reqId)
{
    DHLOGI("Register distributed audio device, devId: %{public}s, dhId: %{public}s.", GetAnonyString(devId).c_str(),
        dhId.c_str());
    std::string version = param.sinkVersion;
    std::string attrs = param.sinkAttrs;
    return DAudioSourceManager::GetInstance().EnableDAudio(devId, dhId, version, attrs, reqId);
}

int32_t DAudioSourceService::UnregisterDistributedHardware(const std::string &devId, const std::string &dhId,
    const std::string &reqId)
{
    DHLOGI("Unregister distributed audio device, devId: %{public}s, dhId: %{public}s.", GetAnonyString(devId).c_str(),
        dhId.c_str());
    return DAudioSourceManager::GetInstance().DisableDAudio(devId, dhId, reqId);
}

int32_t DAudioSourceService::ConfigDistributedHardware(const std::string &devId, const std::string &dhId,
    const std::string &key, const std::string &value)
{
    DHLOGI("Config distributed audio device, devId: %{public}s, dhId: %{public}s.", GetAnonyString(devId).c_str(),
        dhId.c_str());
    return DH_SUCCESS;
}

void DAudioSourceService::DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
    const std::string &eventContent)
{
    DHLOGD("Notify distributed audio device, devId: %{public}s, dhId: %{public}s.", GetAnonyString(devId).c_str(),
        dhId.c_str());
    DAudioSourceManager::GetInstance().HandleDAudioNotify(devId, dhId, eventType, eventContent);
}

int DAudioSourceService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    DHLOGD("Distributed audio source service dump.");
    std::string result;
    std::vector<std::string> argsStr;

    std::transform(args.cbegin(), args.cend(), std::back_inserter(argsStr),
        [](const std::u16string& item) { return Str16ToStr8(item); });

    if (!DaudioHidumper::GetInstance().Dump(argsStr, result)) {
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
} // namespace DistributedHardware
} // namespace OHOS