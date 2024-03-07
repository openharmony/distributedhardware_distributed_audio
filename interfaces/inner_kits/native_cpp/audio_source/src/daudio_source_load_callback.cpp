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

#include "daudio_source_load_callback.h"

#include "daudio_hisysevent.h"
#include "daudio_log.h"
#include "daudio_source_handler.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceLoadCallback"

namespace OHOS {
namespace DistributedHardware {
void DAudioSourceLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject> &remoteObject)
{
    DHLOGI("Load audio SA success, systemAbilityId: %{public}d.", systemAbilityId);
    CHECK_NULL_VOID(remoteObject);
    DAudioSourceHandler::GetInstance().FinishStartSA(params_, remoteObject);
}

void DAudioSourceLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    DHLOGE("Load audio SA failed, systemAbilityId: %{public}d", systemAbilityId);
    DAudioHisysevent::GetInstance().SysEventWriteFault(DAUDIO_INIT_FAIL, "daudio source LoadSA call failed.");
}
} // namespace DistributedHardware
} // namespace OHOS