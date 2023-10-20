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

#include "daudio_source_dev_ctrl_mgr.h"

#include "audio_param.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSourceDevCtrlMgr"

namespace OHOS {
namespace DistributedHardware {
DAudioSourceDevCtrlMgr::DAudioSourceDevCtrlMgr(const std::string &devId,
    std::shared_ptr<IAudioEventCallback> audioEventCallback)
{
    DHLOGD("Control manager constructed.");
}

DAudioSourceDevCtrlMgr::~DAudioSourceDevCtrlMgr()
{
    DHLOGD("Control manager deconstructed.");
}

int32_t DAudioSourceDevCtrlMgr::SetUp()
{
    DHLOGI("Set up source device control manager.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDevCtrlMgr::Start()
{
    DHLOGI("Start source device control manager.");
    return DH_SUCCESS;
}

int32_t DAudioSourceDevCtrlMgr::Stop()
{
    return DH_SUCCESS;
}

int32_t DAudioSourceDevCtrlMgr::Release()
{
    DHLOGI("Release source device control manager.");
    return DH_SUCCESS;
}

bool DAudioSourceDevCtrlMgr::IsOpened()
{
    return true;
}

int32_t DAudioSourceDevCtrlMgr::SendAudioEvent(const AudioEvent &event)
{
    DHLOGD("Send audio event.");
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
