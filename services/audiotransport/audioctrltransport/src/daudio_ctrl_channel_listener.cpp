/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "daudio_ctrl_channel_listener.h"

#include <dlfcn.h>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "CtrlChannelListener"

namespace OHOS {
namespace DistributedHardware {
int32_t DaudioCtrlChannelListener::Init()
{
    DHLOGI("Init.");
    int32_t ret = SoftbusChannelAdapter::GetInstance().CreateChannelServer(PKG_NAME_D_AUDIO, SESSIONNAME_SPK_SINK);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "spk createChannelServer failed");
    SoftbusChannelAdapter::GetInstance().RegisterChannelListener(SESSIONNAME_SPK_SINK,
        AV_TRANS_SPECIAL_DEVICE_ID, this);

    ret = SoftbusChannelAdapter::GetInstance().CreateChannelServer(PKG_NAME_D_AUDIO, SESSIONNAME_MIC_SINK);
    CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ret, "mic createChannelServer failed");
    SoftbusChannelAdapter::GetInstance().RegisterChannelListener(SESSIONNAME_MIC_SINK,
        AV_TRANS_SPECIAL_DEVICE_ID, this);
    return DH_SUCCESS;
}

int32_t DaudioCtrlChannelListener::UnInit()
{
    DHLOGI("UnInit.");
    SoftbusChannelAdapter::GetInstance().RemoveChannelServer(PKG_NAME_D_AUDIO, SESSIONNAME_SPK_SINK);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(SESSIONNAME_SPK_SINK, AV_TRANS_SPECIAL_DEVICE_ID);

    SoftbusChannelAdapter::GetInstance().RemoveChannelServer(PKG_NAME_D_AUDIO, SESSIONNAME_MIC_SINK);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(SESSIONNAME_MIC_SINK, AV_TRANS_SPECIAL_DEVICE_ID);
    sessionName_ = "";
    ctrlTransCallback_ = nullptr;
    return DH_SUCCESS;
}

void DaudioCtrlChannelListener::OnChannelEvent(const AVTransEvent &event)
{
    CHECK_NULL_VOID(ctrlTransCallback_);
    if ((event.type == EventType::EVENT_CHANNEL_OPENED) || (event.type == EventType::EVENT_CHANNEL_CLOSED)) {
        DHLOGI("on receiver channel event. event type:%{public}" PRId32, event.type);
        ctrlTransCallback_->OnCtrlChannelEvent(event);
    }
}

void DaudioCtrlChannelListener::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}
} // namespace DistributedHardware
} // namespace OHOS