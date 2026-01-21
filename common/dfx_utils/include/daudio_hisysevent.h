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

#ifndef OHOS_DAUDIO_HISYSEVENT_H
#define OHOS_DAUDIO_HISYSEVENT_H

#include <cstring>
#include <string>

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "hisysevent.h"
#include "av_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
const std::string DAUDIO_INIT = "DAUDIO_INIT";
const std::string DAUDIO_EXIT = "DAUDIO_EXIT";
const std::string DAUDIO_OPEN = "DAUDIO_OPEN";
const std::string DAUDIO_CLOSE = "DAUDIO_CLOSE";
const std::string DAUIDO_REGISTER = "DAUIDO_REGISTER";
const std::string DAUDIO_UNREGISTER = "DAUDIO_UNREGISTER";

const std::string DAUDIO_OPT_FAIL = "DAUDIO_OPT_FAIL";
const std::string DAUDIO_INIT_FAIL = "DAUDIO_INIT_FAIL";
const std::string DAUDIO_REGISTER_FAIL = "DAUDIO_REGISTER_FAIL";
const std::string DAUDIO_UNREGISTER_FAIL = "DAUDIO_UNREGISTER_FAIL";

class DAudioHisysevent {
    AV_DECLARE_SINGLE_INSTANCE_BASE(DAudioHisysevent);

public:
    void SysEventWriteBehavior(const std::string &eventName, const std::string &msg);
    void SysEventWriteBehavior(const std::string &eventName, int32_t saId, const std::string &msg);
    void SysEventWriteBehavior(const std::string &eventName, const std::string &devId, const std::string &dhId,
        const std::string &msg);
    void SysEventWriteFault(const std::string &eventName, const std::string &msg);
    void SysEventWriteFault(const std::string &eventName, int32_t saId, int32_t errorCode, const std::string &msg);
    void SysEventWriteFault(const std::string &eventName, int32_t errorCode, const std::string &msg);
    void SysEventWriteFault(const std::string &eventName, const std::string &devId, const std::string &dhId,
        int32_t errorCode, const std::string &msg);

private:
    DAudioHisysevent() = default;
    ~DAudioHisysevent() = default;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif