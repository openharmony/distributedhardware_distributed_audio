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

#include "daudio_hitrace.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHitrace"

namespace OHOS {
namespace DistributedHardware {
void DAudioHitrace::Count(const std::string &value, int64_t count, bool isEnable)
{
    CountTraceDebug(isEnable, HITRACE_TAG_ZAUDIO, value, count);
}

DAudioHitrace::DAudioHitrace(const std::string &value, bool isShowLog, bool isEnable)
{
    value_ = value;
    isShowLog_ = isShowLog;
    isEnable_ = isEnable;
    isFinished_ = false;
    if (isShowLog) {
        isShowLog_ = true;
        DHLOGI("%{public}s start.", value_.c_str());
    }
    StartTraceDebug(isEnable_, HITRACE_TAG_ZAUDIO, value);
}

void DAudioHitrace::End()
{
    if (!isFinished_) {
        FinishTraceDebug(isEnable_, HITRACE_TAG_ZAUDIO);
        isFinished_ = true;
        if (isShowLog_) {
            DHLOGI("%{public}s end.", value_.c_str());
        }
    }
}

DAudioHitrace::~DAudioHitrace()
{
    End();
}
} // namespace DistributedHardware
} // namespace OHOS