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

#include "down_stream_element.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DownStreamElement"
namespace OHOS {
namespace DistributedHardware {
int32_t DownStreamElement::AddDownStream(const std::shared_ptr<IElement> &element)
{
    downStreams_.insert(element);
    return DH_SUCCESS;
}

const std::unordered_set<std::shared_ptr<IElement>>& DownStreamElement::GetDownStreams()
{
    return downStreams_;
}
} // DistributedHardware
} // OHOS