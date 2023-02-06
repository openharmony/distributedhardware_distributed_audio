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

#ifndef SOURCE_ELEMENT_H
#define SOURCE_ELEMENT_H

#include "down_stream_element.h"

namespace OHOS {
namespace DistributedHardware {

class SourceElement : public DownStreamElement {
public:
    SourceElement() = default;
    ~SourceElement() = default;
    int32_t Init(const std::string config) override;
    int32_t StartUp() override;
    int32_t ShutDown() override;
    int32_t Release() override;
    std::string GetType() override;
    int32_t PushData(std::shared_ptr<AudioData> &inData, std::shared_ptr<AudioData> &outData) override;

protected:
    int32_t DoProcessData(std::shared_ptr<AudioData> &inData, std::shared_ptr<AudioData> &outData) override;

private:
    std::string elemType_ = SOURCE_REF;
};
} // OHOS
} // DistributedHardware
#endif // SOURCE_ELEMENT_H