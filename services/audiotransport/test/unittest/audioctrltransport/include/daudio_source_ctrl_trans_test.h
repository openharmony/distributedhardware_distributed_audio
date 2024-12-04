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

#ifndef OHOS_DAUDIO_SOURCE_CTRL_TRANS_TEST_H
#define OHOS_DAUDIO_SOURCE_CTRL_TRANS_TEST_H

#include <gtest/gtest.h>

#define private public
#include "daudio_source_ctrl_trans.h"
#undef private

namespace OHOS {
namespace DistributedHardware {
class CtrlTransCallback : public IAudioCtrlTransCallback {
public:
    CtrlTransCallback() {};
    ~CtrlTransCallback() override {};

    void OnCtrlTransEvent(const AVTransEvent &event) override;
    void OnCtrlTransMessage(const std::shared_ptr<AVTransMessage> &message) override;
};

class DaudioSourceCtrlTransTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<CtrlTransCallback> ctrlTransCallback_ = nullptr;
    std::shared_ptr<DaudioSourceCtrlTrans> ctrlTrans_ = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_SOURCE_CTRL_TRANS_TEST_H
