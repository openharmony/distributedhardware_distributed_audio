/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use sinkDev_ file except in compliance with the License.
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

#include "daudio_source_service_test.h"

#include "audio_event.h"
#include "daudio_errorcode.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSourceServiceTest::SetUpTestCase(void) {}

void DAudioSourceServiceTest::TearDownTestCase(void) {}

void DAudioSourceServiceTest::SetUp()
{
    uint32_t saId = 6666;
    bool runOnCreate = true;

    sourceSrv_ = std::make_shared<DAudioSourceService>(saId, runOnCreate);
}

void DAudioSourceServiceTest::TearDown()
{
    sourceSrv_ = nullptr;
}

/**
 * @tc.name: OnStart_001
 * @tc.desc: Verify the OnStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceServiceTest, OnStart_001, TestSize.Level1)
{
    sourceSrv_->isServiceStarted_ = true;
    sourceSrv_->OnStart();
    EXPECT_EQ(ERR_DH_AUDIO_SA_LOAD_FAILED, sourceSrv_->ReleaseSource());
}

/**
 * @tc.name: InitSource_001
 * @tc.desc: Verify the InitSource function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceServiceTest, InitSource_001, TestSize.Level1)
{
    std::string param = "source";
    sptr<IDAudioIpcCallback> callback = nullptr;
    EXPECT_NE(DH_SUCCESS, sourceSrv_->InitSource(param, callback));
    sourceSrv_->ReleaseSource();
}

/**
 * @tc.name: ReleaseSource_001
 * @tc.desc: Verify the ReleaseSource function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceServiceTest, ReleaseSource_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_LOAD_FAILED, sourceSrv_->ReleaseSource());
}

/**
 * @tc.name: ConfigDistributedHardware_001
 * @tc.desc: Verify the ConfigDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceServiceTest, ConfigDistributedHardware_001, TestSize.Level1)
{
    std::string devId = "daef";
    std::string dhId = "1";
    std::string key = "key";
    std::string value = "1";

    EXPECT_EQ(DH_SUCCESS, sourceSrv_->ConfigDistributedHardware(devId, dhId, key, value));
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Verify the Dump function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceServiceTest, Dump_001, TestSize.Level1)
{
    int32_t fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(DH_SUCCESS, sourceSrv_->Dump(fd, args));
    std::u16string order = u"--sourceDevId";
    args.push_back(order);
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, sourceSrv_->Dump(fd, args));
    args.pop_back();
    order = u"-h";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sourceSrv_->Dump(fd, args));
    args.pop_back();
    order = u"--stopDump";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sourceSrv_->Dump(fd, args));
    args.pop_back();
    order = u"--illegal";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sourceSrv_->Dump(fd, args));
}
} // DistributedHardware
} // OHOS
