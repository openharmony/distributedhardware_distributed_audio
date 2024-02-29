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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/mman.h>

#include "distributed_audio_client.h"
#include "audio_manager.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#define HDF_LOG_TAG HDF_AUDIO_UT

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace DistributedHardware {
class AudioManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioManagerTest::SetUpTestCase()
{
}

void AudioManagerTest::TearDownTestCase()
{
}

/**
* @tc.name: GetAllAdaptersAbnormal
* @tc.desc: Verify the abnormal branch of the GetAllAdapters, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioManagerTest, GetAllAdaptersAbnormal, TestSize.Level1)
{
    struct AudioManagerContext managerContext;
    int32_t size = 0;
    AudioAdapterDescriptor *descs = nullptr;
    int32_t ret = managerContext.instance_.GetAllAdapters(nullptr, &descs, &size);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    ret = managerContext.instance_.GetAllAdapters(&managerContext.instance_, nullptr, &size);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    ret = managerContext.instance_.GetAllAdapters(&managerContext.instance_, &descs, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: LoadAdapterAbnormal
* @tc.desc: Verify the abnormal branch of the LoadAdapter, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioManagerTest, LoadAdapterAbnormal, TestSize.Level1)
{
    struct AudioManagerContext managerContext;
    AudioAdapterDescriptor desc = {};
    AudioAdapter *adapter = nullptr;
    struct AudioManager *manager = nullptr;
    int32_t ret = managerContext.instance_.LoadAdapter(nullptr, &desc, &adapter);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    ret = managerContext.instance_.LoadAdapter(&managerContext.instance_, nullptr, &adapter);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    ret = managerContext.instance_.LoadAdapter(&managerContext.instance_, &desc, nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    managerContext.instance_.UnloadAdapter(manager, adapter);
}
} // DistributedHardware
} // OHOS