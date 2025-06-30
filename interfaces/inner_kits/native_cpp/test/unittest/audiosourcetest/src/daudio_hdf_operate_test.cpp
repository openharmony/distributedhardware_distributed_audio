/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "daudio_errorcode.h"
#include "daudio_hdf_operate.h"
#include "daudio_log.h"
#include "mock_hdfoperate_device_manager.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHdfOperateTest"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DAudioHdfOperateTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    sptr<MockDeviceManager> deviceManager_;
};

void DAudioHdfOperateTest::SetUpTestCase(void)
{
    DHLOGI("DAudioHdfOperateTest::SetUpTestCase");
}

void DAudioHdfOperateTest::TearDownTestCase(void)
{
    DHLOGI("DAudioHdfOperateTest::TearDownTestCase");
}

void DAudioHdfOperateTest::SetUp(void)
{
    DHLOGI("DAudioHdfOperateTest::SetUp");
    deviceManager_ = MockDeviceManager::GetOrCreateInstance();
}

void DAudioHdfOperateTest::TearDown(void)
{
    DHLOGI("DAudioHdfOperateTest::TearDown");
    MockDeviceManager::ReleaseInstance();
    deviceManager_ = nullptr;
}

class MockHdfDeathCallback : public HdfDeathCallback {
public:
    virtual ~MockHdfDeathCallback() {}
    bool IsCalled()
    {
        return isCalled_;
    }
protected:
    void OnHdfHostDied()
    {
        isCalled_ = true;
    }
private:
    bool isCalled_ = false;
};

/**
 * @tc.name: LoadDaudioHDFImpl_001
 * @tc.desc: Verify LoadDaudioHDFImpl func
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, LoadDaudioHDFImpl_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::LoadDaudioHDFImpl_001");
    int32_t ret = DaudioHdfOperate::GetInstance().LoadDaudioHDFImpl(nullptr);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
}

/**
 * @tc.name: LoadDaudioHDFImpl_002
 * @tc.desc: Verify LoadDaudioHDFImpl func
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, LoadDaudioHDFImpl_002, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::LoadDaudioHDFImpl_002");
    EXPECT_CALL(*deviceManager_, LoadDevice(_)).WillRepeatedly(testing::Return(HDF_SUCCESS));
    DaudioHdfOperate::GetInstance().audioServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    DaudioHdfOperate::GetInstance().audioextServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    int32_t ret = DaudioHdfOperate::GetInstance().LoadDaudioHDFImpl(nullptr);
    DaudioHdfOperate::GetInstance().audioServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP);
    DaudioHdfOperate::GetInstance().audioextServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: UnLoadDaudioHDFImpl_001
 * @tc.desc: Verify UnLoadDaudioHDFImpl func
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, UnLoadDaudioHDFImpl_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::UnLoadDaudioHDFImpl_001");
    int32_t ret = DaudioHdfOperate::GetInstance().UnLoadDaudioHDFImpl();
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: WaitLoadService_001
 * @tc.desc: Verify WaitLoadService func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, WaitLoadService_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::WaitLoadService_001");
    DaudioHdfOperate::GetInstance().audioServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    int32_t ret = DaudioHdfOperate::GetInstance().WaitLoadService(AUDIO_SERVICE_NAME);
    EXPECT_EQ(DH_SUCCESS, ret);
    DaudioHdfOperate::GetInstance().audioServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP);
    ret = DaudioHdfOperate::GetInstance().WaitLoadService(AUDIO_SERVICE_NAME);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
}

/**
 * @tc.name: WaitLoadService_002
 * @tc.desc: Verify WaitLoadService func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, WaitLoadService_002, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::WaitLoadService_002");
    DaudioHdfOperate::GetInstance().audioextServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    int32_t ret = DaudioHdfOperate::GetInstance().WaitLoadService(AUDIOEXT_SERVICE_NAME);
    EXPECT_EQ(DH_SUCCESS, ret);
    DaudioHdfOperate::GetInstance().audioextServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP);
    ret = DaudioHdfOperate::GetInstance().WaitLoadService(AUDIOEXT_SERVICE_NAME);
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
}

/**
 * @tc.name: LoadDevice_001
 * @tc.desc: Verify LoadDevice func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, LoadDevice_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::LoadDevice_001");
    EXPECT_CALL(*deviceManager_, LoadDevice(_)).WillRepeatedly(testing::Return(HDF_ERR_DEVICE_BUSY));
    int32_t ret = DaudioHdfOperate::GetInstance().LoadDevice();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
    EXPECT_CALL(*deviceManager_, LoadDevice(_)).WillRepeatedly(testing::Return(ERR_DH_AUDIO_FAILED));
    ret = DaudioHdfOperate::GetInstance().LoadDevice();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
}

/**
 * @tc.name: LoadDevice_002
 * @tc.desc: Verify LoadDevice func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, LoadDevice_002, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::LoadDevice_002");
    bool isFirstTime = true;
    EXPECT_CALL(*deviceManager_, LoadDevice(_)).WillRepeatedly([&]()->int32_t {
        if (isFirstTime) {
            isFirstTime = false;
            return HDF_SUCCESS;
        } else {
            return HDF_ERR_DEVICE_BUSY;
        }
    });
    DaudioHdfOperate::GetInstance().audioServStatus_.store(OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    int32_t ret = DaudioHdfOperate::GetInstance().LoadDevice();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
    isFirstTime = true;
    EXPECT_CALL(*deviceManager_, LoadDevice(_)).WillRepeatedly([&]()->int32_t {
        if (isFirstTime) {
            isFirstTime = false;
            return HDF_SUCCESS;
        } else {
            return ERR_DH_AUDIO_FAILED;
        }
    });
    ret = DaudioHdfOperate::GetInstance().LoadDevice();
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, ret);
}

/**
 * @tc.name: UnLoadDevice_001
 * @tc.desc: Verify UnLoadDevice func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, UnloadDevice_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::UnloadDevice_001");
    EXPECT_CALL(*deviceManager_, UnloadDevice(_)).WillRepeatedly(testing::Return(HDF_ERR_DEVICE_BUSY));
    int32_t ret = DaudioHdfOperate::GetInstance().UnLoadDevice();
    EXPECT_EQ(DH_SUCCESS, ret);
}

/**
 * @tc.name: UnLoadDevice_002
 * @tc.desc: Verify UnLoadDevice func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, UnloadDevice_002, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::UnloadDevice_002");
    auto devmgr = DaudioHdfOperate::GetInstance().devmgr_;
    DaudioHdfOperate::GetInstance().devmgr_ = nullptr;
    int32_t ret = DaudioHdfOperate::GetInstance().UnLoadDevice();
    DaudioHdfOperate::GetInstance().devmgr_ = devmgr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: UnRegisterHdfListener_001
 * @tc.desc: Verify UnRegisterHdfListener func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, UnRegisterHdfListener_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::UnRegisterHdfListener_001");
    auto audioSrvHdf = DaudioHdfOperate::GetInstance().audioSrvHdf_;
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = nullptr;
    int32_t ret = DaudioHdfOperate::GetInstance().UnRegisterHdfListener();
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = audioSrvHdf;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: OnHdfHostDied_001
 * @tc.desc: Verify OnHdfHostDied func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, OnHdfHostDied_001, TestSize.Level1)
{
    auto hdfDeathCallback = std::make_shared<MockHdfDeathCallback>();
    DaudioHdfOperate::GetInstance().hdfDeathCallback_ = nullptr;
    DaudioHdfOperate::GetInstance().OnHdfHostDied();
    EXPECT_EQ(hdfDeathCallback->IsCalled(), false);
    DaudioHdfOperate::GetInstance().hdfDeathCallback_ = hdfDeathCallback;
    DaudioHdfOperate::GetInstance().OnHdfHostDied();
    EXPECT_EQ(hdfDeathCallback->IsCalled(), true);
}

/**
 * @tc.name: AddHdfDeathBind_001
 * @tc.desc: Verify AddHdfDeathBind func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, AddHdfDeathBind_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::AddHdfDeathBind_001");
    auto audioSrvHdf = DaudioHdfOperate::GetInstance().audioSrvHdf_;
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = nullptr;
    int32_t ret = DaudioHdfOperate::GetInstance().AddHdfDeathBind();
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = audioSrvHdf;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
 * @tc.name: RemoveHdfDeathBind_001
 * @tc.desc: Verify RemoveHdfDeathBind func.
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DAudioHdfOperateTest, RemoveHdfDeathBind_001, TestSize.Level1)
{
    DHLOGI("DAudioHdfOperateTest::RemoveHdfDeathBind_001");
    auto audioSrvHdf = DaudioHdfOperate::GetInstance().audioSrvHdf_;
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = nullptr;
    int32_t ret = DaudioHdfOperate::GetInstance().RemoveHdfDeathBind();
    DaudioHdfOperate::GetInstance().audioSrvHdf_ = audioSrvHdf;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
