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

#include "daudio_source_mgr_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
const std::string DEV_ID = "Test_Dev_Id";
const std::string DH_ID_MIC = "134217728";
const std::string DH_ID_SPK = "1";
const std::string ATTRS = "attrs";

void DAudioSourceMgrTest::SetUpTestCase(void) {}

void DAudioSourceMgrTest::TearDownTestCase(void) {}

void DAudioSourceMgrTest::SetUp(void)
{
    dAudioIpcCallback_ = new DAudioIpcCallback();
    remoteObject_ = dAudioIpcCallback_;
    ipcCallbackProxy_ = (new DAudioIpcCallbackProxy(remoteObject_));
    auto runner = AppExecFwk::EventRunner::Create(true);
    if (runner == nullptr) {
        return;
    }
    sourceMgr.handler_ = std::make_shared<DAudioSourceManager::SourceManagerHandler>(runner);
}

void DAudioSourceMgrTest::TearDown(void)
{
    dAudioIpcCallback_ = nullptr;
    remoteObject_ = nullptr;
    ipcCallbackProxy_ = nullptr;
}

/**
 * @tc.name: Init_001
 * @tc.desc: Verify the Init and UnInit function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, Init_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.UnInit());

    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.Init(nullptr));
    EXPECT_NE(DH_SUCCESS, sourceMgr.Init(ipcCallbackProxy_));

    std::string localDevId;
    EXPECT_NE(DH_SUCCESS, GetLocalDeviceNetworkId(localDevId));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: CreateAudioDevice_001
 * @tc.desc: Verify the CreateAudioDevice and UnInitfunction.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, CreateAudioDevice_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));

    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID + "1"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_001
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_001, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_002
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_002, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    std::string reqId2 = GetRandomID();
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId2));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_003
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_003, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    DAudioSourceManager::AudioDevice device = { DEV_ID, nullptr };
    sourceMgr.audioDevMap_[DEV_ID] = device;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId1));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: EnableDAudio_004
 * @tc.desc: Verify the EnableDAudio and DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, EnableDAudio_004, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    std::string dhId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, dhId, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    dhId = std::string(105, '1');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, dhId, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    std::string devId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(devId, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    devId = std::string(205, 'a');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(devId, DH_ID_SPK, "", ATTRS, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
    std::string attrs = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", attrs, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DisableDAudio_001
 * @tc.desc: Verify the DisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DisableDAudio_001, TestSize.Level1)
{
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId1));

    std::string dhId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, dhId, reqId1));
    dhId = std::string(105, '1');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, dhId, reqId1));
    std::string devId = "";
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(devId, DH_ID_SPK, reqId1));
    devId = std::string(205, 'a');
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(devId, DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio("Unknown", DH_ID_SPK, reqId1));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: HandleDAudioNotify_001
 * @tc.desc: Verify the HandleDAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, HandleDAudioNotify_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "openspk"));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_SA_DEVICE_NOT_EXIST,
        sourceMgr.HandleDAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "openspk"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.HandleDAudioNotify(DEV_ID + "1", DH_ID_SPK, CLOSE_CTRL, ""));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DAudioNotify_001
 * @tc.desc: Verify the DAudioNotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DAudioNotify_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR,
        sourceMgr.DAudioNotify(DEV_ID, DH_ID_SPK, OPEN_SPEAKER, "openspk"));
}

/**
 * @tc.name: OnEnableDAudio_001
 * @tc.desc: Verify the OnEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnEnableDAudio_002
 * @tc.desc: Verify the OnEnableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnEnableDAudio_002, TestSize.Level1)
{
    std::string reqId = GetRandomID();
    EXPECT_NE(DH_SUCCESS, sourceMgr.Init(ipcCallbackProxy_));
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;

    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnEnableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_001
 * @tc.desc: Verify the OnDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, DH_SUCCESS));

    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    int32_t ret = -40003;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, ret));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: OnDisableDAudio_003
 * @tc.desc: Verify the OnDisableDAudio function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, OnDisableDAudio_003, TestSize.Level1)
{
    std::string reqId = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId;
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    int32_t ret = -40003;
    EXPECT_EQ(DH_SUCCESS, sourceMgr.OnDisableDAudio(DEV_ID, DH_ID_SPK, ret));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_001
 * @tc.desc: Verify the GetRequestId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_001, TestSize.Level1)
{
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));

    std::string reqId0 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId0));
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_MIC, "", ATTRS, reqId1));

    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_MIC));
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK + "2"));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: GetRequestId_002
 * @tc.desc: Verify the GetRequestId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, GetRequestId_002, TestSize.Level1)
{
    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_SPK));

    std::string reqId0 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.EnableDAudio(DEV_ID, DH_ID_SPK, "", ATTRS, reqId0));

    EXPECT_EQ("", sourceMgr.GetRequestId(DEV_ID, DH_ID_MIC));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: DeleteAudioDevice_001
 * @tc.desc: Verify the DeleteAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, DeleteAudioDevice_001, TestSize.Level1)
{
    sourceMgr.daudioMgrCallback_ = std::make_shared<DAudioSourceMgrCallback>();
    sourceMgr.ipcCallback_ = ipcCallbackProxy_;
    std::string reqId0 = GetRandomID();
    std::string reqId1 = GetRandomID();
    EXPECT_EQ(DH_SUCCESS, sourceMgr.CreateAudioDevice(DEV_ID));
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_SPK] = reqId0;
    sourceMgr.audioDevMap_[DEV_ID].ports[DH_ID_MIC] = reqId1;

    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_SPK, reqId0));
    EXPECT_EQ(DH_SUCCESS, sourceMgr.DisableDAudio(DEV_ID, DH_ID_MIC, reqId1));

    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnInit());
}

/**
 * @tc.name: LoadAVReceiverEngineProvider_001
 * @tc.desc: Verify the LoadAVReceiverEngineProvider function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSourceMgrTest, LoadAVReceiverEngineProvider_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVReceiverEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.LoadAVSenderEngineProvider());
    EXPECT_EQ(DH_SUCCESS, sourceMgr.UnloadAVSenderEngineProvider());
}
} // namespace DistributedHardware
} // namespace OHOS
