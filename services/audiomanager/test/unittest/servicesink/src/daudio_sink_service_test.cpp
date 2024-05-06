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

#include "daudio_sink_service_test.h"

#include "audio_event.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "iservice_registry.h"
#include "daudio_sink_ipc_callback_proxy.h"
#include "daudio_sink_load_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioSinkServiceTest::SetUpTestCase(void) {}

void DAudioSinkServiceTest::TearDownTestCase(void) {}

void DAudioSinkServiceTest::SetUp()
{
    uint32_t saId = 6666;
    bool runOnCreate = true;
    std::string params = "params";
    samgr_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr_ == nullptr) {
        return;
    }
    sptr<DAudioSinkLoadCallback> loadCallback(new DAudioSinkLoadCallback(params));
    samgr_->LoadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID, loadCallback);
    remoteObject_ = samgr_->GetSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    if (remoteObject_ == nullptr) {
        return;
    }

    sinkSrv_ = std::make_shared<DAudioSinkService>(saId, runOnCreate);
}

void DAudioSinkServiceTest::TearDown()
{
    if (samgr_ != nullptr) {
        samgr_->UnloadSystemAbility(DISTRIBUTED_HARDWARE_AUDIO_SINK_SA_ID);
    }
    sinkSrv_ = nullptr;
}

/**
 * @tc.name: OnStart_001
 * @tc.desc: Verify the OnStart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, OnStart_001, TestSize.Level1)
{
    sinkSrv_->isServiceStarted_ = true;
    sinkSrv_->OnStart();

    std::string dhId = "oh123";
    std::string pram = "test";
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->SubscribeLocalHardware(dhId, pram));
}

/**
 * @tc.name: InitSink_001
 * @tc.desc: Verify the InitSink function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, InitSink_001, TestSize.Level1)
{
    std::string param = "sink";
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject_));
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->InitSink(param, dAudioSinkIpcCallbackProxy));
}

/**
 * @tc.name: SubscribeLocalHardware_001
 * @tc.desc: Verify the SubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, SubscribeLocalHardware_001, TestSize.Level1)
{
    std::string dhId = "oh123";
    std::string pram = "test";

    sinkSrv_->isServiceStarted_ = true;
    sinkSrv_->OnStop();
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->SubscribeLocalHardware(dhId, pram));
}

/**
 * @tc.name: UnsubscribeLocalHardware_001
 * @tc.desc: Verify the UnsubscribeLocalHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, UnsubscribeLocalHardware_001, TestSize.Level1)
{
    std::string devId = "efwewf";
    std::string dhId = "oh123";
    int32_t eventType = 2;
    std::string eventContent = "OPEN_MIC";
    std::string param = "sink";
    sptr<DAudioSinkIpcCallbackProxy> dAudioSinkIpcCallbackProxy(new DAudioSinkIpcCallbackProxy(remoteObject_));

    sinkSrv_->InitSink(param, dAudioSinkIpcCallbackProxy);
    sinkSrv_->DAudioNotify(devId, dhId, eventType, eventContent);
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->UnsubscribeLocalHardware(dhId));
    sinkSrv_->ReleaseSink();
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Verify the Dump function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, Dump_001, TestSize.Level1)
{
    int32_t fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->Dump(fd, args));
    std::u16string order = u"-h";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->Dump(fd, args));
    args.pop_back();
    order = u"--stopDump";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->Dump(fd, args));
    order = u"--illegal";
    args.push_back(order);
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->Dump(fd, args));
}

/**
 * @tc.name: PauseDistributedHardware_001
 * @tc.desc: Verify the PauseDistributedHardware function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DAudioSinkServiceTest, PauseDistributedHardware_001, TestSize.Level1)
{
    std::string networkId = "1";
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->PauseDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->ResumeDistributedHardware(networkId));
    EXPECT_EQ(DH_SUCCESS, sinkSrv_->StopDistributedHardware(networkId));
}
} // DistributedHardware
} // OHOS
