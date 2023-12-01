/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "daudio_adapter_internal.h"
#include "audio_adapter_internal_test.h"
#include "audio_adapter.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#include "audio_types.h"
#include <v1_0/iaudio_adapter.h>
#include <v1_0/iaudio_callback.h>
#include <v1_0/iaudio_capture.h>
#include <v1_0/iaudio_render.h>


#define HDF_LOG_TAG HDF_AUDIO_UT

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace DistributedHardware {
class AudioAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioAdapterTest::SetUpTestCase()
{
}

void AudioAdapterTest::TearDownTestCase()
{
}

/**
* @tc.name: InitAllPortsInternal
* @tc.desc: Verify the abnormal branch of the InitAllPortsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, InitAllPortsInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    int32_t ret = adapterContext.instance_.InitAllPorts(adapter);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: InitAllPortsInternal
* @tc.desc: Verify the abnormal branch of the InitAllPortsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, InitAllPortsInternal_002, TestSize.Level1)
{
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext->instance_.InitAllPorts(&adapterContext->instance_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
* @tc.name: CreateRenderInternal
* @tc.desc: Verify the abnormal branch of the CreateRenderInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, CreateRenderInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const struct ::AudioDeviceDescriptor *desc = nullptr;
    const struct ::AudioSampleAttributes *attrs = nullptr;
    struct AudioRender **render = nullptr;
    int32_t ret = adapterContext.instance_.CreateRender(adapter, desc, attrs, render);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: DestroyRenderInternal
* @tc.desc: Verify the abnormal branch of the DestroyRenderInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, DestroyRenderInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    int32_t ret = adapterContext.instance_.DestroyRender(adapter, render);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: DestroyRenderInternal
* @tc.desc: Verify the abnormal branch of the DestroyRenderInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, DestroyRenderInternal_002, TestSize.Level1)
{
    struct AudioRender *render = new AudioRender;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.DestroyRender(&adapterContext1->instance_, render);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.DestroyRender(&adapterContext->instance_, render));
    delete render;
}

/**
* @tc.name: CreateCaptureInternal
* @tc.desc: Verify the abnormal branch of the CreateCaptureInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, CreateCaptureInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const struct ::AudioDeviceDescriptor *desc = nullptr;
    const struct ::AudioSampleAttributes *attrs = nullptr;
    struct AudioCapture **capture = nullptr;
    int32_t ret = adapterContext.instance_.CreateCapture(adapter, desc, attrs, capture);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: DestroyCaptureInternal
* @tc.desc: Verify the abnormal branch of the DestroyCaptureInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, DestroyCaptureInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    int32_t ret = adapterContext.instance_.DestroyCapture(adapter, capture);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: DestroyCaptureInternal
* @tc.desc: Verify the abnormal branch of the DestroyCaptureInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, DestroyCaptureInternal_002, TestSize.Level1)
{
    struct AudioCapture *capture = new AudioCapture;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.DestroyCapture(&adapterContext1->instance_, capture);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.DestroyCapture(&adapterContext->instance_, capture));
    delete capture;
}

/**
* @tc.name: GetPassthroughModeInternal
* @tc.desc: Verify the abnormal branch of the GetPassthroughModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, GetPassthroughModeInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const struct ::AudioPort *port = nullptr;
    enum ::AudioPortPassthroughMode *mode = nullptr;
    int32_t ret = adapterContext.instance_.GetPassthroughMode(adapter, port, mode);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetPassthroughModeInternal
* @tc.desc: Verify the abnormal branch of the GetPassthroughModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, GetPassthroughModeInternal_002, TestSize.Level1)
{
    struct ::AudioPort *port = new ::AudioPort;
    enum ::AudioPortPassthroughMode *mode = new ::AudioPortPassthroughMode;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.GetPassthroughMode(&adapterContext1->instance_, port, mode);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    port->dir = AudioPortDirection::PORT_OUT;
    port->portId = 1;
    port->portName = "name";
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.GetPassthroughMode(&adapterContext->instance_, port, mode));
    delete port;
    delete mode;
}

/**
* @tc.name: ReleaseAudioRouteInternal
* @tc.desc: Verify the abnormal branch of the ReleaseAudioRouteInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, ReleaseAudioRouteInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    int32_t routeHandle = 0;
    int32_t ret = adapterContext.instance_.ReleaseAudioRoute(adapter, routeHandle);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: ReleaseAudioRouteInternal
* @tc.desc: Verify the abnormal branch of the ReleaseAudioRouteInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, ReleaseAudioRouteInternal_002, TestSize.Level1)
{
    int32_t routeHandle = 0;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.ReleaseAudioRoute(&adapterContext1->instance_, routeHandle);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.ReleaseAudioRoute(&adapterContext->instance_, routeHandle));
}

/**
* @tc.name: SetPassthroughModeInternal
* @tc.desc: Verify the abnormal branch of the SetPassthroughModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, SetPassthroughModeInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const struct ::AudioPort *port = nullptr;
    int32_t ret = adapterContext.instance_.SetPassthroughMode(adapter, port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: SetPassthroughModeInternal
* @tc.desc: Verify the abnormal branch of the SetPassthroughModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, SetPassthroughModeInternal_002, TestSize.Level1)
{
    struct ::AudioPort *port = new ::AudioPort;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.SetPassthroughMode(&adapterContext1->instance_, port,
        PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    port->dir = AudioPortDirection::PORT_OUT;
    port->portId = 1;
    port->portName = "name";
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.SetPassthroughMode(&adapterContext->instance_,
        port, PORT_PASSTHROUGH_LPCM));
    delete port;
}

/**
* @tc.name: UpdateAudioRouteInternal
* @tc.desc: Verify the abnormal branch of the UpdateAudioRouteInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, UpdateAudioRouteInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext1;
    struct AudioAdapter *adapter = nullptr;
    const struct ::AudioRoute *route = nullptr;
    int32_t *routeHandle = nullptr;
    int32_t ret = adapterContext1.instance_.UpdateAudioRoute(adapter, route, routeHandle);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    struct ::AudioRoute *route1 = new ::AudioRoute;
    route1->sourcesNum = 0;
    route1->sinksNum = 0;
    int32_t a = 1;
    int32_t *routeHandle1 = &a;
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.UpdateAudioRoute(&adapterContext->instance_, route1, routeHandle1));
    delete route1;
}

/**
* @tc.name: UpdateAudioRouteInternal
* @tc.desc: Verify the abnormal branch of the UpdateAudioRouteInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, UpdateAudioRouteInternal_002, TestSize.Level1)
{
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    struct ::AudioRoute *route = new struct ::AudioRoute;
    route->sourcesNum = 0;
    route->sinksNum = 0;
    int32_t *routeHandle = new int32_t(0);
    int32_t ret = adapterContext->instance_.UpdateAudioRoute(&adapterContext->instance_, route, routeHandle);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    delete route;
    delete routeHandle;
}

/**
* @tc.name: SetExtraParamsInternal
* @tc.desc: Verify the abnormal branch of the SetExtraParamsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, SetExtraParamsInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const char *condition = nullptr;
    const char *value = nullptr;
    int32_t ret = adapterContext.instance_.SetExtraParams(adapter, AUDIO_EXT_PARAM_KEY_NONE, condition, value);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: SetExtraParamsInternal
* @tc.desc: Verify the abnormal branch of the SetExtraParamsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, SetExtraParamsInternal_002, TestSize.Level1)
{
    std::string t_condition = "condition";
    std::string t_value = "value";
    const char *condition = t_condition.c_str();
    const char *value = t_value.c_str();
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.SetExtraParams(&adapterContext1->instance_,
        AUDIO_EXT_PARAM_KEY_NONE, condition, value);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.SetExtraParams(&adapterContext->instance_,
        AUDIO_EXT_PARAM_KEY_NONE, condition, value));
}

/**
* @tc.name: GetExtraParamsInternal
* @tc.desc: Verify the abnormal branch of the GetExtraParamsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, GetExtraParamsInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext;
    struct AudioAdapter *adapter = nullptr;
    const char *condition = nullptr;
    char *value = nullptr;
    int32_t length = 0;
    int32_t ret = adapterContext.instance_.GetExtraParams(adapter, AUDIO_EXT_PARAM_KEY_NONE, condition, value, length);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetExtraParamsInternal
* @tc.desc: Verify the abnormal branch of the GetExtraParamsInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, GetExtraParamsInternal_002, TestSize.Level1)
{
    std::string t_condition = "condition";
    std::string t_value = "value";
    const char *condition = t_condition.c_str();
    char *value = new char;
    int32_t length = 0;
    auto adapterContext1 = std::make_unique<AudioAdapterContext>();
    int32_t ret = adapterContext1->instance_.GetExtraParams(&adapterContext1->instance_,
        AUDIO_EXT_PARAM_KEY_NONE, condition, value, length);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    length = 1;
    EXPECT_EQ(DH_SUCCESS, adapterContext->instance_.GetExtraParams(&adapterContext->instance_,
        AUDIO_EXT_PARAM_KEY_NONE, condition, value, length));
    delete value;
}

/**
* @tc.name: RegExtraParamObserverInternal
* @tc.desc: Verify the abnormal branch of the RegExtraParamObserverInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioAdapterTest, RegExtraParamObserverInternal_001, TestSize.Level1)
{
    struct AudioAdapterContext adapterContext1;
    struct AudioAdapter *adapter = nullptr;
    ParamCallback callback = nullptr;
    void* cookie = nullptr;
    int32_t ret = adapterContext1.instance_.RegExtraParamObserver(adapter, callback, cookie);
    auto adapterContext = std::make_unique<AudioAdapterContext>();
    adapterContext->proxy_ = new MockIAudioAdapter();
    adapterContext->adapterName_ = "adapterName";
    ParamCallback callback1;
    cookie = &callback1;
    adapterContext->instance_.RegExtraParamObserver(&adapterContext->instance_,
        callback1, cookie);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}
} // DistributedHardware
} // OHOS