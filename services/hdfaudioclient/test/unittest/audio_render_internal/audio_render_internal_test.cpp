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

#include "daudio_render_internal.h"
#include "audio_render.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#define HDF_LOG_TAG HDF_AUDIO_UT

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace DistributedHardware {
class AudioRenderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioRenderTest::SetUpTestCase()
{
}

void AudioRenderTest::TearDownTestCase()
{
}

/**
* @tc.name: GetLatencyInternal
* @tc.desc: Verify the abnormal branch of the GetLatencyInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, GetLatencyInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    uint32_t *ms = nullptr;
    int32_t ret = renderContext.instance_.GetLatency(render, ms);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: RenderFrameInternal
* @tc.desc: Verify the abnormal branch of the RenderFrameInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, RenderFrameInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    const void *frame = nullptr;
    uint64_t requestBytes = 0;
    uint64_t *replyBytes = nullptr;
    int32_t ret = renderContext.instance_.RenderFrame(render, frame, requestBytes, replyBytes);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetRenderPositionInternal
* @tc.desc: Verify the abnormal branch of the GetRenderPositionInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, GetRenderPositionInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    uint64_t *frames = nullptr;
    struct ::AudioTimeStamp *time = nullptr;
    int32_t ret = renderContext.instance_.GetRenderPosition(render, frames, time);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: SetRenderSpeedInternal
* @tc.desc: Verify the abnormal branch of the SetRenderSpeedInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, SetRenderSpeedInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    float speed = 0.0;
    int32_t ret = renderContext.instance_.SetRenderSpeed(render, speed);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetRenderSpeedInternal
* @tc.desc: Verify the abnormal branch of the GetRenderSpeedInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, GetRenderSpeedInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    float *speed = nullptr;
    int32_t ret = renderContext.instance_.GetRenderSpeed(render, speed);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetRenderSpeedInternal
* @tc.desc: Verify the abnormal branch of the GetRenderSpeedInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, GetRenderSpeedInternal_002, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = new AudioRender;
    float *speed = new float;
    int32_t ret = renderContext.instance_.GetRenderSpeed(render, speed);
    delete render;
    delete speed;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, ret);
}

/**
* @tc.name: SetChannelModeInternal
* @tc.desc: Verify the abnormal branch of the SetChannelModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, SetChannelModeInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    int32_t ret = renderContext.instance_.SetChannelMode(render, AUDIO_CHANNEL_NORMAL);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: GetChannelModeInternal
* @tc.desc: Verify the abnormal branch of the GetChannelModeInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, GetChannelModeInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    enum ::AudioChannelMode *mode = nullptr;
    int32_t ret = renderContext.instance_.GetChannelMode(render, mode);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: RegCallbackInternal
* @tc.desc: Verify the abnormal branch of the RegCallbackInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, RegCallbackInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    ::RenderCallback callback = nullptr;
    void *cookie = nullptr;
    int32_t ret = renderContext.instance_.RegCallback(render, callback, cookie);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}

/**
* @tc.name: DrainBufferInternal
* @tc.desc: Verify the abnormal branch of the DrainBufferInternal, when param is null.
* @tc.type: FUNC
* @tc.require: AR000H0E6H
*/
HWTEST_F(AudioRenderTest, DrainBufferInternal_001, TestSize.Level1)
{
    struct AudioRenderContext renderContext;
    struct AudioRender *render = nullptr;
    enum ::AudioDrainNotifyType *type = nullptr;
    int32_t ret = renderContext.instance_.DrainBuffer(render, type);
    EXPECT_EQ(ERR_DH_AUDIO_HDI_INVALID_PARAM, ret);
}
} // DistributedHardware
} // OHOS