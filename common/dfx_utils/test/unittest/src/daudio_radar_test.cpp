/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "daudio_radar.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "gtest/gtest.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioRadarTest"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

class DaudioRadarTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DaudioRadarTest::SetUpTestCase(void)
{
    DHLOGI("enter");
}

void DaudioRadarTest::TearDownTestCase(void)
{
    DHLOGI("enter");
}

void DaudioRadarTest::SetUp(void)
{
    DHLOGI("enter");
}

void DaudioRadarTest::TearDown(void)
{
    DHLOGI("enter");
}

/**
 * @tc.name: ReportDaudioInit_001
 * @tc.desc: check ReportDaudioInit
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioInit_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioInit_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioInit(FUNC, AudioInit::SERVICE_INIT,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioInit_001 end");
}

/**
 * @tc.name: ReportDaudioInit_002
 * @tc.desc: check ReportDaudioInit
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioInit_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioInit_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioInit(FUNC, AudioInit::SERVICE_INIT,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioInit_002 end");
}

/**
 * @tc.name: ReportDaudioInitProgress_001
 * @tc.desc: check ReportDaudioInitProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioInitProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioInitProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioInitProgress(FUNC, AudioInit::SERVICE_INIT, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioInitProgress_001 end");
}

/**
 * @tc.name: ReportDaudioInitProgress_002
 * @tc.desc: check ReportDaudioInitProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioInitProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioInitProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioInitProgress(FUNC, AudioInit::SERVICE_INIT,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioInitProgress_002 end");
}

/**
 * @tc.name: ReportSpeakerOpen_001
 * @tc.desc: check ReportSpeakerOpen
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerOpen_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerOpen_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerOpen(FUNC, SpeakerOpen::CREATE_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerOpen_001 end");
}

/**
 * @tc.name: ReportSpeakerOpen_002
 * @tc.desc: check ReportSpeakerOpen
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerOpen_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerOpen_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerOpen(FUNC, SpeakerOpen::CREATE_STREAM,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerOpen_002 end");
}

/**
 * @tc.name: ReportSpeakerOpenProgress_001
 * @tc.desc: check ReportSpeakerOpenProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerOpenProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerOpenProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerOpenProgress(FUNC, SpeakerOpen::CREATE_STREAM, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerOpenProgress_001 end");
}

/**
 * @tc.name: ReportSpeakerOpenProgress_002
 * @tc.desc: check ReportSpeakerOpenProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerOpenProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerOpenProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerOpenProgress(FUNC, SpeakerOpen::CREATE_STREAM,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerOpenProgress_002 end");
}

/**
 * @tc.name: ReportSpeakerClose_001
 * @tc.desc: check ReportSpeakerClose
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerClose_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerClose_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerClose(FUNC, SpeakerClose::DESTROY_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerClose_001 end");
}

/**
 * @tc.name: ReportSpeakerClose_002
 * @tc.desc: check ReportSpeakerClose
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerClose_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerClose_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerClose(FUNC, SpeakerClose::DESTROY_STREAM,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerClose_002 end");
}

/**
 * @tc.name: ReportSpeakerCloseProgress_001
 * @tc.desc: check ReportSpeakerCloseProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerCloseProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerCloseProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerCloseProgress(FUNC, SpeakerClose::DESTROY_STREAM, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerCloseProgress_001 end");
}

/**
 * @tc.name: ReportSpeakerCloseProgress_002
 * @tc.desc: check ReportSpeakerCloseProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportSpeakerCloseProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportSpeakerCloseProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportSpeakerCloseProgress(FUNC, SpeakerClose::DESTROY_STREAM,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportSpeakerCloseProgress_002 end");
}

/**
 * @tc.name: ReportMicOpen_001
 * @tc.desc: check ReportMicOpen
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicOpen_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicOpen_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicOpen(FUNC, MicOpen::CREATE_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicOpen_001 end");
}

/**
 * @tc.name: ReportMicOpen_002
 * @tc.desc: check ReportMicOpen
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicOpen_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicOpen_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicOpen(FUNC, MicOpen::CREATE_STREAM,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicOpen_002 end");
}

/**
 * @tc.name: ReportMicOpenProgress_001
 * @tc.desc: check ReportMicOpenProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicOpenProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicOpenProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicOpenProgress(FUNC, MicOpen::CREATE_STREAM,
        DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicOpenProgress_001 end");
}

/**
 * @tc.name: ReportMicOpenProgress_002
 * @tc.desc: check ReportMicOpenProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicOpenProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicOpenProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicOpenProgress(FUNC, MicOpen::CREATE_STREAM,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicOpenProgress_002 end");
}

/**
 * @tc.name: ReportMicClose_001
 * @tc.desc: check ReportMicClose
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicClose_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicClose_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicClose(FUNC, MicClose::DESTROY_STREAM,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicClose_001 end");
}

/**
 * @tc.name: ReportMicClose_002
 * @tc.desc: check ReportMicClose
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicClose_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicClose_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicClose(FUNC, MicClose::DESTROY_STREAM,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicClose_002 end");
}

/**
 * @tc.name: ReportMicCloseProgress_001
 * @tc.desc: check ReportMicCloseProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicCloseProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicCloseProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicCloseProgress(FUNC, MicClose::DESTROY_STREAM,
        DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicCloseProgress_001 end");
}

/**
 * @tc.name: ReportMicCloseProgress_002
 * @tc.desc: check ReportMicCloseProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportMicCloseProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportMicCloseProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportMicCloseProgress(FUNC, MicClose::DESTROY_STREAM,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportMicCloseProgress_002 end");
}

/**
 * @tc.name: ReportDaudioUnInit_001
 * @tc.desc: check ReportDaudioUnInit
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioUnInit_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioUnInit_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioUnInit(FUNC, AudioUnInit::UNREGISTER,
        BizState::BIZ_STATE_START, DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioUnInit_001 end");
}

/**
 * @tc.name: ReportDaudioUnInit_002
 * @tc.desc: check ReportDaudioUnInit
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioUnInit_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioUnInit_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioUnInit(FUNC, AudioUnInit::UNREGISTER,
        BizState::BIZ_STATE_START, ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioUnInit_002 end");
}

/**
 * @tc.name: ReportDaudioUnInitProgress_001
 * @tc.desc: check ReportDaudioUnInitProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioUnInitProgress_001, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioUnInitProgress_001 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioUnInitProgress(FUNC, AudioUnInit::UNREGISTER,
        DH_SUCCESS);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioUnInitProgress_001 end");
}

/**
 * @tc.name: ReportDaudioUnInitProgress_002
 * @tc.desc: check ReportDaudioUnInitProgress
 * @tc.type: FUNC
 */
HWTEST_F(DaudioRadarTest, ReportDaudioUnInitProgress_002, TestSize.Level1)
{
    DHLOGI("DaudioRadarTest ReportDaudioUnInitProgress_002 begin");
    bool ret = DaudioRadar::GetInstance().ReportDaudioUnInitProgress(FUNC, AudioUnInit::UNREGISTER,
        ERR_DH_AUDIO_FAILED);
    EXPECT_EQ(ret, true);
    DHLOGI("DaudioRadarTest ReportDaudioUnInitProgress_002 end");
}
}
}