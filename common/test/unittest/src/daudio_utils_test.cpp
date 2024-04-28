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

#include "daudio_utils_test.h"

#include <thread>

#include "cJSON.h"
#include "securec.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_latency_test.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioUtilsTest"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
constexpr static int64_t TEMP_BEEP_TIME_INTERVAL_US = 10000; // 10ms
constexpr static int64_t MIN_BEEP_TIME_INTERVAL_US = 900000; // 900ms

void DAudioUtilsTest::SetUpTestCase(void) {}

void DAudioUtilsTest::TearDownTestCase(void) {}

void DAudioUtilsTest::SetUp(void) {}

void DAudioUtilsTest::TearDown(void) {}

/**
 * @tc.name: DAudioLatencyTest_001
 * @tc.desc: Verify the DAudioLatencyTest AddPlayTime, AddRecordTime and ComputeLatency function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioLatencyTest_001, TestSize.Level1)
{
    int32_t latency = DAudioLatencyTest::GetInstance().ComputeLatency();
    EXPECT_EQ(-1, latency);

    int64_t t = GetNowTimeUs();
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, DAudioLatencyTest::GetInstance().AddRecordTime(t));

    t = GetNowTimeUs();
    EXPECT_EQ(DH_SUCCESS, DAudioLatencyTest::GetInstance().AddPlayTime(t));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, DAudioLatencyTest::GetInstance().AddPlayTime(t + TEMP_BEEP_TIME_INTERVAL_US));

    std::this_thread::sleep_for(std::chrono::microseconds(MIN_BEEP_TIME_INTERVAL_US));
    t = GetNowTimeUs();
    EXPECT_EQ(DH_SUCCESS, DAudioLatencyTest::GetInstance().AddPlayTime(t));

    t = GetNowTimeUs();
    EXPECT_EQ(DH_SUCCESS, DAudioLatencyTest::GetInstance().AddRecordTime(t));
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, DAudioLatencyTest::GetInstance().AddRecordTime(t + TEMP_BEEP_TIME_INTERVAL_US));

    latency = DAudioLatencyTest::GetInstance().ComputeLatency();
    EXPECT_EQ(-1, latency);

    std::this_thread::sleep_for(std::chrono::microseconds(MIN_BEEP_TIME_INTERVAL_US));
    t = GetNowTimeUs();
    EXPECT_EQ(DH_SUCCESS, DAudioLatencyTest::GetInstance().AddRecordTime(t));

    latency = DAudioLatencyTest::GetInstance().ComputeLatency();
    EXPECT_LE(0, latency);
}

/**
 * @tc.name: DAudioLatencyTest_002
 * @tc.desc: Verify the DAudioLatencyTest IsFrameHigh function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioLatencyTest_002, TestSize.Level1)
{
    int32_t threshhold = 5000;
    int32_t spanSizeInByte = 960;
    std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(spanSizeInByte);
    memset_s(buf.get(), spanSizeInByte, 0, spanSizeInByte);
    bool isHigh = DAudioLatencyTest::GetInstance().IsFrameHigh(reinterpret_cast<int16_t *>(buf.get()),
        spanSizeInByte / sizeof(int16_t), threshhold);
    EXPECT_EQ(false, isHigh);

    memset_s(buf.get(), spanSizeInByte, threshhold, spanSizeInByte);
    isHigh = DAudioLatencyTest::GetInstance().IsFrameHigh(reinterpret_cast<int16_t *>(buf.get()),
        spanSizeInByte / sizeof(int16_t), threshhold);
    EXPECT_EQ(true, isHigh);
}

/**
 * @tc.name: DAudioLatencyTest_003
 * @tc.desc: Verify the DAudioLatencyTest IsFrameHigh function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioLatencyTest_003, TestSize.Level1)
{
    bool status = true;
    int32_t threshhold = 8000;
    int32_t spanSizeInByte = 960;
    std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(spanSizeInByte);
    memset_s(buf.get(), spanSizeInByte, threshhold, spanSizeInByte);
    int64_t beepTime = DAudioLatencyTest::GetInstance().RecordBeepTime(static_cast<uint8_t *>(buf.get()),
        spanSizeInByte, status);
    EXPECT_NE(0, beepTime);
    EXPECT_EQ(false, status);

    memset_s(buf.get(), spanSizeInByte, 0, spanSizeInByte);
    beepTime = DAudioLatencyTest::GetInstance().RecordBeepTime(static_cast<uint8_t *>(buf.get()),
        spanSizeInByte, status);
    EXPECT_EQ(0, beepTime);
    EXPECT_EQ(true, status);
}

/**
 * @tc.name: DAudioLogTest_001
 * @tc.desc: Verify the GetCurrentTime function and DHLOG definition and DHLog function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_001, TestSize.Level1)
{
    DHLOGD("DAudio TDD test DHLOGD print.");
    DHLOGI("DAudio TDD test DHLOGI print.");
    DHLOGW("DAudio TDD test DHLOGW print.");
    DHLOGE("DAudio TDD test DHLOGE print.");
    int64_t tvSec;
    int64_t tvNSec;
    GetCurrentTime(tvSec, tvNSec);
    EXPECT_GE(tvSec, 0);
    EXPECT_GE(tvNSec, 0);
}

/**
 * @tc.name: DAudioLogTest_002
 * @tc.desc: Verify the GetCurrentTime, GetCurNano and AbsoluteSleep function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_002, TestSize.Level1)
{
    int32_t eventType = 200;
    GetEventNameByType(eventType);
    cJSON * jsonObj = nullptr;
    std::initializer_list<std::string> keys = { "one", "two" };
    CJsonParamCheck(jsonObj, keys);
    jsonObj = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObj, "one", "one");
    cJSON_AddNumberToObject(jsonObj, "two", 2);
    CJsonParamCheck(jsonObj, keys);

    int64_t tvSec;
    int64_t tvNSec;
    GetCurrentTime(tvSec, tvNSec);
    int64_t curNano = GetCurNano();
    EXPECT_NE(0, curNano);
    int32_t ret = AbsoluteSleep(curNano);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: DAudioLogTest_003
 * @tc.desc: Verify the CalculateSampleNum and UpdateTimeOffset function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_003, TestSize.Level1)
{
    uint32_t sampleRate = 48000;
    uint32_t timeInterval = 5;
    int32_t desiredSpanSizeInFrame = 240;
    int32_t spanSizeInFrame = CalculateSampleNum(sampleRate, timeInterval);
    EXPECT_EQ(desiredSpanSizeInFrame, spanSizeInFrame);

    int64_t frameIndex = 0;
    int64_t framePeriodNs = 5000000;
    int64_t startTime = 0;
    int64_t timeOffset = UpdateTimeOffset(frameIndex, framePeriodNs, startTime);
    EXPECT_NE(0, startTime);
    EXPECT_EQ(0, timeOffset);

    frameIndex = AUDIO_OFFSET_FRAME_NUM / 2;
    timeOffset = UpdateTimeOffset(frameIndex, framePeriodNs, startTime);
    EXPECT_EQ(0, timeOffset);

    frameIndex = AUDIO_OFFSET_FRAME_NUM;
    timeOffset = UpdateTimeOffset(frameIndex, framePeriodNs, startTime);
    EXPECT_NE(0, timeOffset);
}

/**
 * @tc.name: DAudioLogTest_004
 * @tc.desc: Verify the GetAudioParamBool function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_004, TestSize.Level1)
{
    std::string params = "";
    std::string key = "";
    bool value = false;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, GetAudioParamBool(params, key, value));

    params = "params";
    key = "key";
    EXPECT_EQ(ERR_DH_AUDIO_NOT_FOUND_KEY, GetAudioParamBool(params, key, value));

    params = "key=0";
    EXPECT_EQ(DH_SUCCESS, GetAudioParamBool(params, key, value));
    EXPECT_EQ(false, value);

    params = "param1=true;key=1;param2=false;";
    EXPECT_EQ(DH_SUCCESS, GetAudioParamBool(params, key, value));
    EXPECT_EQ(true, value);
}

/**
 * @tc.name: DAudioLogTest_005
 * @tc.desc: Verify the GetAudioParamInt function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_005, TestSize.Level1)
{
    std::string params = "";
    std::string key = "";
    int32_t value = 5;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, GetAudioParamInt(params, key, value));

    params = "params";
    key = "key";
    EXPECT_EQ(ERR_DH_AUDIO_NOT_FOUND_KEY, GetAudioParamInt(params, key, value));

    params = "key=0";
    EXPECT_EQ(DH_SUCCESS, GetAudioParamInt(params, key, value));
    EXPECT_EQ(0, value);

    params = "param1=true;key=1;param2=false;";
    EXPECT_EQ(DH_SUCCESS, GetAudioParamInt(params, key, value));
    EXPECT_EQ(1, value);
}

/**
 * @tc.name: DAudioLogTest_006
 * @tc.desc: Verify the JsonParamCheck function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_006, TestSize.Level1)
{
    cJSON *jParam = cJSON_CreateObject();
    CHECK_NULL_VOID(jParam);
    cJSON_AddStringToObject(jParam, KEY_DEV_ID, "123");
    cJSON_AddStringToObject(jParam, KEY_DH_ID, "1");
    cJSON_AddStringToObject(jParam, KEY_ATTRS, "");
    cJSON_AddStringToObject(jParam, KEY_FORMAT, "TEST_8000");
    EXPECT_EQ(true, CJsonParamCheck(jParam, { KEY_ATTRS }));
    EXPECT_EQ(true, CJsonParamCheck(jParam, { KEY_DH_ID }));
    EXPECT_EQ(false, CJsonParamCheck(jParam, { KEY_FORMAT }));
    EXPECT_EQ(true, CJsonParamCheck(jParam, { KEY_DEV_ID }));
    cJSON_Delete(jParam);
}

/**
 * @tc.name: DAudioLogTest_007
 * @tc.desc: Verify the CheckIsNum and CheckDevIdIsLegal function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_007, TestSize.Level1)
{
    uint8_t maxDhIdLen = 20;
    std::string tempDhIdStr(maxDhIdLen + 1, 'a');
    EXPECT_EQ(false, CheckIsNum(tempDhIdStr));

    tempDhIdStr = "";
    EXPECT_EQ(false, CheckIsNum(tempDhIdStr));

    tempDhIdStr = "TestParams";
    EXPECT_EQ(false, CheckIsNum(tempDhIdStr));

    tempDhIdStr = "1";
    EXPECT_EQ(true, CheckIsNum(tempDhIdStr));

    std::string tempDevIdStr(DAUDIO_MAX_DEVICE_ID_LEN + 1, 'a');
    EXPECT_EQ(false, CheckDevIdIsLegal(tempDevIdStr));

    tempDevIdStr = "";
    EXPECT_EQ(false, CheckDevIdIsLegal(tempDevIdStr));

    tempDevIdStr = "Test*Params#";
    EXPECT_EQ(false, CheckDevIdIsLegal(tempDevIdStr));

    tempDevIdStr = "Test1";
    EXPECT_EQ(true, CheckDevIdIsLegal(tempDevIdStr));
}

/**
 * @tc.name: DAudioLogTest_009
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_009, TestSize.Level1)
{
    EXPECT_EQ(AddDhIdPrefix("1394302"), "Audio_1394302");
    EXPECT_EQ(AddDhIdPrefix("Audio_1394302"), "Audio_1394302");
    EXPECT_EQ(ReduceDhIdPrefix("Audio_1394302"), "1394302");
    EXPECT_EQ(ReduceDhIdPrefix("1394302"), "1394302");
}

/**
 * @tc.name: DAudioLogTest_010
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_010, TestSize.Level1)
{
    std::string key = "123";
    cJSON *jsonObject = nullptr;
    EXPECT_EQ(false, IsString(jsonObject, key));
    jsonObject = cJSON_CreateObject();
    CHECK_NULL_VOID(jsonObject);
    EXPECT_EQ(false, IsString(jsonObject, key));
    cJSON_AddStringToObject(jsonObject, "key", key.c_str());
    EXPECT_EQ(false, IsString(jsonObject, key));
    cJSON_Delete(jsonObject);
    cJSON *jsonObject1 = cJSON_CreateObject();
    CHECK_NULL_VOID(jsonObject1);
    cJSON_AddStringToObject(jsonObject1, "key", key.c_str());
    EXPECT_EQ(false, IsString(jsonObject1, key));
    cJSON_Delete(jsonObject1);
}

/**
 * @tc.name: DAudioLogTest_011
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_011, TestSize.Level1)
{
    std::string key = "123";
    cJSON *jsonObject = nullptr;
    EXPECT_EQ(false, IsInt32(jsonObject, key));
    jsonObject = cJSON_CreateObject();
    CHECK_NULL_VOID(jsonObject);
    EXPECT_EQ(false, IsInt32(jsonObject, key));
    cJSON_AddStringToObject(jsonObject, "key", key.c_str());
    EXPECT_EQ(false, IsInt32(jsonObject, key));
    cJSON_Delete(jsonObject);
    cJSON *jsonObject1 = cJSON_CreateObject();
    CHECK_NULL_VOID(jsonObject1);
    cJSON_AddNumberToObject(jsonObject1, "key", INT32_MAX);
    EXPECT_EQ(false, IsInt32(jsonObject1, key));
    cJSON_Delete(jsonObject1);
}

/**
 * @tc.name: DAudioLogTest_012
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_012, TestSize.Level1)
{
    std::string key = "123";
    cJSON *jsonObject = nullptr;
    EXPECT_EQ(false, IsAudioParam(jsonObject, key));
    jsonObject = cJSON_CreateObject();
    CHECK_NULL_VOID(jsonObject);
    EXPECT_EQ(false, IsAudioParam(jsonObject, key));
    cJSON *jsonObj = cJSON_CreateArray();
    CHECK_NULL_VOID(jsonObj);
    cJSON_AddItemToObject(jsonObject, key.c_str(), jsonObj);
    EXPECT_EQ(false, IsAudioParam(jsonObject, key));
    cJSON_Delete(jsonObject);
}

/**
 * @tc.name: DAudioLogTest_013
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_013, TestSize.Level1)
{
    std::string key = "123";
    bool isEnabled = false;
    EXPECT_EQ(false, IsParamEnabled(key, isEnabled));
}

/**
 * @tc.name: DAudioLogTest_014
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_014, TestSize.Level1)
{
    char *key = nullptr;
    int32_t value = 0;
    EXPECT_EQ(false, GetSysPara(key, value));
    std::string str = "123";
    EXPECT_EQ(true, GetSysPara(str.c_str(), value));
}

/**
 * @tc.name: DAudioLogTest_015
 * @tc.desc: Verify the AddDhIdPrefix and ReduceDhIdPrefix function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DAudioUtilsTest, DAudioUtilTest_015, TestSize.Level1)
{
    int64_t nanoTime = 0;
    EXPECT_NE(DH_SUCCESS, AbsoluteSleep(nanoTime));
    nanoTime = 123456;
    EXPECT_EQ(DH_SUCCESS, AbsoluteSleep(nanoTime));
}
} // namespace DistributedHardware
} // namespace OHOS
