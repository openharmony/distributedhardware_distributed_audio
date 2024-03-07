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

#include "daudio_latency_test.h"

#include <ctime>
#include <string>

#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioLatencyTest"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioLatencyTest);
DAudioLatencyTest::DAudioLatencyTest()
{
    DHLOGI("DAudioLatencyTest constructed.");
}

DAudioLatencyTest::~DAudioLatencyTest()
{
    DHLOGI("DAudioLatencyTest deconstructed.");
}

int32_t DAudioLatencyTest::AddPlayTime(const int64_t playBeepTime)
{
    if (GetNowTimeUs() - lastPlayTime_ <= TWO_BEEP_TIME_INTERVAL) {
        DHLOGE("Catch play high frame, but not in %{public}d ms.", TWO_BEEP_TIME_INTERVAL);
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Catch play high frame, playTime: %{public}" PRId64, playBeepTime);
    playBeepTime_.push_back(playBeepTime);
    lastPlayTime_ = GetNowTimeUs();
    return DH_SUCCESS;
}

int32_t DAudioLatencyTest::AddRecordTime(const int64_t recordBeepTime)
{
    if (captureBeepTime_.size() >= playBeepTime_.size()) {
        DHLOGE("Catch record high frame size error, capturesize %{public}zu, playsize %{public}zu.",
            captureBeepTime_.size(), playBeepTime_.size());
        return ERR_DH_AUDIO_BAD_VALUE;
    }
    if (GetNowTimeUs() - lastRecordTime_ <= TWO_BEEP_TIME_INTERVAL) {
        DHLOGE("Catch record high frame, but not in %{public}d ms.", TWO_BEEP_TIME_INTERVAL);
        return ERR_DH_AUDIO_FAILED;
    }
    DHLOGI("Catch record high frame, recordTime: %{public}" PRId64, recordBeepTime);
    captureBeepTime_.push_back(recordBeepTime);
    lastRecordTime_ = GetNowTimeUs();
    return DH_SUCCESS;
}

bool DAudioLatencyTest::IsFrameHigh(const int16_t *audioData, const int32_t size, int32_t threshhold)
{
    int32_t max = 0;
    for (int32_t i = 0; i < size; i++) {
        int16_t f = abs(audioData[i]);
        if (f > max) {
            max = f;
        }
    }
    return (max >= threshhold) ? true : false;
}

int64_t DAudioLatencyTest::RecordBeepTime(const uint8_t *base, const int32_t &sizePerFrame, bool &status)
{
    int32_t threshhold = BEEP_THRESHHOLD;
    bool isHigh = IsFrameHigh(reinterpret_cast<int16_t *>(const_cast<uint8_t *>(base)),
        sizePerFrame / sizeof(int16_t), threshhold);
    if (isHigh && status) {
        status = false;
        return GetNowTimeUs();
    } else if (!isHigh) {
        status = true;
    }
    return 0;
}

int32_t DAudioLatencyTest::ComputeLatency()
{
    DHLOGD("Compute latency time.");
    int32_t playSize = static_cast<int32_t>(playBeepTime_.size());
    int32_t captureSize = static_cast<int32_t>(captureBeepTime_.size());
    if (playSize == 0 || playBeepTime_.size() != captureBeepTime_.size()) {
        DHLOGE("Record num is not equal %{public}d: %{public}d", playSize, captureSize);
        return -1;
    }
    DHLOGI("Record %{public}d times frame high.", playSize);
    int32_t sum = 0;
    for (int32_t i = 0; i < playSize; i++) {
        DHLOGI("Send: %{public}" PRId64", Received: %{public}" PRId64, playBeepTime_[i], captureBeepTime_[i]);
        DHLOGI("Time is: %{public}" PRId64" ms.", (captureBeepTime_[i] - playBeepTime_[i]) / US_PER_MS);
        sum += captureBeepTime_[i] - playBeepTime_[i];
    }
    DHLOGI("Audio latency in average is: %{public}d us.", sum / playSize);
    playBeepTime_.clear();
    captureBeepTime_.clear();
    return sum / playSize;
}
} // namespace DistributedHardware
} // namespace OHOS
