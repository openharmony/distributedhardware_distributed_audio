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

#ifndef OHOS_DAUDIO_LATENCY_TEST_H
#define OHOS_DAUDIO_LATENCY_TEST_H

#include <vector>

#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class DAudioLatencyTest {
DECLARE_SINGLE_INSTANCE_BASE(DAudioLatencyTest);
public:
    int32_t AddPlayTime(const int64_t playBeepTime);
    int32_t AddRecordTime(const int64_t recordBeepTime);
    int64_t RecordBeepTime(const uint8_t *base, const int32_t &sizePerFrame, bool &status);
    bool IsFrameHigh(const int16_t *audioData, const int32_t size, int32_t threshhold);
    int32_t ComputeLatency();

private:
    DAudioLatencyTest();
    ~DAudioLatencyTest();

private:
    constexpr static int32_t TWO_BEEP_TIME_INTERVAL = 900000; // 900ms
    constexpr static int32_t BEEP_THRESHHOLD = 8000;
    constexpr static int32_t US_PER_MS = 1000;
    std::vector<int64_t> playBeepTime_;
    std::vector<int64_t> captureBeepTime_;
    int64_t lastPlayTime_ = 0;
    int64_t lastRecordTime_ = 0;
};
}
}
#endif