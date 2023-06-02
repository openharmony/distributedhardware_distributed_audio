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

#ifndef OHOS_DAUDIO_UTIL_H
#define OHOS_DAUDIO_UTIL_H

#include <chrono>
#include <string>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

#define AUDIO_MS_PER_SECOND 1000
#define AUDIO_US_PER_SECOND 1000000
#define AUDIO_NS_PER_SECOND ((int64_t)1000000000)
namespace OHOS {
namespace DistributedHardware {
int32_t GetLocalDeviceNetworkId(std::string &networkId);
std::string GetRandomID();
std::string GetAnonyString(const std::string &value);
int32_t GetDevTypeByDHId(int32_t dhId);
int64_t GetNowTimeUs();
int32_t GetAudioParamStr(const std::string &params, const std::string &key, std::string &value);
int32_t GetAudioParamBool(const std::string &params, const std::string &key, bool &value);
int32_t GetAudioParamInt(const std::string &params, const std::string &key, int32_t &value);
bool JsonParamCheck(const json &jsonObj, const std::initializer_list<std::string> &key);
bool IsString(const json &jsonObj, const std::string &key);
bool IsInt32(const json &jsonObj, const std::string &key);
bool IsAudioParam(const json &jsonObj, const std::string &key);
int32_t CalculateSampleNum(uint32_t sampleRate, uint32_t timems);
int64_t GetCurNano();
int32_t AbsoluteSleep(int64_t nanoTime);
int64_t CalculateOffset(const int64_t frameIndex, const int64_t framePeriodNs, const int64_t startTime);
int64_t UpdateTimeOffset(const int64_t frameIndex, const int64_t framePeriodNs, int64_t &startTime);
void GetCurrentTime(int64_t &tvSec, int64_t &tvNSec);
bool CheckIsNum(const std::string &jsonString);
bool CheckDevIdIsLegal(const std::string &devId);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_UTIL_H
