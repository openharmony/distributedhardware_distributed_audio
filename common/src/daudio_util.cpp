/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "daudio_util.h"

#include <ctime>
#include <cstddef>
#include <iomanip>
#include <map>
#include <random>
#include <sstream>
#include <sys/time.h>

#include "softbus_bus_center.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "parameter.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioUtils"

namespace OHOS {
namespace DistributedHardware {
using JsonTypeCheckFunc = bool (*)(const json &jsonObj, const std::string &key);
constexpr int32_t WORD_WIDTH_8 = 8;
constexpr int32_t WORD_WIDTH_4 = 4;
constexpr size_t INT32_SHORT_ID_LENGTH = 20;
constexpr size_t INT32_MIN_ID_LENGTH = 3;
constexpr size_t INT32_PLAINTEXT_LENGTH = 4;
constexpr uint8_t MAX_KEY_DH_ID_LEN = 20;

std::map<std::string, JsonTypeCheckFunc> typeCheckMap = {
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_EVENT_CONTENT, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_DH_ID, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_DEV_ID, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_RESULT, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_EVENT_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_AUDIO_PARAM, &DistributedHardware::IsAudioParam),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_ATTRS, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_RANDOM_TASK_CODE, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_SAMPLING_RATE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_CHANNELS, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_FORMAT, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_SOURCE_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_CONTENT_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_STREAM_USAGE, &DistributedHardware::IsInt32),
};

int32_t GetLocalDeviceNetworkId(std::string &networkId)
{
    NodeBasicInfo basicInfo = { { 0 } };
    int32_t ret = GetLocalNodeDeviceInfo(PKG_NAME.c_str(), &basicInfo);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to obtain the network ID of the local device. ret: %d", ret);
        return ret;
    }

    networkId = std::string(basicInfo.networkId);
    return DH_SUCCESS;
}

std::string GetRandomID()
{
    static std::random_device rd;
    static std::uniform_int_distribution<uint64_t> dist(0ULL, 0xFFFFFFFFFFFFFFFFULL);
    uint64_t ab = dist(rd);
    uint64_t cd = dist(rd);
    uint32_t a, b, c, d;
    std::stringstream ss;
    ab = (ab & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    cd = (cd & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    a = (ab >> 32U);
    b = (ab & 0xFFFFFFFFU);
    c = (cd >> 32U);
    d = (cd & 0xFFFFFFFFU);
    ss << std::hex << std::nouppercase << std::setfill('0');
    ss << std::setw(WORD_WIDTH_8) << (a);
    ss << std::setw(WORD_WIDTH_4) << (b >> 16U);
    ss << std::setw(WORD_WIDTH_4) << (b & 0xFFFFU);
    ss << std::setw(WORD_WIDTH_4) << (c >> 16U);
    ss << std::setw(WORD_WIDTH_4) << (c & 0xFFFFU);
    ss << std::setw(WORD_WIDTH_8) << d;

    return ss.str();
}

std::string GetAnonyString(const std::string &value)
{
    std::string res;
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LENGTH) {
        return tmpStr;
    }

    if (strLen <= INT32_SHORT_ID_LENGTH) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAINTEXT_LENGTH);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAINTEXT_LENGTH, INT32_PLAINTEXT_LENGTH);
    }

    return res;
}

int32_t GetDevTypeByDHId(int32_t dhId)
{
    if (static_cast<uint32_t>(dhId) & 0x8000000) {
        return AUDIO_DEVICE_TYPE_MIC;
    } else if (static_cast<uint32_t>(dhId) & 0x7ffffff) {
        return AUDIO_DEVICE_TYPE_SPEAKER;
    }
    return AUDIO_DEVICE_TYPE_UNKNOWN;
}

void GetCurrentTime(int64_t &tvSec, int64_t &tvNSec)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) < 0) {
        DHLOGE("Get current time failed");
    }
    tvSec = time.tv_sec;
    tvNSec = time.tv_nsec;
}

int64_t GetNowTimeUs()
{
    std::chrono::microseconds nowUs =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

int32_t GetAudioParamStr(const std::string &params, const std::string &key, std::string &value)
{
    size_t step = key.size();
    if (step >= params.size()) {
        return ERR_DH_AUDIO_FAILED;
    }
    size_t pos = params.find(key);
    if (pos == params.npos || params.at(pos + step) != '=') {
        return ERR_DH_AUDIO_NOT_FOUND_KEY;
    }
    size_t splitPosEnd = params.find(';', pos);
    if (splitPosEnd != params.npos) {
        value = params.substr(pos + step + 1, splitPosEnd - pos - step - 1);
    } else {
        value = params.substr(pos + step + 1);
    }
    return DH_SUCCESS;
}

int32_t GetAudioParamBool(const std::string &params, const std::string &key, bool &value)
{
    std::string val;
    GetAudioParamStr(params, key, val);
    value = (val != "0");
    return DH_SUCCESS;
}

int32_t GetAudioParamInt(const std::string &params, const std::string &key, int32_t &value)
{
    std::string val = "0";
    int32_t ret = GetAudioParamStr(params, key, val);
    value = std::stoi(val);
    return ret;
}

bool JsonParamCheck(const json &jsonObj, const std::initializer_list<std::string> &keys)
{
    if (jsonObj.is_discarded()) {
        DHLOGE("Json parameter is invalid.");
        return false;
    }

    for (auto it = keys.begin(); it != keys.end(); it++) {
        if (!jsonObj.contains(*it)) {
            DHLOGE("Json parameter not contain param(%s).", (*it).c_str());
            return false;
        }

        auto iter = typeCheckMap.find(*it);
        if (iter == typeCheckMap.end()) {
            DHLOGE("Check is not supported yet, key %s.", (*it).c_str());
            return false;
        }
        JsonTypeCheckFunc &func = iter->second;
        bool res = (*func)(jsonObj, *it);
        if (!res) {
            DHLOGE("The key %s value format in json is illegal.", (*it).c_str());
            return false;
        }
    }
    return true;
}

bool IsString(const json &jsonObj, const std::string &key)
{
    return jsonObj[key].is_string();
}

bool IsInt32(const json &jsonObj, const std::string &key)
{
    return jsonObj[key].is_number_integer() && INT32_MIN <= jsonObj[key] && jsonObj[key] <= INT32_MAX;
}

bool IsAudioParam(const json &jsonObj, const std::string &key)
{
    return JsonParamCheck(jsonObj[key],
        { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT, KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE });
}

int32_t CalculateSampleNum(uint32_t sampleRate, uint32_t timems)
{
    return (sampleRate * timems) / AUDIO_MS_PER_SECOND;
}

int64_t GetCurNano()
{
    int64_t result = -1;
    struct timespec time;
    clockid_t clockId = CLOCK_MONOTONIC;
    int ret = clock_gettime(clockId, &time);
    if (ret < 0) {
        DHLOGE("GetCurNanoTime fail, ret: %d", ret);
        return result;
    }
    result = (time.tv_sec * AUDIO_NS_PER_SECOND) + time.tv_nsec;
    return result;
}

int32_t AbsoluteSleep(int64_t nanoTime)
{
    int32_t ret = -1;
    if (nanoTime <= 0) {
        DHLOGE("AbsoluteSleep invalid sleep time : %d ns", nanoTime);
        return ret;
    }
    struct timespec time;
    time.tv_sec = nanoTime / AUDIO_NS_PER_SECOND;
    time.tv_nsec = nanoTime - (time.tv_sec * AUDIO_NS_PER_SECOND);

    clockid_t clockId = CLOCK_MONOTONIC;
    ret = clock_nanosleep(clockId, TIMER_ABSTIME, &time, nullptr);
    if (ret != 0) {
        DHLOGE("AbsoluteSleep may failed, ret is : %d", ret);
    }
    return ret;
}

int64_t CalculateOffset(const int64_t frameIndex, const int64_t framePeriodNs, const int64_t startTime)
{
    int64_t totalOffset = GetCurNano() - startTime;
    return totalOffset - frameIndex * framePeriodNs;
}

int64_t UpdateTimeOffset(const int64_t frameIndex, const int64_t framePeriodNs, int64_t &startTime)
{
    int64_t timeOffset = 0;
    if (frameIndex == 0) {
        startTime = GetCurNano();
    } else if (frameIndex % AUDIO_OFFSET_FRAME_NUM == 0) {
        timeOffset = CalculateOffset(frameIndex, framePeriodNs, startTime);
    }
    return timeOffset;
}

bool CheckIsNum(const std::string &jsonString)
{
    if (jsonString.empty() || jsonString.size() > MAX_KEY_DH_ID_LEN) {
        DHLOGE("Json string size %d, is zero or too long.", jsonString.size());
        return false;
    }
    for (char const &c : jsonString) {
        if (!std::isdigit(c)) {
            DHLOGE("Json string is not number.");
            return false;
        }
    }
    return true;
}

bool CheckDevIdIsLegal(const std::string &devId)
{
    if (devId.empty() || devId.size() > DAUDIO_MAX_DEVICE_ID_LEN) {
        DHLOGE("DevId size %d, is zero or too long.", devId.size());
        return false;
    }
    for (char const &c : devId) {
        if (!std::isalnum(c)) {
            DHLOGE("DevId is not number or letter.");
            return false;
        }
    }
    return true;
}

template <typename T>
bool GetSysPara(const char *key, T &value)
{
    if (key == nullptr) {
        DHLOGE("GetSysPara: key is nullptr");
        return false;
    }
    char paraValue[20] = {0}; // 20 for system parameter
    auto res = GetParameter(key, "-1", paraValue, sizeof(paraValue));
    if (res <= 0) {
        DHLOGD("GetSysPara fail, key:%{public}s res:%{public}d", key, res);
        return false;
    }
    DHLOGI("GetSysPara: key:%{public}s value:%{public}s", key, paraValue);
    std::stringstream valueStr;
    valueStr << paraValue;
    valueStr >> value;
    return true;
}

template bool GetSysPara(const char *key, int32_t &value);
template bool GetSysPara(const char *key, uint32_t &value);
template bool GetSysPara(const char *key, int64_t &value);
template bool GetSysPara(const char *key, std::string &value);

bool IsParamEnabled(std::string key, bool &isEnabled)
{
    // todo 当前默认是engine， 如果要默认为老的trans通路，需要把true / false 颠倒
    int32_t policyFlag = 0;
    if (GetSysPara(key.c_str(), policyFlag) && policyFlag == 1) {
        isEnabled = false;
        return false;
    }
    isEnabled = true;
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS