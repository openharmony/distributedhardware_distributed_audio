/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

std::map<std::string, JsonTypeCheckFunc> typeCheckMap = {
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_EVENT_CONTENT, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_DH_ID, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_DEV_ID, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_RESULT, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_EVENT_TYPE, &DistributedHardware::IsInt32),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_AUDIO_PARAM, &DistributedHardware::IsAudioParam),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_ATTRS, &DistributedHardware::IsString),
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
} // namespace DistributedHardware
} // namespace OHOS