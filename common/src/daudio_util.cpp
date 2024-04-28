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

#include "audio_event.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "parameter.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioUtil"

namespace OHOS {
namespace DistributedHardware {
using JsonTypeCheckFunc = bool (*)(const cJSON *jsonObj, const std::string &key);
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
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_REQID, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_VERSION, &DistributedHardware::IsString),
    std::map<std::string, JsonTypeCheckFunc>::value_type(KEY_CHANGE_TYPE, &DistributedHardware::IsString),
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

std::map<int32_t, std::string> eventNameMap = {
    std::make_pair(EVENT_UNKNOWN, "EVENT_UNKNOWN"),
    std::make_pair(OPEN_CTRL, "OPEN_CTRL"),
    std::make_pair(CLOSE_CTRL, "CLOSE_CTRL"),
    std::make_pair(CTRL_OPENED, "CTRL_OPENED"),
    std::make_pair(CTRL_CLOSED, "CTRL_CLOSED"),
    std::make_pair(NOTIFY_OPEN_CTRL_RESULT, "NOTIFY_OPEN_CTRL_RESULT"),
    std::make_pair(NOTIFY_CLOSE_CTRL_RESULT, "NOTIFY_CLOSE_CTRL_RESULT"),
    std::make_pair(DATA_OPENED, "DATA_OPENED"),
    std::make_pair(DATA_CLOSED, "DATA_CLOSED"),

    std::make_pair(OPEN_SPEAKER, "OPEN_SPEAKER"),
    std::make_pair(CLOSE_SPEAKER, "CLOSE_SPEAKER"),
    std::make_pair(SPEAKER_OPENED, "SPEAKER_OPENED"),
    std::make_pair(SPEAKER_CLOSED, "SPEAKER_CLOSED"),
    std::make_pair(NOTIFY_OPEN_SPEAKER_RESULT, "NOTIFY_OPEN_SPEAKER_RESULT"),
    std::make_pair(NOTIFY_CLOSE_SPEAKER_RESULT, "NOTIFY_CLOSE_SPEAKER_RESULT"),
    std::make_pair(NOTIFY_HDF_SPK_DUMP, "NOTIFY_HDF_SPK_DUMP"),
    std::make_pair(NOTIFY_HDF_MIC_DUMP, "NOTIFY_HDF_MIC_DUMP"),

    std::make_pair(OPEN_MIC, "OPEN_MIC"),
    std::make_pair(CLOSE_MIC, "CLOSE_MIC"),
    std::make_pair(MIC_OPENED, "MIC_OPENED"),
    std::make_pair(MIC_CLOSED, "MIC_CLOSED"),
    std::make_pair(NOTIFY_OPEN_MIC_RESULT, "NOTIFY_OPEN_MIC_RESULT"),
    std::make_pair(NOTIFY_CLOSE_MIC_RESULT, "NOTIFY_CLOSE_MIC_RESULT"),

    std::make_pair(VOLUME_SET, "VOLUME_SET"),
    std::make_pair(VOLUME_GET, "VOLUME_GET"),
    std::make_pair(VOLUME_CHANGE, "VOLUME_CHANGE"),
    std::make_pair(VOLUME_MIN_GET, "VOLUME_MIN_GET"),
    std::make_pair(VOLUME_MAX_GET, "VOLUME_MAX_GET"),
    std::make_pair(VOLUME_MUTE_SET, "VOLUME_MUTE_SET"),

    std::make_pair(AUDIO_FOCUS_CHANGE, "AUDIO_FOCUS_CHANGE"),
    std::make_pair(AUDIO_RENDER_STATE_CHANGE, "AUDIO_RENDER_STATE_CHANGE"),

    std::make_pair(SET_PARAM, "SET_PARAM"),
    std::make_pair(SEND_PARAM, "SEND_PARAM"),

    std::make_pair(AUDIO_ENCODER_ERR, "AUDIO_ENCODER_ERR"),
    std::make_pair(AUDIO_DECODER_ERR, "AUDIO_DECODER_ERR"),

    std::make_pair(CHANGE_PLAY_STATUS, "CHANGE_PLAY_STATUS"),

    std::make_pair(MMAP_SPK_START, "MMAP_SPK_START"),
    std::make_pair(MMAP_SPK_STOP, "MMAP_SPK_STOP"),
    std::make_pair(MMAP_MIC_START, "MMAP_MIC_START"),
    std::make_pair(MMAP_MIC_STOP, "MMAP_MIC_STOP"),
    std::make_pair(AUDIO_START, "AUDIO_START"),
    std::make_pair(AUDIO_STOP, "AUDIO_STOP")
};

std::string GetEventNameByType(const int32_t eventType)
{
    auto iter = eventNameMap.find(eventType);
    if (iter == eventNameMap.end()) {
        DHLOGE("Can't find matched eventname");
        return "EVENT_UNKNOWN";
    }
    return iter->second;
}

int32_t GetLocalDeviceNetworkId(std::string &networkId)
{
    NodeBasicInfo basicInfo = { { 0 } };
    int32_t ret = GetLocalNodeDeviceInfo(PKG_NAME.c_str(), &basicInfo);
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to obtain the network ID of the local device. ret: %{public}d", ret);
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
    DHLOGI("Get dev type by dhId: %{public}d.", dhId);
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
    int32_t ret = GetAudioParamStr(params, key, val);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param string fail, error code %{public}d.", ret);
        return ret;
    }

    value = (val != "0");
    return DH_SUCCESS;
}

int32_t GetAudioParamInt(const std::string &params, const std::string &key, int32_t &value)
{
    std::string val = "0";
    int32_t ret = GetAudioParamStr(params, key, val);
    if (ret != DH_SUCCESS) {
        DHLOGE("Get audio param string fail, error code %{public}d.", ret);
        return ret;
    }
    if (!CheckIsNum(val)) {
        DHLOGE("String is not number. str:%{public}s.", val.c_str());
        return ERR_DH_AUDIO_NOT_SUPPORT;
    }
    value = std::stoi(val);
    return DH_SUCCESS;
}

bool IsString(const cJSON *jsonObj, const std::string &key)
{
    if (jsonObj == nullptr || !cJSON_IsObject(jsonObj)) {
        DHLOGE("JSON parameter is invalid.");
        return false;
    }
    cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (paramValue == nullptr) {
        DHLOGE("paramValue is null");
        return false;
    }

    if (cJSON_IsString(paramValue)) {
        return true;
    }
    return false;
}

bool IsInt32(const cJSON *jsonObj, const std::string &key)
{
    if (jsonObj == nullptr || !cJSON_IsObject(jsonObj)) {
        DHLOGE("JSON parameter is invalid.");
        return false;
    }
    cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (paramValue == nullptr) {
        DHLOGE("paramValue is null");
        return false;
    }

    if (cJSON_IsNumber(paramValue)) {
        int value = paramValue->valueint;
        if (INT32_MIN <= value && value <= INT32_MAX) {
            return true;
        }
    }
    return false;
}

bool IsAudioParam(const cJSON *jsonObj, const std::string &key)
{
    if (jsonObj == nullptr || !cJSON_IsObject(jsonObj)) {
        DHLOGE("JSON parameter is invalid.");
        return false;
    }
    cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (paramValue == nullptr || !cJSON_IsObject(paramValue)) {
        DHLOGE("paramValue is null or is not object");
        return false;
    }

    return CJsonParamCheck(paramValue,
        { KEY_SAMPLING_RATE, KEY_CHANNELS, KEY_FORMAT, KEY_SOURCE_TYPE, KEY_CONTENT_TYPE, KEY_STREAM_USAGE });
}

bool CJsonParamCheck(const cJSON *jsonObj, const std::initializer_list<std::string> &keys)
{
    if (jsonObj == nullptr || !cJSON_IsObject(jsonObj)) {
        DHLOGE("JSON parameter is invalid.");
        return false;
    }

    for (auto it = keys.begin(); it != keys.end(); it++) {
        cJSON *paramValue = cJSON_GetObjectItemCaseSensitive(jsonObj, (*it).c_str());
        if (paramValue == nullptr) {
            DHLOGE("JSON parameter does not contain key: %{public}s", (*it).c_str());
            return false;
        }
        auto iter = typeCheckMap.find(*it);
        if (iter == typeCheckMap.end()) {
            DHLOGE("Check is not supported yet, key %{public}s.", (*it).c_str());
            return false;
        }
        JsonTypeCheckFunc &func = iter->second;
        bool res = (*func)(jsonObj, *it);
        if (!res) {
            DHLOGE("The key %{public}s value format in JSON is illegal.", (*it).c_str());
            return false;
        }
    }
    return true;
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
        DHLOGE("GetCurNanoTime fail, ret: %{public}d", ret);
        return result;
    }
    result = (time.tv_sec * AUDIO_NS_PER_SECOND) + time.tv_nsec;
    return result;
}

int32_t AbsoluteSleep(int64_t nanoTime)
{
    int32_t ret = -1;
    if (nanoTime <= 0) {
        DHLOGE("AbsoluteSleep invalid sleep time : %{public}" PRId64" ns", nanoTime);
        return ret;
    }
    struct timespec time;
    time.tv_sec = nanoTime / AUDIO_NS_PER_SECOND;
    time.tv_nsec = nanoTime - (time.tv_sec * AUDIO_NS_PER_SECOND);

    clockid_t clockId = CLOCK_MONOTONIC;
    ret = clock_nanosleep(clockId, TIMER_ABSTIME, &time, nullptr);
    if (ret != 0) {
        DHLOGE("AbsoluteSleep may failed, ret is : %{public}d", ret);
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
        int32_t stringSize = static_cast<int32_t>(jsonString.size());
        DHLOGE("Json string size %{public}d, is zero or too long.", stringSize);
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
        int32_t stringSize = static_cast<int32_t>(devId.size());
        DHLOGE("DevId size %{public}d, is zero or too long.", stringSize);
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

bool IsOutDurationRange(int64_t startTime, int64_t endTime, int64_t lastStartTime)
{
    int64_t currentInterval = endTime - startTime;
    int64_t twiceInterval = startTime - lastStartTime;
    return (currentInterval > MAX_TIME_INTERVAL_US || twiceInterval > MAX_TIME_INTERVAL_US) ? true : false;
}

std::string GetCJsonString(const char *key, const char *value)
{
    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create cJSON object.");
        return "Failed to create cJSON object.";
    }
    cJSON_AddStringToObject(jParam, key, value);
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return "Failed to create JSON data.";
    }
    std::string content(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DHLOGD("create cJSON success : %{public}s", content.c_str());
    return content;
}

std::string ParseStringFromArgs(std::string args, const char *key)
{
    DHLOGD("ParseStringFrom Args : %{public}s", args.c_str());
    cJSON *jParam = cJSON_Parse(args.c_str());
    if (jParam == nullptr) {
        DHLOGE("Failed to parse JSON: %{public}s", cJSON_GetErrorPtr());
        return "Failed to parse JSON";
    }
    if (!CJsonParamCheck(jParam, { key })) {
        DHLOGE("Not found the key : %{public}s.", key);
        cJSON_Delete(jParam);
        return "Not found the key.";
    }
    cJSON *dhIdItem = cJSON_GetObjectItem(jParam, key);
    if (dhIdItem == NULL || !cJSON_IsString(dhIdItem)) {
        DHLOGE("Not found the value of the key : %{public}s.", key);
        cJSON_Delete(jParam);
        return "Not found the value.";
    }
    std::string content(dhIdItem->valuestring);
    cJSON_Delete(jParam);
    DHLOGD("Parsed string is: %{public}s.", content.c_str());
    return content;
}

std::string AddDhIdPrefix(const std::string &dhId)
{
    std::string prefix = "Audio_";
    size_t pos = dhId.find(prefix);
    DHLOGD("Append the prefix. The current dhId is %{public}s.", dhId.c_str());
    if (pos != std::string::npos) {
        DHLOGD("No need to add prefix.");
        return dhId;
    } else {
        prefix.append(dhId);
        DHLOGD("After append the prefix. The current dhId is %{public}s.", prefix.c_str());
        return prefix;
    }
}

std::string ReduceDhIdPrefix(const std::string &dhId)
{
    std::string prefix = "Audio_";
    size_t pos = dhId.find(prefix);
    DHLOGD("Delete the prefix. The current dhId is %{public}s.", dhId.c_str());
    if (pos != std::string::npos) {
        DHLOGD("After delete the prefix. The current dhId is %{public}s.", dhId.substr(prefix.size()).c_str());
        return dhId.substr(prefix.size());
    } else {
        DHLOGD("No need to delete prefix.");
        return dhId;
    }
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

bool IsParamEnabled(const std::string &key, bool &isEnabled)
{
    // by default: old trans
    int32_t policyFlag = 0;
    if (GetSysPara(key.c_str(), policyFlag) && policyFlag == 1) {
        isEnabled = true;
        return true;
    }
    isEnabled = false;
    return false;
}

void SaveFile(const std::string fileName, uint8_t *audioData, int32_t size)
{
    char path[PATH_MAX + 1] = {0x00};
    if (fileName.length() > PATH_MAX || realpath(fileName.c_str(), path) == nullptr) {
        DHLOGE("The file path is invalid.");
        return;
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::out | std::ios::app);
    if (!ofs.is_open()) {
        DHLOGE("open file failed");
        return;
    }
    ofs.write(reinterpret_cast<char*>(audioData), size);
    ofs.close();
}
} // namespace DistributedHardware
} // namespace OHOS