/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <fstream>
#include <map>
#include <string>
#include "cJSON.h"

#define AUDIO_MS_PER_SECOND 1000
#define AUDIO_US_PER_SECOND 1000000
#define AUDIO_NS_PER_SECOND ((int64_t)1000000000)
namespace OHOS {
namespace DistributedHardware {
const std::string DUMP_SERVER_PARA = "sys.daudio.dump.write.enable";
const std::string DUMP_SERVICE_DIR = "/data/local/tmp/";

int32_t GetLocalDeviceNetworkId(std::string &networkId);
std::string GetRandomID();
std::string GetAnonyString(const std::string &value);
int32_t GetDevTypeByDHId(int32_t dhId);
int64_t GetNowTimeUs();
int32_t GetAudioParamStr(const std::string &params, const std::string &key, std::string &value);
int32_t GetAudioParamBool(const std::string &params, const std::string &key, bool &value);
int32_t GetAudioParamInt(const std::string &params, const std::string &key, int32_t &value);
bool CJsonParamCheck(const cJSON *jsonObj, const std::initializer_list<std::string> &keys);
bool IsString(const cJSON *jsonObj, const std::string &key);
bool IsInt32(const cJSON *jsonObj, const std::string &key);
bool IsAudioParam(const cJSON *jsonObj, const std::string &key);
int32_t CalculateSampleNum(uint32_t sampleRate, uint32_t timems);
int64_t GetCurNano();
int32_t AbsoluteSleep(int64_t nanoTime);
int64_t CalculateOffset(const int64_t frameIndex, const int64_t framePeriodNs, const int64_t startTime);
int64_t UpdateTimeOffset(const int64_t frameIndex, const int64_t framePeriodNs, int64_t &startTime);
void GetCurrentTime(int64_t &tvSec, int64_t &tvNSec);
bool CheckIsNum(const std::string &jsonString);
bool CheckDevIdIsLegal(const std::string &devId);
bool IsOutDurationRange(int64_t startTime, int64_t endTime, int64_t lastStartTime);
void SaveFile(std::string fileName, uint8_t *audioData, int32_t size);
std::string GetCJsonString(const char *key, const char *value);
std::string ParseStringFromArgs(std::string args, const char *key);
std::string GetEventNameByType(const int32_t eventType);

template <typename T>
bool GetSysPara(const char *key, T &value);
bool IsParamEnabled(const std::string &key, bool &isEnabled);

class DumpFileUtil {
public:
    static void OpenDumpFile(const std::string &para, const std::string &fileName, FILE **file);
    static void CloseDumpFile(FILE **dumpFile);
    static void WriteDumpFile(FILE *dumpFile, void *buffer, size_t bufferSize);

    static std::map<std::string, std::string> g_lastPara;

private:
    static FILE *OpenDumpFileInner(const std::string &para, const std::string &fileName);
    static void ChangeDumpFileState(const std::string &para, FILE **dumpFile, const std::string &fileName);
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_UTIL_H
