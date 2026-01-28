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

#ifndef OHOS_DISTRIBUTED_AUDIO_COMMON_DFX_UTILS_INCLUDE_DAUDIO_RADAR_H
#define OHOS_DISTRIBUTED_AUDIO_COMMON_DFX_UTILS_INCLUDE_DAUDIO_RADAR_H

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

#include "dhfwk_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
const std::string ORG_PKG_NAME = "ohos.dhardware.daudio";
const std::string ORG_PKG = "ORG_PKG";
const std::string FUNC = "FUNC";
const std::string BIZ_SCENE = "BIZ_SCENE";
const std::string BIZ_STAGE = "BIZ_STAGE";
const std::string STAGE_RES = "STAGE_RES";
const std::string BIZ_STATE = "BIZ_STATE";
const std::string TO_CALL_PKG = "TO_CALL_PKG";
const std::string HOST_PKG = "HOST_PKG";
const std::string ERROR_CODE = "ERROR_CODE";
const std::string DISTRIBUTED_AUDIO_BEHAVIOR = "DISTRIBUTED_AUDIO_BEHAVIOR";
constexpr char DISTRIBUTED_AUDIO[] = "DISTAUDIO";

enum class BizScene : int32_t {
    AUDIO_INIT = 1,
    SPEAKER_OPEN = 2,
    MIC_OPEN = 3,
    SPEAKER_CLOSE = 4,
    MIC_CLOSE = 5,
    AUDIO_UNINIT = 6,
};

enum class StageRes : int32_t {
    STAGE_IDLE = 0,
    STAGE_SUCC = 1,
    STAGE_FAIL = 2,
    STAGE_CANCEL = 3,
    STAGE_UNKNOW = 4,
};

enum class BizState : int32_t {
    BIZ_STATE_START = 1,
    BIZ_STATE_END = 2,
};

enum class AudioInit : int32_t {
    SERVICE_INIT = 1,
    SOURCE_AUDIO_INIT = 2,
    LOAD_HDF_DRIVER = 3,
};

enum class SpeakerOpen : int32_t {
    CREATE_STREAM = 1,
    INIT_ENGINE = 2,
    TRANS_CONTROL = 3,
    TRANS_START = 4,
    NOTIFY_HDF = 5,
};

enum class MicOpen : int32_t {
    CREATE_STREAM = 1,
    INIT_ENGINE = 2,
    TRANS_CONTROL = 3,
    TRANS_START = 4,
    NOTIFY_HDF = 5,
};

enum class SpeakerClose : int32_t {
    DESTROY_STREAM = 1,
    STOP_TRANS = 2,
    RELEASE_TRANS = 3,
    NOTIFY_HDF = 4,
};

enum class MicClose : int32_t {
    DESTROY_STREAM = 1,
    STOP_TRANS = 2,
    RELEASE_TRANS = 3,
    NOTIFY_HDF = 4,
};

enum class AudioUnInit : int32_t {
    UNREGISTER = 1,
    UNLOAD_HDF_DRIVER = 2,
    DISABLED = 3,
};

class DaudioRadar {
    FWK_DECLARE_SINGLE_INSTANCE(DaudioRadar);
public:
    bool ReportDaudioInit(const std::string& func, AudioInit bizStage, BizState bizState, int32_t errCode);
    bool ReportDaudioInitProgress(const std::string& func, AudioInit bizStage, int32_t errCode);
    bool ReportSpeakerOpen(const std::string& func, SpeakerOpen bizStage, BizState bizState, int32_t errCode);
    bool ReportSpeakerOpenProgress(const std::string& func, SpeakerOpen bizStage, int32_t errCode);
    bool ReportSpeakerClose(const std::string& func, SpeakerClose bizStage, BizState bizState, int32_t errCode);
    bool ReportSpeakerCloseProgress(const std::string& func, SpeakerClose bizStage, int32_t errCode);
    bool ReportMicOpen(const std::string& func, MicOpen bizStage, BizState bizState, int32_t errCode);
    bool ReportMicOpenProgress(const std::string& func, MicOpen bizStage, int32_t errCode);
    bool ReportMicClose(const std::string& func, MicClose bizStage, BizState bizState, int32_t errCode);
    bool ReportMicCloseProgress(const std::string& func, MicClose bizStage, int32_t errCode);
    bool ReportDaudioUnInit(const std::string& func, AudioUnInit bizStage, BizState bizState, int32_t errCode);
    bool ReportDaudioUnInitProgress(const std::string& func, AudioUnInit bizStage, int32_t errCode);
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_AUDIO_COMMON_DFX_UTILS_INCLUDE_DAUDIO_RADAR_H