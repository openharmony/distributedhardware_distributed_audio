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

#include "hisysevent.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioRadar"

namespace OHOS {
namespace DistributedHardware {
FWK_IMPLEMENT_SINGLE_INSTANCE(DaudioRadar);

bool DaudioRadar::ReportDaudioInit(const std::string& func, AudioInit bizStage, BizState bizState, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_INIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_INIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportDaudioInit error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportDaudioInitProgress(const std::string& func, AudioInit bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_INIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_INIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportDaudioInitProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportSpeakerOpen(const std::string& func, SpeakerOpen bizStage,
    BizState bizState, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportSpeakerOpen error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportSpeakerOpenProgress(const std::string& func, SpeakerOpen bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportSpeakerOpenProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportSpeakerClose(const std::string& func, SpeakerClose bizStage,
    BizState bizState, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportSpeakerClose error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportSpeakerCloseProgress(const std::string& func, SpeakerClose bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SPEAKER_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportSpeakerCloseProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportMicOpen(const std::string& func, MicOpen bizStage,
    BizState bizState, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportMicOpen error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportMicOpenProgress(const std::string& func, MicOpen bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_OPEN),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportMicOpenProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportMicClose(const std::string& func, MicClose bizStage,
    BizState bizState, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportMicClose error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportMicCloseProgress(const std::string& func, MicClose bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MIC_CLOSE),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportMicCloseProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportDaudioUnInit(const std::string& func, AudioUnInit bizStage, BizState bizState,
    int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_UNINIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(bizState));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_UNINIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(bizState),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportDaudioUnInit error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DaudioRadar::ReportDaudioUnInitProgress(const std::string& func, AudioUnInit bizStage, int32_t errCode)
{
    int32_t res = DH_SUCCESS;
    StageRes stageRes = (errCode == DH_SUCCESS) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_UNINIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            DISTRIBUTED_AUDIO,
            DISTRIBUTED_AUDIO_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::AUDIO_UNINIT),
            BIZ_STAGE, static_cast<int32_t>(bizStage),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != DH_SUCCESS) {
        DHLOGE("ReportDaudioUnInitProgress error, res:%{public}d", res);
        return false;
    }
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS