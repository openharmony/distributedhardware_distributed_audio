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

#include "daudio_handler.h"

#include <vector>

#include "audio_system_manager.h"
#include "string_ex.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHandler"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioHandler);

DAudioHandler::DAudioHandler()
{
    DHLOGD("Distributed audio handler constructed.");
}

DAudioHandler::~DAudioHandler()
{
    DHLOGD("Distributed audio handler deconstructed.");
}

int32_t DAudioHandler::Initialize()
{
    DHLOGI("Distributed audio handler initialize.");
    return QueryAudioInfo();
}

bool DAudioHandler::AddItemsToObject(DHItem &dhItem, cJSON* infoJson, const int32_t &dhId)
{
    DHLOGD("Get dhId and then add other items into cjson object");
    int32_t deviceType = GetDevTypeByDHId(dhId);
    if (deviceType == AUDIO_DEVICE_TYPE_MIC) {
        dhItem.subtype = "mic";
        cJSON *sampleArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(sampleArray, false);
        cJSON_AddItemToObject(infoJson, "SampleRates", sampleArray);
        for (const auto &value : micInfos_.sampleRates) {
            cJSON_AddItemToArray(sampleArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }

        cJSON *channelArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(channelArray, false);
        cJSON_AddItemToObject(infoJson, "ChannelMasks", channelArray);
        for (const auto &value : micInfos_.channels) {
            cJSON_AddItemToArray(channelArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }

        cJSON *formatsArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(formatsArray, false);
        cJSON_AddItemToObject(infoJson, "Formats", formatsArray);
        for (const auto &value : micInfos_.formats) {
            cJSON_AddItemToArray(formatsArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }
    } else if (deviceType == AUDIO_DEVICE_TYPE_SPEAKER) {
        dhItem.subtype = "speaker";
        cJSON *sampleArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(sampleArray, false);
        cJSON_AddItemToObject(infoJson, "SampleRates", sampleArray);
        for (const auto &value : spkInfos_.sampleRates) {
            cJSON_AddItemToArray(sampleArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }

        cJSON *channelArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(channelArray, false);
        cJSON_AddItemToObject(infoJson, "ChannelMasks", channelArray);
        for (const auto &value : spkInfos_.channels) {
            cJSON_AddItemToArray(channelArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }

        cJSON *formatsArray = cJSON_CreateArray();
        CHECK_NULL_RETURN(formatsArray, false);
        cJSON_AddItemToObject(infoJson, "Formats", formatsArray);
        for (const auto &value : spkInfos_.formats) {
            cJSON_AddItemToArray(formatsArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
        }
    }
    return true;
}

std::vector<DHItem> DAudioHandler::QueryMeta()
{
    DHLOGI("Query meta distributed hardware information.");
    return Query();
}

std::vector<DHItem> DAudioHandler::Query()
{
    DHLOGI("Query distributed hardware information.");
    auto audioSrv = AudioStandard::AudioSystemManager::GetInstance();
    std::vector<DHItem> dhItemVec;
    if (audioSrv == nullptr) {
        DHLOGE("Unable to get audio system manager.");
        return dhItemVec;
    }

    auto audioDevices = audioSrv->GetDevices(AudioStandard::DeviceFlag::ALL_DEVICES_FLAG);
    for (auto dev : audioDevices) {
        auto dhId = audioSrv->GetPinValueFromType(dev->deviceType_, dev->deviceRole_);

        cJSON* infoJson = cJSON_CreateObject();
        if (infoJson == nullptr) {
            DHLOGE("Failed to create cJSON object.");
            return dhItemVec;
        }
        DHItem dhItem;
        if (!AddItemsToObject(dhItem, infoJson, dhId)) {
            cJSON_Delete(infoJson);
            return dhItemVec;
        }
        cJSON_AddNumberToObject(infoJson, "INTERRUPT_GROUP_ID", dev->interruptGroupId_);
        cJSON_AddNumberToObject(infoJson, "VOLUME_GROUP_ID", dev->volumeGroupId_);
        dhItem.dhId = AddDhIdPrefix(std::to_string(dhId));
        char *jsonInfo = cJSON_Print(infoJson);
        if (jsonInfo == NULL) {
            DHLOGE("Failed to create JSON data.");
            cJSON_Delete(infoJson);
            return dhItemVec;
        }
        dhItem.attrs = jsonInfo;
        dhItemVec.push_back(dhItem);
        DHLOGD("Query result: dhId: %{public}d, subtype: %{public}s, attrs: %{public}s.",
            dhId, dhItem.subtype.c_str(), jsonInfo);
        if (dhId == DEFAULT_RENDER_ID) {
            dhItem.dhId = AddDhIdPrefix(std::to_string(LOW_LATENCY_RENDER_ID));
            dhItemVec.push_back(dhItem);
            DHLOGD("Query result: dhId: %{public}d, attrs: %{public}s.", LOW_LATENCY_RENDER_ID, jsonInfo);
        }
        cJSON_Delete(infoJson);
        cJSON_free(jsonInfo);
    }
    ablityForDumpVec_ = dhItemVec;
    return dhItemVec;
}

std::vector<DHItem> DAudioHandler::ablityForDump()
{
    DHLOGD("Get audio ablity for dump.");
    if (ablityForDumpVec_.size() > 0) {
        return ablityForDumpVec_;
    }
    Initialize();
    Query();
    return ablityForDumpVec_;
}

int32_t DAudioHandler::QueryAudioInfo()
{
    DHLOGD("Start to query codec information.");
    micInfos_.sampleRates = OHOS::AudioStandard::AudioCapturer::GetSupportedSamplingRates();
    micInfos_.formats = OHOS::AudioStandard::AudioCapturer::GetSupportedFormats();
    micInfos_.channels = OHOS::AudioStandard::AudioCapturer::GetSupportedChannels();
    spkInfos_.sampleRates = OHOS::AudioStandard::AudioRenderer::GetSupportedSamplingRates();
    spkInfos_.formats = OHOS::AudioStandard::AudioRenderer::GetSupportedFormats();
    spkInfos_.channels = OHOS::AudioStandard::AudioRenderer::GetSupportedChannels();
    return DH_SUCCESS;
}

std::map<std::string, std::string> DAudioHandler::QueryExtraInfo()
{
    DHLOGD("Query extra information");
    std::map<std::string, std::string> extraInfo;
    return extraInfo;
}

bool DAudioHandler::IsSupportPlugin()
{
    DHLOGD("Is support plug in");
    return false;
}

void DAudioHandler::RegisterPluginListener(std::shared_ptr<PluginListener> listener)
{
    DHLOGI("Register plugin listener");
    CHECK_NULL_VOID(listener);
    listener_ = listener;
}

void DAudioHandler::UnRegisterPluginListener()
{
    DHLOGI("UnRegister plugin listener");
    listener_ = nullptr;
}

IHardwareHandler* GetHardwareHandler()
{
    return &DAudioHandler::GetInstance();
}
} // namespace DistributedHardware
} // namespace OHOS
