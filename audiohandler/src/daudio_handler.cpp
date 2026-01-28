/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "avcodec_list.h"
#include "string_ex.h"

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHandler"

namespace OHOS {
namespace DistributedHardware {
FWK_IMPLEMENT_SINGLE_INSTANCE(DAudioHandler);

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
        return AddParamsToJson(dhItem, infoJson, MIC, micInfos_);
    } else if (deviceType == AUDIO_DEVICE_TYPE_SPEAKER) {
        return AddParamsToJson(dhItem, infoJson, SPEAKER, spkInfos_);
    }
    return true;
}

bool DAudioHandler::AddParamsToJson(DHItem &dhItem, cJSON* infoJson, const std::string &subtype, const AudioInfo &infos)
{
    dhItem.subtype = subtype;
    cJSON *sampleArray = cJSON_CreateArray();
    CHECK_NULL_RETURN(sampleArray, false);
    cJSON_AddItemToObject(infoJson, SAMPLERATES, sampleArray);
    for (const auto &value : infos.sampleRates) {
        cJSON_AddItemToArray(sampleArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
    }
    cJSON *channelArray = cJSON_CreateArray();
    CHECK_NULL_RETURN(channelArray, false);
    cJSON_AddItemToObject(infoJson, CHANNELMASKS, channelArray);
    for (const auto &value : infos.channels) {
        cJSON_AddItemToArray(channelArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
    }
    cJSON *formatsArray = cJSON_CreateArray();
    CHECK_NULL_RETURN(formatsArray, false);
    cJSON_AddItemToObject(infoJson, FORMATS, formatsArray);
    for (const auto &value : infos.formats) {
        cJSON_AddItemToArray(formatsArray, cJSON_CreateNumber(static_cast<uint32_t>(value)));
    }
    cJSON *usageArray = cJSON_CreateArray();
    CHECK_NULL_RETURN(usageArray, false);
    cJSON_AddItemToObject(infoJson, SUPPORTEDSTREAM, usageArray);
    for (const auto &value : supportedStream_) {
        cJSON_AddItemToArray(usageArray, cJSON_CreateString(value.c_str()));
    }
    cJSON *codecArray = cJSON_CreateArray();
    CHECK_NULL_RETURN(codecArray, false);
    cJSON_AddItemToObject(infoJson, CODEC, codecArray);
    for (const auto &value : codec_) {
        cJSON_AddItemToArray(codecArray, cJSON_CreateString(value.c_str()));
    }
    cJSON_AddStringToObject(infoJson, PROTOCOLVER, VERSION_TWO);
    return true;
}

std::vector<DHItem> DAudioHandler::QueryMeta()
{
    DHLOGI("Query meta distributed hardware information.");
    return RealQuery(KEY_TYPE_META);
}

std::vector<DHItem> DAudioHandler::Query()
{
    DHLOGI("Query full distributed hardware information.");
    return RealQuery(KEY_TYPE_FULL);
}

std::vector<DHItem> DAudioHandler::RealQuery(const std::string &dataType)
{
    auto audioSrv = AudioStandard::AudioSystemManager::GetInstance();
    std::vector<DHItem> dhItemVec;
    CHECK_AND_RETURN_RET_LOG(audioSrv == nullptr, dhItemVec, "Unable to get audio system manager.");
    auto audioDevices = audioSrv->GetDevices(AudioStandard::DeviceFlag::ALL_DEVICES_FLAG);
    for (auto dev : audioDevices) {
        if (dev == nullptr) {
            continue;
        }
        auto dhId = audioSrv->GetPinValueFromType(dev->deviceType_, dev->deviceRole_);
        if (dhId != DEFAULT_RENDER_ID && dhId != DEFAULT_CAPTURE_ID) {
            continue;
        }

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
        cJSON_AddNumberToObject(infoJson, INTERRUPT_GROUP_ID, dev->interruptGroupId_);
        cJSON_AddNumberToObject(infoJson, VOLUME_GROUP_ID, dev->volumeGroupId_);
        cJSON_AddStringToObject(infoJson, KEY_DATATYPE, dataType.c_str());
        dhItem.dhId = std::to_string(dhId);
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
            dhItem.dhId = std::to_string(LOW_LATENCY_RENDER_ID);
            dhItemVec.push_back(dhItem);
            DHLOGD("Query result: dhId: %{public}d, attrs: %{public}s.", LOW_LATENCY_RENDER_ID, jsonInfo);
        }
        cJSON_Delete(infoJson);
        cJSON_free(jsonInfo);
    }
    DHLOGD("Query result: size: (%{public}zu).", dhItemVec.size());
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

bool DAudioHandler::IsMimeSupported(const std::string &coder)
{
    DHLOGD("Craete avCodecList start.");
    std::shared_ptr<MediaAVCodec::AVCodecList> avCodecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    if (avCodecList == nullptr) {
        DHLOGE("Create avCodecList failed.");
        return false;
    }
    MediaAVCodec::CapabilityData *capData = avCodecList->GetCapability(coder, true,
        MediaAVCodec::AVCodecCategory::AVCODEC_NONE);
    if (capData == nullptr) {
        DHLOGI("%{public}s is not supported.", coder.c_str());
        return false;
    }
    return true;
}

void DAudioHandler::AddToVec(std::vector<std::string> &container, const std::string &value)
{
    auto it = std::find(container.begin(), container.end(), value);
    if (it == container.end()) {
        container.push_back(value);
    }
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
    AddToVec(supportedStream_, MUSIC);
    AddToVec(codec_, PCM);
    if (IsMimeSupported(std::string(MediaAVCodec::CodecMimeType::AUDIO_AAC))) {
        AddToVec(codec_, AAC);
    }
    if (IsMimeSupported(std::string(MediaAVCodec::CodecMimeType::AUDIO_OPUS))) {
        AddToVec(codec_, OPUS);
    }
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
