/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "histreamer_query_tool.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioHandler"

using json = nlohmann::json;

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DAudioHandler);

DAudioHandler::DAudioHandler()
{
    encoderInfos_.channelMaxVal = 0;
    encoderInfos_.channelMinVal = 0;
    decoderInfos_.channelMaxVal = 0;
    decoderInfos_.channelMinVal = 0;
    spkInfos_.channelMaxVal = 0;
    spkInfos_.channelMinVal = 0;
    micInfos_.channelMaxVal = 0;
    micInfos_.channelMinVal = 0;
    DHLOGD("Distributed audio handler constructed.");
}

DAudioHandler::~DAudioHandler()
{
    DHLOGD("Distributed audio handler deconstructed.");
}

int32_t DAudioHandler::Initialize()
{
    DHLOGI("Distributed audio handler initialize.");
    int32_t ret = QueryCodecInfo();
    if (ret != DH_SUCCESS) {
        DHLOGE("Failed to query the codec information.");
        return ret;
    }
    ret = QueryAudioInfo();
    GetSupportAudioInfo(audioInfos_, encoderInfos_, decoderInfos_);
    return ret;
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

        json infoJson;
        int32_t deviceType = GetDevTypeByDHId(dhId);
        if (deviceType == AUDIO_DEVICE_TYPE_MIC) {
            infoJson["SampleRates"] = micInfos_.sampleRates;
            infoJson["ChannelMasks"] = micInfos_.channels;
            infoJson["Formats"] = micInfos_.formats;
        } else if (deviceType == AUDIO_DEVICE_TYPE_SPEAKER) {
            infoJson["SampleRates"] = spkInfos_.sampleRates;
            infoJson["ChannelMasks"] = spkInfos_.channels;
            infoJson["Formats"] = spkInfos_.formats;
        }
        infoJson["INTERRUPT_GROUP_ID"] = dev->interruptGroupId_;
        infoJson["VOLUME_GROUP_ID"] = dev->volumeGroupId_;

        std::string audioEncoders =
            HiStreamerQueryTool::GetInstance().QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::AUDIO_ENCODER);
        DHLOGI("DScreen QueryAudioEncoderAbility info: %s", audioEncoders.c_str());
        infoJson[KEY_HISTREAMER_AUDIO_ENCODER] = audioEncoders;

        std::string audioDecoders =
            HiStreamerQueryTool::GetInstance().QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::AUDIO_DECODER);
        DHLOGI("DScreen QueryAudioDecoderAbility info: %s", audioDecoders.c_str());
        infoJson[KEY_HISTREAMER_AUDIO_DECODER] = audioDecoders;

        DHItem dhItem;
        dhItem.dhId = std::to_string(dhId);
        dhItem.attrs = infoJson.dump();
        dhItemVec.push_back(dhItem);
        DHLOGD("Query result: dhId: %d, attrs: %s.", dhId, infoJson.dump().c_str());
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
int32_t DAudioHandler::QueryCodecInfo()
{
    DHLOGD("Query codec information.");
    auto avCodecList = Media::AVCodecListFactory::CreateAVCodecList();
    if (avCodecList == nullptr) {
        DHLOGE("Failed to query the avcodec information.");
        return ERR_DH_AUDIO_NULLPTR;
    }

    bool queryFlag = false;
    for (auto codec : avCodecList->GetAudioEncoderCaps()) {
        if (codec == nullptr || codec->GetCodecInfo() == nullptr || codec->GetCodecInfo()->GetName() != AVENC_AAC) {
            continue;
        }
        encoderInfos_.sampleRates = codec->GetSupportedSampleRates();
        encoderInfos_.formats = codec->GetSupportedFormats();
        encoderInfos_.channelMaxVal = codec->GetSupportedChannel().maxVal;
        encoderInfos_.channelMinVal = codec->GetSupportedChannel().minVal;
        queryFlag = true;
    }

    for (auto codec : avCodecList->GetAudioDecoderCaps()) {
        if (codec == nullptr || codec->GetCodecInfo() == nullptr || codec->GetCodecInfo()->GetName() != AVENC_AAC) {
            continue;
        }
        decoderInfos_.sampleRates = codec->GetSupportedSampleRates();
        decoderInfos_.formats = codec->GetSupportedFormats();
        decoderInfos_.channelMaxVal = codec->GetSupportedChannel().maxVal;
        decoderInfos_.channelMinVal = codec->GetSupportedChannel().minVal;
        queryFlag = true;
    }

    if (queryFlag == false) {
        DHLOGE("Failed to query the codec information.");
        return ERR_DH_AUDIO_FAILED;
    }
    return DH_SUCCESS;
}

int32_t DAudioHandler::QueryAudioInfo()
{
    DHLOGD("Start to query codec information.");
    audioInfos_.sampleRates = OHOS::AudioStandard::AudioCapturer::GetSupportedSamplingRates();
    audioInfos_.formats = OHOS::AudioStandard::AudioCapturer::GetSupportedFormats();
    audioInfos_.channels = OHOS::AudioStandard::AudioCapturer::GetSupportedChannels();
    return DH_SUCCESS;
}

void DAudioHandler::GetSupportAudioInfo(AudioInfo &audioInfos, CoderInfo &encoderInfos,
    CoderInfo &decoderInfos)
{
    for (auto iter = audioInfos.sampleRates.begin(); iter != audioInfos.sampleRates.end(); iter++) {
        if (std::find(encoderInfos.sampleRates.begin(), encoderInfos.sampleRates.end(), *iter) !=
            encoderInfos.sampleRates.end()) {
            micInfos_.sampleRates.push_back(*iter);
        }
        if (std::find(decoderInfos.sampleRates.begin(), decoderInfos.sampleRates.end(), *iter) !=
            decoderInfos.sampleRates.end()) {
            spkInfos_.sampleRates.push_back(*iter);
        }
    }

    for (auto iter = audioInfos.formats.begin(); iter != audioInfos.formats.end(); iter++) {
        if (std::find(encoderInfos.formats.begin(), encoderInfos.formats.end(), *iter) != encoderInfos.formats.end()) {
            micInfos_.formats.push_back(*iter);
        }
        if (std::find(decoderInfos.formats.begin(), decoderInfos.formats.end(), *iter) != decoderInfos.formats.end()) {
            spkInfos_.formats.push_back(*iter);
        }
    }

    for (auto iter = audioInfos.channels.begin(); iter != audioInfos.channels.end(); iter++) {
        if (*iter <= encoderInfos.channelMaxVal && *iter >= encoderInfos.channelMinVal) {
            micInfos_.channels.push_back(*iter);
        }
        if (*iter <= decoderInfos.channelMaxVal && *iter >= decoderInfos.channelMinVal) {
            spkInfos_.channels.push_back(*iter);
        }
    }
    if (micInfos_.sampleRates.empty()) {
        micInfos_.sampleRates.push_back(SAMPLE_RATE_DEFAULT);
    }
    if (spkInfos_.sampleRates.empty()) {
        spkInfos_.sampleRates.push_back(SAMPLE_RATE_DEFAULT);
    }
    if (micInfos_.channels.empty()) {
        micInfos_.channels.push_back(CHANNEL_COUNT_DEFAULT);
    }
    if (spkInfos_.channels.empty()) {
        spkInfos_.channels.push_back(CHANNEL_COUNT_DEFAULT);
    }
    if (micInfos_.formats.empty()) {
        micInfos_.formats.push_back(SAMPLE_FORMAT_DEFAULT);
    }
    if (spkInfos_.formats.empty()) {
        spkInfos_.formats.push_back(SAMPLE_FORMAT_DEFAULT);
    }
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
    if (listener == nullptr) {
        DHLOGE("The parameter is empty.");
        return;
    }
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
