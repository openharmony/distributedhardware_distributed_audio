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
#include "nlohmann/json.hpp"
#include "string_ex.h"

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
        DHItem dhItem;
        int32_t deviceType = GetDevTypeByDHId(dhId);
        if (deviceType == AUDIO_DEVICE_TYPE_MIC) {
            dhItem.subtype = "mic";
            infoJson["SampleRates"] = micInfos_.sampleRates;
            infoJson["ChannelMasks"] = micInfos_.channels;
            infoJson["Formats"] = micInfos_.formats;
        } else if (deviceType == AUDIO_DEVICE_TYPE_SPEAKER) {
            dhItem.subtype = "speaker";
            infoJson["SampleRates"] = spkInfos_.sampleRates;
            infoJson["ChannelMasks"] = spkInfos_.channels;
            infoJson["Formats"] = spkInfos_.formats;
        }
        infoJson["INTERRUPT_GROUP_ID"] = dev->interruptGroupId_;
        infoJson["VOLUME_GROUP_ID"] = dev->volumeGroupId_;

        dhItem.dhId = std::to_string(dhId);
        dhItem.attrs = infoJson.dump();
        dhItemVec.push_back(dhItem);
        DHLOGD("Query result: dhId: %d, subtype: %s, attrs: %s.", dhId, dhItem.subtype.c_str(),
            infoJson.dump().c_str());
        if (dhId == DEFAULT_RENDER_ID) {
            dhItem.dhId = std::to_string(LOW_LATENCY_RENDER_ID);
            dhItemVec.push_back(dhItem);
            DHLOGD("Query result: dhId: %d, attrs: %s.", LOW_LATENCY_RENDER_ID, infoJson.dump().c_str());
        }
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
