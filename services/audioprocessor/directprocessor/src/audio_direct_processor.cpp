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

#include "audio_direct_processor.h"

#include "daudio_errorcode.h"
#include "daudio_hisysevent.h"
#include "daudio_hitrace.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDirectProcessor"

namespace OHOS {
namespace DistributedHardware {
int32_t AudioDirectProcessor::ConfigureAudioProcessor(const AudioCommonParam &localDevParam,
    const AudioCommonParam &remoteDevParam, const std::shared_ptr<IAudioProcessorCallback> &procCallback)
{
    DHLOGI("Configure direct audio processor.");
    CHECK_NULL_RETURN(procCallback, ERR_DH_AUDIO_BAD_VALUE);
    procCallback_ = procCallback;
    return DH_SUCCESS;
}

int32_t AudioDirectProcessor::ReleaseAudioProcessor()
{
    DHLOGI("Release direct audio processor.");
    return DH_SUCCESS;
}

int32_t AudioDirectProcessor::StartAudioProcessor()
{
    DHLOGI("Start direct audio processor.");
    return DH_SUCCESS;
}

int32_t AudioDirectProcessor::StopAudioProcessor()
{
    DHLOGI("Stop direct audio processor.");
    return DH_SUCCESS;
}

int32_t AudioDirectProcessor::FeedAudioProcessor(const std::shared_ptr<AudioData> &inputData)
{
    DHLOGD("Feed audio processor.");
    CHECK_NULL_RETURN(inputData, ERR_DH_AUDIO_BAD_VALUE);
    auto cbObj = procCallback_.lock();
    CHECK_NULL_RETURN(cbObj, ERR_DH_AUDIO_BAD_VALUE);
    cbObj->OnAudioDataDone(inputData);
    return DH_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS