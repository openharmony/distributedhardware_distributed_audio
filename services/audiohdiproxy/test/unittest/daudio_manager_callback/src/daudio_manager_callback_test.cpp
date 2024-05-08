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

#include "daudio_manager_callback_test.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DAudioManagerCallbackTest::SetUpTestCase(void) {}

void DAudioManagerCallbackTest::TearDownTestCase(void) {}

void DAudioManagerCallbackTest::SetUp()
{
    adpName_ = "hello";
    hdiCallback_ = std::make_shared<MockIDAudioHdiCallback>();
    manCallback_ = std::make_shared<DAudioManagerCallback>(hdiCallback_);
}

void DAudioManagerCallbackTest::TearDown() {}

/**
 * @tc.name: CreateStream_001
 * @tc.desc: Verify the CreateStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, CreateStream_001, TestSize.Level1)
{
    manCallback_->callback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, manCallback_->CreateStream(streamId_));
}

/**
 * @tc.name: CreateStream_002
 * @tc.desc: Verify the CreateStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, CreateStream_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: DestroyStream_001
 * @tc.desc: Verify the DestroyStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, DestroyStream_001, TestSize.Level1)
{
    manCallback_->callback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: DestroyStream_002
 * @tc.desc: Verify the DestroyStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, DestroyStream_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_001
 * @tc.desc: Verify the SetParameters function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, SetParameters_001, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioParameter param;
    manCallback_->callback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, manCallback_->SetParameters(streamId_, param));
    EXPECT_EQ(HDF_FAILURE, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_002
 * @tc.desc: Verify the SetParameters function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, SetParameters_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioParameter param = {
        .format = 0x1u,
        .channelCount = 2,
        .sampleRate = 48000,
        .period = 0,
        .frameSize = 0,
        .streamUsage = 0,
        .ext = "HDF_SUCCESS"
    };
    EXPECT_EQ(HDF_SUCCESS, manCallback_->SetParameters(streamId_, param));
    param = {
        .format = 1 << 1,
        .channelCount = 2,
        .sampleRate = 48000,
        .period = 0,
        .frameSize = 0,
        .streamUsage = 1,
        .ext = "HDF_SUCCESS"
    };
    EXPECT_EQ(HDF_SUCCESS, manCallback_->SetParameters(streamId_, param));
    param = {
        .format = 1 << 1 | 1 << 0,
        .channelCount = 2,
        .sampleRate = 48000,
        .period = 0,
        .frameSize = 0,
        .streamUsage = 2,
        .ext = "HDF_SUCCESS"
    };
    EXPECT_EQ(HDF_SUCCESS, manCallback_->SetParameters(streamId_, param));
    param = {
        .format = -1,
        .channelCount = 2,
        .sampleRate = 48000,
        .period = 0,
        .frameSize = 0,
        .streamUsage = -1,
        .ext = "HDF_SUCCESS"
    };
    EXPECT_NE(HDF_SUCCESS, manCallback_->SetParameters(streamId_, param));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, NotifyEvent_001, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    manCallback_->callback_ = nullptr;
    OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent event;
    EXPECT_EQ(HDF_FAILURE, manCallback_->NotifyEvent(streamId_, event));
    EXPECT_EQ(HDF_FAILURE, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: NotifyEvent_002
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, NotifyEvent_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    OHOS::HDI::DistributedAudio::Audioext::V2_0::DAudioEvent event;
    event.type = AudioEventHDF::AUDIO_EVENT_VOLUME_SET;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_MUTE_SET;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_CHANGE_PLAY_STATUS;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_MMAP_START_SPK;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_MMAP_STOP_SPK;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_MMAP_START_MIC;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_MMAP_STOP_MIC;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_START;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = AudioEventHDF::AUDIO_EVENT_STOP;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    event.type = -1;
    event.content = "HDF_SUCCESS";
    EXPECT_EQ(HDF_SUCCESS, manCallback_->NotifyEvent(streamId_, event));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: WriteStreamData_001
 * @tc.desc: Verify the WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, WriteStreamData_001, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    manCallback_->callback_ = nullptr;
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData data;
    EXPECT_EQ(HDF_FAILURE, manCallback_->WriteStreamData(streamId_, data));
    EXPECT_EQ(HDF_FAILURE, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: WriteStreamData_002
 * @tc.desc: Verify the WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, WriteStreamData_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData data;
    data.param.format = 16;
    data.param.channelCount = 2;
    data.param.sampleRate = 48000;
    data.param.period = 2;
    data.param.frameSize = 4096;
    data.param.streamUsage = 1;
    data.param.ext = "hello";
    uint32_t dataSize = 4096;
    std::shared_ptr<OHOS::DistributedHardware::AudioData> audioData = std::make_shared<AudioData>(dataSize);
    data.data.assign(audioData->Data(), audioData->Data() + audioData->Capacity());
    EXPECT_EQ(HDF_SUCCESS, manCallback_->WriteStreamData(streamId_, data));
    audioData = std::make_shared<AudioData>(3000);
    data.data.assign(audioData->Data(), audioData->Data() + audioData->Capacity());
    EXPECT_EQ(HDF_SUCCESS, manCallback_->WriteStreamData(streamId_, data));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: ReadStreamData_001
 * @tc.desc: Verify the ReadStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, ReadStreamData_001, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    manCallback_->callback_ = nullptr;
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData data;
    EXPECT_EQ(HDF_FAILURE, manCallback_->ReadStreamData(streamId_, data));
    EXPECT_EQ(HDF_FAILURE, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: ReadStreamData_002
 * @tc.desc: Verify the ReadStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, ReadStreamData_002, TestSize.Level1)
{
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->CreateStream(streamId_));
    OHOS::HDI::DistributedAudio::Audioext::V2_0::AudioData data;
    data.param.format = 16;
    data.param.channelCount = 2;
    data.param.sampleRate = 48000;
    data.param.period = 1;
    data.param.frameSize = 1;
    data.param.streamUsage = 1;
    data.param.ext = "hello";
    uint32_t dataSize = 4096;
    std::shared_ptr<OHOS::DistributedHardware::AudioData> audioData = std::make_shared<AudioData>(dataSize);
    data.data.assign(audioData->Data(), audioData->Data() + audioData->Capacity());
    EXPECT_EQ(HDF_SUCCESS, manCallback_->ReadStreamData(streamId_, data));
    EXPECT_EQ(HDF_SUCCESS, manCallback_->DestroyStream(streamId_));
}

/**
 * @tc.name: ReadMmapPosition_002
 * @tc.desc: Verify the ReadMmapPosition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, ReadMmapPosition_001, TestSize.Level1)
{
    int32_t streamId = 0;
    uint64_t frames = 1;
    OHOS::HDI::DistributedAudio::Audioext::V2_0::CurrentTime time;
    EXPECT_EQ(HDF_SUCCESS, manCallback_->ReadMmapPosition(streamId, frames, time));
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->ReadMmapPosition(streamId, frames, time));
}

/**
 * @tc.name: RefreshAshmemInfo_002
 * @tc.desc: Verify the RefreshAshmemInfo function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(DAudioManagerCallbackTest, RefreshAshmemInfo_001, TestSize.Level1)
{
    int32_t streamId = 1;
    int fd = 1;
    int32_t ashmemLength = 240;
    int32_t lengthPerTrans = 960;
    EXPECT_EQ(HDF_SUCCESS, manCallback_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
    manCallback_->callback_ = std::make_shared<MockIDAudioHdiCallback>();
    EXPECT_EQ(HDF_SUCCESS, manCallback_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
}
} // DistributedHardware
} // OHOS