/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dmic_dev_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t DH_ID = 1;
constexpr size_t NOTIFY_WAIT_FRAMES = 5;
constexpr int32_t DH_ID_MIC = 134217728;
const std::string DEV_ID = "Test_Dev_Id";
const std::string CAP = "Test_Capability";

void DMicDevTest::SetUpTestCase(void) {}

void DMicDevTest::TearDownTestCase(void) {}

void DMicDevTest::SetUp(void)
{
    eventCb_ = std::make_shared<MockIAudioEventCallback>();
    mic_ = std::make_shared<DMicDev>(DEV_ID, eventCb_);
}

void DMicDevTest::TearDown(void)
{
    eventCb_ = nullptr;
    mic_ = nullptr;
}

/**
 * @tc.name: InitReceiverEngine_001
 * @tc.desc: Verify InitReceiverEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, InitReceiverEngine_001, TestSize.Level1)
{
    IAVEngineProvider *providerPtr = nullptr;
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    mic_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_STOP_SUCCESS;
    mic_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_START_FAIL;
    mic_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    mic_->OnEngineTransEvent(event);
    event.type = EventType::EVENT_START_SUCCESS;
    mic_->OnEngineTransEvent(event);

    std::shared_ptr<AVTransMessage> message = nullptr;
    mic_->OnEngineTransMessage(message);
    size_t size = 4096;
    auto audioData = std::make_shared<AudioData>(size);
    mic_->OnEngineTransDataAvailable(audioData);
    mic_->SendToProcess(audioData);
    mic_->echoCannelOn_ = true;
    mic_->OnEngineTransDataAvailable(audioData);
    mic_->SendToProcess(audioData);
    mic_->echoCannelOn_ = false;
    mic_->SendToProcess(audioData);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->InitReceiverEngine(providerPtr));
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->InitReceiverEngine(providerPtr));
}

/**
 * @tc.name: SendToProcess_001
 * @tc.desc: Verify SendToProcess and EnableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SendToProcess_001, TestSize.Level1)
{
    // Call SendToProcess with null pointer
    mic_->SendToProcess(nullptr);
    // Define audio data capacity
    const size_t capacity = 1;
    // Create audio data shared pointer
    auto writeData = std::make_shared<AudioData>(capacity);
    // Call SendToProcess with valid audio data
    mic_->SendToProcess(writeData);
    // Set frame index value
    mic_->frameIndex_ = 10;
    // Store pts value in map
    mic_->ptsMap_[mic_->frameIndex_] = 10;
    // Call SendToProcess again
    mic_->SendToProcess(writeData);
    // Set frame output index flag
    mic_->frameOutIndexFlag_ = 13;
    // Call SendToProcess with flag set
    mic_->SendToProcess(writeData);
    // Verify audio data is not null
    EXPECT_NE(nullptr, writeData);
}

/**
 * @tc.name: EnableDMic_001
 * @tc.desc: Verify EnableDMic and EnableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, EnableDMic_001, TestSize.Level1)
{
    // Verify EnableDevice returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));
    // Verify EnableDevice returns null pointer error repeatedly
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));

    // Verify EnableDevice with mic ID returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID_MIC, CAP));
}

/**
 * @tc.name: DisableDMic_001
 * @tc.desc: Verify DisableDMic and DisableDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, DisableDMic_001, TestSize.Level1)
{
    // Verify DisableDevice returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID));

    // Set current port to mic ID
    mic_->curPort_ = DH_ID_MIC;
    // Verify DisableDevice with mic ID returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID_MIC));
    // Verify device is not opened
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: CreateStream_001
 * @tc.desc: Verify CreateStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, CreateStream_001, TestSize.Level1)
{
    // Verify CreateStream returns success
    EXPECT_EQ(DH_SUCCESS, mic_->CreateStream(streamId_));

    // Set event callback to null
    eventCb_ = nullptr;
    // Verify CreateStream returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->CreateStream(streamId_));
}

/**
 * @tc.name: DestroyStream_001
 * @tc.desc: Verify DestroyStream function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, DestroyStream_001, TestSize.Level1)
{
    // Verify DestroyStream returns success
    EXPECT_EQ(DH_SUCCESS, mic_->DestroyStream(streamId_));

    // Set event callback to null
    eventCb_ = nullptr;
    // Verify DestroyStream returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DestroyStream(streamId_));
}

/**
 * @tc.name: SetParameters_001
 * @tc.desc: Verify SetParameters and GetAudioParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetParameters_001, TestSize.Level1)
{
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_8000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_U8,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 30,
        .period = 0,
        .ext = "Test",
    };
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    mic_->GetAudioParam();
    param.streamUsage = StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));

    param.capturerFlags = MMAP_MODE;
    EXPECT_EQ(ERR_DH_AUDIO_SA_PARAM_INVALID, mic_->SetParameters(streamId_, param));
    param.period = 5;
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    param.period = 20;
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    mic_->GetCodecCaps(AAC);
    mic_->GetCodecCaps(OPUS);
    param.streamUsage = StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, NotifyEvent_001, TestSize.Level1)
{
    AudioEvent event = AudioEvent(OPEN_MIC, "OPEN_MIC");
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    event.type = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    mic_->isTransReady_ = false;
    event.type = AUDIO_START;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    event.type = AUDIO_STOP;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    mic_->isTransReady_ = true;
    for (int32_t i = 0; i < NOTIFY_WAIT_FRAMES; i++) {
        size_t size = 4096;
        auto audioData = std::make_shared<AudioData>(size);
        mic_->dataQueue_.push_back(audioData);
    }
    event.type = AUDIO_START;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyEvent(streamId_, event));

    eventCb_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->NotifyEvent(streamId_, event));
}

/**
 * @tc.name: SetUp_001
 * @tc.desc: Verify SetUp function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetUp_001, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify SetUp returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());

    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Verify SetUp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());

    // Create another mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransportInner>();
    // Verify SetUp returns failed
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, mic_->SetUp());
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Start_001, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify Start returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Start());

    // Create receiver transport instance
    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    // Verify Start does not return success
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    // Verify device is not opened
    EXPECT_FALSE(mic_->IsOpened());

    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Verify SetUp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
    // Set transport ready status to true
    mic_->isTransReady_.store(true);
    // Verify Start returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    // Set opened status to true
    mic_->isOpened_.store(true);
    // Verify device is opened
    EXPECT_TRUE(mic_->IsOpened());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify Start and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Start_002, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify SetUp returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    // Verify Start does not return success
    EXPECT_NE(DH_SUCCESS, mic_->Start());

    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Verify SetUp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
    // Verify Start returns timeout error
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, mic_->Start());
    // Verify device is not opened
    EXPECT_FALSE(mic_->IsOpened());

    // Set transport ready status to true
    mic_->isTransReady_.store(true);
    // Verify Start returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    // Set opened status to true
    mic_->isOpened_.store(true);
    // Verify device is opened
    EXPECT_TRUE(mic_->IsOpened());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Stop_001, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify Stop returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());

    // Create receiver transport instance
    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    // Verify Stop does not return success
    EXPECT_NE(DH_SUCCESS, mic_->Stop());

    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Verify Stop returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
    // Verify device is not opened
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: Stop_002
 * @tc.desc: Verify Stop and IsOpened function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Stop_002, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify SetUp returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    // Verify Start does not return success
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    // Verify Stop returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
    // Verify device is not opened
    EXPECT_FALSE(mic_->IsOpened());
}

/**
 * @tc.name: Release_001
 * @tc.desc: Verify Release function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Release_001, TestSize.Level1)
{
    // Set mic transport to null
    mic_->micTrans_ = nullptr;
    // Verify Release returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Release());

    // Create receiver transport instance
    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    // Verify Release returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Release());

    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Verify Release returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Release());

    // Define test parameters
    int32_t fd = 10;
    int32_t ashmemLength = 10;
    int32_t streamId = 1;
    int32_t lengthPerTrans = 10;
    // Verify refresh ashmem info returns success
    EXPECT_EQ(DH_SUCCESS, mic_->RefreshAshmemInfo(streamId, fd, ashmemLength, lengthPerTrans));
}

/**
 * @tc.name: ReadTimeStampFromAVsync_001
 * @tc.desc: Verify ReadTimeStampFromAVsync function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, ReadTimeStampFromAVsync_001, TestSize.Level1)
{
    // Initialize timestamp variable
    int64_t timePts = 0;
    // Disable AV sync mode
    mic_->avSyncParam_.isAVsync = 0;
    // Verify read timestamp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->ReadTimeStampFromAVsync(timePts));
    // Enable AV sync mode
    mic_->avSyncParam_.isAVsync = 1;
    // Verify read timestamp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->ReadTimeStampFromAVsync(timePts));
}

/**
 * @tc.name: WriteTimeStampToAVsync_001
 * @tc.desc: Verify WriteTimeStampToAVsync function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, WriteTimeStampToAVsync_001, TestSize.Level1)
{
    // Initialize timestamp variable
    int64_t timePts = 0;
    // Disable AV sync mode
    mic_->avSyncParam_.isAVsync = 0;
    // Verify write timestamp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->WriteTimeStampToAVsync(timePts));
    // Enable AV sync mode
    mic_->avSyncParam_.isAVsync = 1;
    // Verify write timestamp returns success
    EXPECT_EQ(DH_SUCCESS, mic_->WriteTimeStampToAVsync(timePts));
}

/**
 * @tc.name: AVsyncMacthScene_001
 * @tc.desc: Verify AVsyncMacthScene function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, AVsyncMacthScene_001, TestSize.Level1)
{
    // Set audio data pointer to null
    std::shared_ptr<AudioData> writedata = nullptr;
    // Set start status to false
    mic_->isStartStatus_ = false;
    // Verify AV sync match returns success
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    // Create audio data instance
    auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
    // Add data to queue
    mic_->dataQueue_.push_back(data);
    // Set start status to true
    mic_->isStartStatus_ = true;
    // Verify AV sync match returns success
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    // Set start status to false
    mic_->isStartStatus_ = false;
    // Verify AV sync match returns success
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    // Set start status to true
    mic_->isStartStatus_ = true;
    // Fill data queue with multiple entries
    for (size_t i = 0; i < 6; ++i) {
        auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        mic_->dataQueue_.push_back(data);
    }
    // Verify AV sync match returns success
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
}

/**
 * @tc.name: GetAudioDataFromQueue_001
 * @tc.desc: Verify GetAudioDataFromQueue function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, GetAudioDataFromQueue_001, TestSize.Level1)
{
    // Set scene type
    mic_->scene_ = 2;
    // Set start status to true
    mic_->isStartStatus_ = true;
    // Define data capacity
    const size_t capacity = 1;
    // Create audio data instance
    auto writeData = std::make_shared<AudioData>(capacity);
    // Add data to queue
    mic_->dataQueue_.push_back(writeData);
    // Initialize read data pointer
    std::shared_ptr<AudioData> readData = nullptr;
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    // Add data to queue again
    mic_->dataQueue_.push_back(writeData);
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    // Set start status to false
    mic_->isStartStatus_ = false;
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    // Change scene type
    mic_->scene_ = 3;
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
}

/**
 * @tc.name: GetAudioDataFromQueue_002
 * @tc.desc: Verify GetAudioDataFromQueue function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, GetAudioDataFromQueue_002, TestSize.Level1)
{
    // Disable AV sync mode
    mic_->avSyncParam_.isAVsync = 0;
    // Define data capacity
    const size_t capacity = 1;
    // Initialize read data pointer
    std::shared_ptr<AudioData> readData = nullptr;
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    // Create audio data instance
    auto writeData = std::make_shared<AudioData>(capacity);
    // Add data to queue
    mic_->dataQueue_.push_back(writeData);
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    // Enable AV sync mode
    mic_->avSyncParam_.isAVsync = 1;
    // Verify get data from queue returns success
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
}

/**
 * @tc.name: ReadStreamData_001
 * @tc.desc: Verify ReadStreamData and WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, ReadStreamData_001, TestSize.Level1)
{
    mic_->curStatus_ = AudioStatus::STATUS_START;
    mic_->paramHDF_.period = 10;
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    EXPECT_EQ(DH_SUCCESS, mic_->WriteStreamData(streamId_, writeData));

    std::shared_ptr<AudioData> readData = nullptr;
    mic_->dataQueue_.push_back(writeData);
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData));
    for (size_t i = 0; i < 11; ++i) {
        auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        mic_->dataQueue_.push_back(data);
    }
    mic_->isEnqueueRunning_ = true;
    mic_->FillJitterQueue();
    mic_->paramHDF_.period = 0;
    mic_->FillJitterQueue();
    mic_->paramHDF_.period = 10;
    mic_->FillJitterQueue();
    std::shared_ptr<AudioData> readData1 = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData1));

    mic_->curStatus_ = AudioStatus::STATUS_STOP;
    EXPECT_EQ(ERR_DH_AUDIO_FAILED, mic_->ReadStreamData(streamId_, readData1));

    mic_->curStatus_ = AudioStatus::STATUS_START;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData1));
    mic_->avSyncParam_.isAVsync = 1;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData1));
    mic_->avSyncParam_.isAVsync = 0;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadStreamData(streamId_, readData1));
}

/**
 * @tc.name: NotifyHdfAudioEvent_001
 * @tc.desc: Verify NotifyHdfAudioEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, NotifyHdfAudioEvent_001, TestSize.Level1)
{
    // Create audio open event
    AudioEvent event = AudioEvent(OPEN_MIC, "OPEN_MIC");
    // Set test device ID
    int32_t dhId = 0;
    // Verify notify HDF audio event returns success
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyHdfAudioEvent(event, dhId));

    // Change event type to mic opened
    event.type = MIC_OPENED;
    // Set device ID to mic ID
    dhId = DH_ID_MIC;
    // Verify notify HDF audio event returns success
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyHdfAudioEvent(event, dhId));
}

/**
 * @tc.name: OnStateChange_001
 * @tc.desc: Verify OnStateChange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnStateChange_001, TestSize.Level1)
{
    // Set event type to data opened
    AudioEventType event = DATA_OPENED;
    // Verify state change callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    // Change event type to data closed
    event = DATA_CLOSED;
    // Verify state change callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    // Change event type to unknown
    event = EVENT_UNKNOWN;
    // Verify state change callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    // Set event callback to null
    eventCb_ = nullptr;
    // Verify state change callback returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnStateChange(event));
}

/**
 * @tc.name: OnDecodeTransDataDone_001
 * @tc.desc: Verify OnDecodeTransDataDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnDecodeTransDataDone_001, TestSize.Level1)
{
    // Set audio data pointer to null
    std::shared_ptr<AudioData> data = nullptr;
    // Verify decode done callback returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));
    // Disable AV sync mode
    mic_->avSyncParam_.isAVsync = 0;
    // Verify decode done callback returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));
    // Enable AV sync mode
    mic_->avSyncParam_.isAVsync = 1;
    // Verify decode done callback returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));

    // Define data capacity
    const size_t capacity = 1;
    // Create valid audio data instance
    data = std::make_shared<AudioData>(capacity);
    // Fill data queue beyond max size
    for (size_t i = 1; i <= mic_->DATA_QUEUE_MAX_SIZE + 1; i++) {
        EXPECT_EQ(DH_SUCCESS, mic_->OnDecodeTransDataDone(data));
    }
}

/**
 * @tc.name: SendMessage_001
 * @tc.desc: Verify SendMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SendMessage_001, TestSize.Level1)
{
    // Define test message content
    std::string content = "content";
    // Define test destination device ID
    std::string dstDevId = "dstDevId";
    // Verify send message returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(MIC_OPENED, content, dstDevId));
    // Verify send message returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(OPEN_MIC, content, dstDevId));
    // Create mock transport instance
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    // Initialize control transport
    mic_->InitCtrlTrans();
    // Verify send message returns success
    EXPECT_EQ(DH_SUCCESS, mic_->SendMessage(OPEN_MIC, content, dstDevId));
    // Create start success event
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    // Handle control transport event
    mic_->OnCtrlTransEvent(event);
    // Change event type to stop success
    event.type = EventType::EVENT_STOP_SUCCESS;
    // Handle control transport event
    mic_->OnCtrlTransEvent(event);
    // Change event type to start fail
    event.type = EventType::EVENT_START_FAIL;
    // Handle control transport event
    mic_->OnCtrlTransEvent(event);
    // Change event type to channel closed
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    // Handle control transport event
    mic_->OnCtrlTransEvent(event);
    // Change event type to start success
    event.type = EventType::EVENT_START_SUCCESS;
    // Handle control transport event
    mic_->OnCtrlTransEvent(event);
    // Set transport to null
    mic_->micTrans_ = nullptr;
    // Verify init control transport does not return success
    EXPECT_NE(DH_SUCCESS, mic_->InitCtrlTrans());
}

/**
 * @tc.name: AddToVec001
 * @tc.desc: Verify AddToVec function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, AddToVec001, TestSize.Level1)
{
    // Create empty codec type container
    std::vector<AudioCodecType> container;
    // Add AAC codec type to container
    mic_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
    // Verify container size is 1
    EXPECT_EQ(1, container.size());
}

/**
 * @tc.name: GetCodecCaps001
 * @tc.desc: Verify GetCodecCaps function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, GetCodecCaps001, TestSize.Level1)
{
    // Save original codec list
    std::vector<AudioCodecType> container = mic_->codec_;
    // Clear codec list
    mic_->codec_.clear();
    // Get AAC codec capabilities
    mic_->GetCodecCaps(AAC);
    // Get codec list size
    auto num = mic_->codec_.size();
    // Verify codec list size is 1
    EXPECT_EQ(1, num);
    // Get OPUS codec capabilities
    mic_->GetCodecCaps(OPUS);
    // Get codec list size
    num = mic_->codec_.size();
    // Restore original codec list
    mic_->codec_ = container;
    // Verify codec list size is 2
    EXPECT_EQ(2, num);
}

/**
 * @tc.name: IsMimeSupported001
 * @tc.desc: Verify IsMimeSupported function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, IsMimeSupported001, TestSize.Level1)
{
    // Save original codec list
    std::vector<AudioCodecType> container = mic_->codec_;
    // Clear codec list
    mic_->codec_.clear();
    // Get AAC codec capabilities
    mic_->GetCodecCaps(AAC);
    // Check if AAC encoder is supported
    bool ret = mic_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_AAC_EN);
    // Verify result is true
    EXPECT_EQ(ret, true);
    // Check if OPUS is supported
    ret = mic_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_OPUS);
    // Restore original codec list
    mic_->codec_ = container;
    // Verify result is false
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReadMmapPosition001
 * @tc.desc: Verify ReadMmapPosition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, ReadMmapPosition001, TestSize.Level1)
{
    // Set test stream ID
    int32_t streamId = 0;
    // Initialize frame count variable
    uint64_t frames = 0;
    // Initialize time structure
    CurrentTimeHDF time;
    // Verify MMAP start returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->MmapStart());
    // Verify read MMAP position returns success
    EXPECT_EQ(DH_SUCCESS, mic_->ReadMmapPosition(streamId, frames, time));
}

/**
 * @tc.name: AVsyncRefreshAshmem001
 * @tc.desc: Verify AVsyncRefreshAshmem function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, AVsyncRefreshAshmem001, TestSize.Level1)
{
    // Set test file descriptor
    int32_t fd = 10;
    // Set test ashmem length
    int32_t ashmemLength = 10;
    // Verify AV sync refresh ashmem returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->AVsyncRefreshAshmem(fd, ashmemLength));
    // Deinitialize AV sync ashmem
    mic_->AVsyncDeintAshmem();
    // Verify AV sync ashmem pointer is null
    EXPECT_EQ(nullptr, mic_->avsyncAshmem_);
}

/**
 * @tc.name: UpdateWorkModeParam001
 * @tc.desc: Verify UpdateWorkModeParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, UpdateWorkModeParam001, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    std::string dhId = "dhId";
    // Define async parameter with invalid scene
    AudioAsyncParam param1{-1, 0, 0, 0};
    // Verify update work mode parameter returns success
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param1));
    // Define async parameter with valid scene
    AudioAsyncParam param2{-1, 0, 0, 1};
    // Verify update work mode parameter returns success
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param2));
}

/**
 * @tc.name: OnCtrlTransMessage_001
 * @tc.desc: Verify OnCtrlTransMessage function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnCtrlTransMessage_001, TestSize.Level1)
{
    // Set transport message pointer to null
    std::shared_ptr<AVTransMessage> message = nullptr;
    // Handle null control transport message
    mic_->OnCtrlTransMessage(message);

    // Create valid transport message
    message = std::make_shared<AVTransMessage>();
    // Set message type to open mic
    message->type_ = OPEN_MIC;
    // Set message destination device ID
    message->dstDevId_ = DEV_ID;
    // Set message content
    message->content_ = "TestContent";
    // Handle control transport message
    mic_->OnCtrlTransMessage(message);
    // Verify message pointer is not null
    EXPECT_NE(nullptr, message);
}

/**
 * @tc.name: InitSenderEngine_001
 * @tc.desc: Verify InitSenderEngine function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, InitSenderEngine_001, TestSize.Level1)
{
    // Set engine provider pointer to null
    IAVEngineProvider *providerPtr = nullptr;
    // Verify init sender engine returns success
    EXPECT_EQ(DH_SUCCESS, mic_->InitSenderEngine(providerPtr));
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Pause_001, TestSize.Level1)
{
    // Verify pause function returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Pause());
}

/**
 * @tc.name: Restart_001
 * @tc.desc: Verify Restart function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, Restart_001, TestSize.Level1)
{
    // Verify restart function returns success
    EXPECT_EQ(DH_SUCCESS, mic_->Restart());
}

/**
 * @tc.name: GetQueSize_001
 * @tc.desc: Verify GetQueSize function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, GetQueSize_001, TestSize.Level1)
{
    // Get initial queue size
    uint32_t size = mic_->GetQueSize();
    // Verify queue size is 0
    EXPECT_EQ(0, size);

    // Create audio data instance
    auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
    // Add data to queue
    mic_->dataQueue_.push_back(data);
    // Get queue size after adding data
    size = mic_->GetQueSize();
    // Verify queue size is 1
    EXPECT_EQ(1, size);
}

/**
 * @tc.name: IsAVsync_001
 * @tc.desc: Verify IsAVsync function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, IsAVsync_001, TestSize.Level1)
{
    // Disable AV sync mode
    mic_->avSyncParam_.isAVsync = 0;
    // Verify AV sync is disabled
    EXPECT_FALSE(mic_->IsAVsync());

    // Enable AV sync mode
    mic_->avSyncParam_.isAVsync = 1;
    // Verify AV sync is enabled
    EXPECT_TRUE(mic_->IsAVsync());
}

/**
 * @tc.name: OnEngineTransDataAvailable_002
 * @tc.desc: Verify OnEngineTransDataAvailable with index flag.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnEngineTransDataAvailable_002, TestSize.Level1)
{
    // Set audio data size
    size_t size = 4096;
    // Create audio data instance
    auto audioData = std::make_shared<AudioData>(size);
    // Set audio data PTS
    audioData->SetPts(1000);
    // Set audio data special PTS
    audioData->SetPtsSpecial(2000);

    // Set frame input index
    mic_->frameInIndex_ = 14;
    // Create ring buffer instance
    mic_->ringBuffer_ = std::make_unique<DaudioRingBuffer>();
    // Initialize ring buffer
    mic_->ringBuffer_->RingBufferInit(mic_->frameData_);
    // Handle engine transport data available
    mic_->OnEngineTransDataAvailable(audioData);
    // Verify frame input index is reset to 0
    EXPECT_EQ(0, mic_->frameInIndex_);

    // Set frame input index
    mic_->frameInIndex_ = 15;
    // Handle engine transport data available
    mic_->OnEngineTransDataAvailable(audioData);
    // Verify frame input index is incremented
    EXPECT_EQ(16, mic_->frameInIndex_);
}

/**
 * @tc.name: SendToProcess_002
 * @tc.desc: Verify SendToProcess with ptsMap scenarios.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SendToProcess_002, TestSize.Level1)
{
    // Define data capacity
    const size_t capacity = 1;
    // Create audio data instance
    auto audioData = std::make_shared<AudioData>(capacity);

    // Clear PTS map
    mic_->ptsMap_.clear();
    // Reset frame output index
    mic_->frameOutIndex_ = 0;
    // Send data to process
    mic_->SendToProcess(audioData);

    // Add PTS entry to map
    mic_->ptsMap_[0] = 100;
    // Send data to process
    mic_->SendToProcess(audioData);
    // Verify PTS map size is 1
    EXPECT_EQ(1, mic_->ptsMap_.size());

    // Add another PTS entry to map
    mic_->ptsMap_[15] = 200;
    // Set frame output index
    mic_->frameOutIndex_ = 15;
    // Set frame output index flag
    mic_->frameOutIndexFlag_ = 16;
    // Send data to process
    mic_->SendToProcess(audioData);
    // Verify frame output index is reset to 0
    EXPECT_EQ(0, mic_->frameOutIndex_);
}

/**
 * @tc.name: OnDecodeTransDataDone_002
 * @tc.desc: Verify OnDecodeTransDataDone with MMAP_MODE.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnDecodeTransDataDone_002, TestSize.Level1)
{
    // Define audio parameters with MMAP mode
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 4096,
        .period = 5,
        .capturerFlags = MMAP_MODE,
    };
    // Set audio parameters
    mic_->SetParameters(streamId_, param);

    // Set current status to start
    mic_->curStatus_ = AudioStatus::STATUS_START;
    // Define data capacity
    const size_t capacity = 4096;
    // Create audio data instance
    auto data = std::make_shared<AudioData>(capacity);
    // Verify decode done callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnDecodeTransDataDone(data));

    // Set current status to idle
    mic_->curStatus_ = AudioStatus::STATUS_IDLE;
    // Verify decode done callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnDecodeTransDataDone(data));

    // Set empty data flag to true
    mic_->isExistedEmpty_.store(true);
    // Verify decode done callback returns success
    EXPECT_EQ(DH_SUCCESS, mic_->OnDecodeTransDataDone(data));
}

/**
 * @tc.name: AVsyncRefreshAshmem_002
 * @tc.desc: Verify AVsyncRefreshAshmem with various parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, AVsyncRefreshAshmem_002, TestSize.Level1)
{
    // Set invalid file descriptor
    int32_t fd = -1;
    // Set ashmem length
    int32_t ashmemLength = 8192;
    // Verify AV sync refresh ashmem returns success
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncRefreshAshmem(fd, ashmemLength));

    // Set valid file descriptor
    fd = 10;
    // Set small ashmem length
    ashmemLength = 1024;
    // Verify AV sync refresh ashmem returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->AVsyncRefreshAshmem(fd, ashmemLength));
    // Verify AV sync ashmem pointer is not null
    EXPECT_NE(nullptr, mic_->avsyncAshmem_);

    // Deinitialize AV sync ashmem
    mic_->AVsyncDeintAshmem();
    // Verify AV sync ashmem pointer is null
    EXPECT_EQ(nullptr, mic_->avsyncAshmem_);
}

/**
 * @tc.name: UpdateWorkModeParam_002
 * @tc.desc: Verify UpdateWorkModeParam with AVsync scene types.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, UpdateWorkModeParam_002, TestSize.Level1)
{
    // Define test device ID
    std::string devId = "devId";
    // Define test DH ID
    std::string dhId = "dhId";
    // Define async parameter for broadcast scene
    AudioAsyncParam param1{10, 1024, static_cast<uint32_t>(AudioAVScene::BROADCAST), 1};
    // Verify update work mode parameter returns null pointer error
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->UpdateWorkModeParam(devId, dhId, param1));
    // Verify scene is not set to broadcast size
    EXPECT_NE(DMicDev::DATA_QUEUE_BROADCAST_SIZE, mic_->scene_);

    // Define async parameter for video call scene
    AudioAsyncParam param2{10, 1024, static_cast<uint32_t>(AudioAVScene::VIDEOCALL), 1};
    // Verify update work mode parameter returns success
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param2));
    // Verify scene is set to video call size
    EXPECT_EQ(DMicDev::DATA_QUEUE_VIDEOCALL_SIZE, mic_->scene_);

    // Define default async parameter
    AudioAsyncParam param3{-1, 0, 0, 0};
    // Verify update work mode parameter returns success
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param3));
}

/**
 * @tc.name: OnEngineTransMessage_002
 * @tc.desc: Verify OnEngineTransMessage with valid message.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnEngineTransMessage_002, TestSize.Level1)
{
    // Create transport message instance
    auto message = std::make_shared<AVTransMessage>();
    // Set message type to close mic
    message->type_ = CLOSE_MIC;
    // Set message destination device ID
    message->dstDevId_ = DEV_ID;
    // Set message content
    message->content_ = "TestContent";
    // Handle engine transport message
    mic_->OnEngineTransMessage(message);
    // Verify message pointer is not null
    EXPECT_NE(nullptr, message);
}

/**
 * @tc.name: WriteStreamData_001
 * @tc.desc: Verify WriteStreamData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, WriteStreamData_001, TestSize.Level1)
{
    // Define data capacity
    const size_t capacity = 4096;
    // Create audio data instance
    auto data = std::make_shared<AudioData>(capacity);
    // Verify write stream data returns success
    EXPECT_EQ(DH_SUCCESS, mic_->WriteStreamData(streamId_, data));
}

/**
 * @tc.name: MmapStop_001
 * @tc.desc: Verify MmapStop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, MmapStop_001, TestSize.Level1)
{
    // Verify MMAP stop returns success
    EXPECT_EQ(DH_SUCCESS, mic_->MmapStop());

    // Set enqueue running flag to true
    mic_->isEnqueueRunning_.store(true);
    // Verify MMAP stop returns success
    EXPECT_EQ(DH_SUCCESS, mic_->MmapStop());
}

/**
 * @tc.name: RefreshAshmemInfo_002
 * @tc.desc: Verify RefreshAshmemInfo with existing ashmem.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, RefreshAshmemInfo_002, TestSize.Level1)
{
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 4096,
        .period = 5,
        .capturerFlags = MMAP_MODE,
    };
    mic_->SetParameters(streamId_, param);

    int32_t fd = 10;
    int32_t ashmemLength = 1024;
    int32_t lengthPerTrans = 512;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->RefreshAshmemInfo(streamId_, fd, ashmemLength, lengthPerTrans));

    // Call again with ashmem already created
    EXPECT_EQ(DH_SUCCESS, mic_->RefreshAshmemInfo(streamId_, fd, ashmemLength, lengthPerTrans));
}

/**
 * @tc.name: GetAudioParam_001
 * @tc.desc: Verify GetAudioParam function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, GetAudioParam_001, TestSize.Level1)
{
    AudioParamHDF paramHdf = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 4096,
        .period = 5,
    };
    mic_->SetParameters(streamId_, paramHdf);

    AudioParam param = mic_->GetAudioParam();
    EXPECT_EQ(SAMPLE_RATE_48000, param.comParam.sampleRate);
    EXPECT_EQ(STEREO, param.comParam.channelMask);
    EXPECT_EQ(SAMPLE_S16LE, param.comParam.bitFormat);
}

/**
 * @tc.name: OnDecodeTransDataDone_003
 * @tc.desc: Verify OnDecodeTransDataDone with queue overflow.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, OnDecodeTransDataDone_003, TestSize.Level1)
{
    mic_->curStatus_ = AudioStatus::STATUS_START;
    const size_t capacity = 4096;

    // Fill queue beyond max size
    for (size_t i = 0; i < 20; i++) {
        auto data = std::make_shared<AudioData>(capacity);
        mic_->OnDecodeTransDataDone(data);
    }

    EXPECT_GT(mic_->dataQueue_.size(), 0);
}

/**
 * @tc.name: FillJitterQueue_001
 * @tc.desc: Verify FillJitterQueue function behavior.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, FillJitterQueue_001, TestSize.Level1)
{
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_UNKNOWN,
        .frameSize = 4096,
        .period = 5,
        .capturerFlags = MMAP_MODE,
    };
    mic_->SetParameters(streamId_, param);

    mic_->isEnqueueRunning_ = true;
    mic_->paramHDF_.period = 0;
    mic_->FillJitterQueue();

    mic_->paramHDF_.period = 5;
    for (size_t i = 0; i < 15; i++) {
        auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        mic_->dataQueue_.push_back(data);
    }
    mic_->FillJitterQueue();

    mic_->isEnqueueRunning_ = false;
    EXPECT_EQ(false, mic_->isEnqueueRunning_);
}

/**
 * @tc.name: SetParameters_002
 * @tc.desc: Verify SetParameters with AAC codec.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetParameters_002, TestSize.Level1)
{
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_MEDIA,
        .frameSize = 4096,
        .period = 5,
    };
    mic_->codec_.clear();
    mic_->GetCodecCaps("AAC");

    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_AAC_EN, mic_->param_.comParam.codecType);
}

/**
 * @tc.name: SetParameters_003
 * @tc.desc: Verify SetParameters with OPUS codec.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5F
 */
HWTEST_F(DMicDevTest, SetParameters_003, TestSize.Level1)
{
    AudioParamHDF param = {
        .sampleRate = SAMPLE_RATE_48000,
        .channelMask = STEREO,
        .bitFormat = SAMPLE_S16LE,
        .streamUsage = STREAM_USAGE_VOICE_COMMUNICATION,
        .frameSize = 4096,
        .period = 5,
    };
    mic_->codec_.clear();
    mic_->GetCodecCaps("OPUS");

    EXPECT_EQ(DH_SUCCESS, mic_->SetParameters(streamId_, param));
    EXPECT_EQ(AudioCodecType::AUDIO_CODEC_OPUS, mic_->param_.comParam.codecType);
}
} // namespace DistributedHardware
} // namespace OHOS
