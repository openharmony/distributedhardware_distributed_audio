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
    mic_->SendToProcess(nullptr);
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    mic_->SendToProcess(writeData);
    mic_->frameIndex_ = 10;
    mic_->ptsMap_[mic_->frameIndex_] = 10;
    mic_->SendToProcess(writeData);
    mic_->frameOutIndexFlag_ = 13;
    mic_->SendToProcess(writeData);
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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->EnableDevice(DH_ID, CAP));

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
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID));

    mic_->curPort_ = DH_ID_MIC;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->DisableDevice(DH_ID_MIC));
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
    EXPECT_EQ(DH_SUCCESS, mic_->CreateStream(streamId_));

    eventCb_ = nullptr;
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
    EXPECT_EQ(DH_SUCCESS, mic_->DestroyStream(streamId_));

    eventCb_ = nullptr;
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransportInner>();
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Start());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    EXPECT_FALSE(mic_->IsOpened());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
    mic_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    mic_->isOpened_.store(true);
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    EXPECT_NE(DH_SUCCESS, mic_->Start());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->SetUp());
    EXPECT_EQ(ERR_DH_AUDIO_SA_WAIT_TIMEOUT, mic_->Start());
    EXPECT_FALSE(mic_->IsOpened());

    mic_->isTransReady_.store(true);
    EXPECT_EQ(DH_SUCCESS, mic_->Start());
    mic_->isOpened_.store(true);
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_NE(DH_SUCCESS, mic_->Stop());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SetUp());
    EXPECT_NE(DH_SUCCESS, mic_->Start());
    EXPECT_EQ(DH_SUCCESS, mic_->Stop());
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
    mic_->micTrans_ = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->Release());

    mic_->micTrans_ = std::make_shared<AVTransReceiverTransport>(DEV_ID, mic_);
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->Release());

    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    EXPECT_EQ(DH_SUCCESS, mic_->Release());

    int32_t fd = 10;
    int32_t ashmemLength = 10;
    int32_t streamId = 1;
    int32_t lengthPerTrans = 10;
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
    int64_t timePts = 0;
    mic_->avSyncParam_.isAVsync = 0;
    EXPECT_EQ(DH_SUCCESS, mic_->ReadTimeStampFromAVsync(timePts));
    mic_->avSyncParam_.isAVsync = 1;
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
    int64_t timePts = 0;
    mic_->avSyncParam_.isAVsync = 0;
    EXPECT_EQ(DH_SUCCESS, mic_->WriteTimeStampToAVsync(timePts));
    mic_->avSyncParam_.isAVsync = 1;
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
    std::shared_ptr<AudioData> writedata = nullptr;
    mic_->isStartStatus_ = false;
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
    mic_->dataQueue_.push_back(data);
    mic_->isStartStatus_ = true;
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    mic_->isStartStatus_ = false;
    EXPECT_EQ(DH_SUCCESS, mic_->AVsyncMacthScene(writedata));
    mic_->isStartStatus_ = true;
    for (size_t i = 0; i < 6; ++i) {
        auto data = std::make_shared<AudioData>(DEFAULT_AUDIO_DATA_SIZE);
        mic_->dataQueue_.push_back(data);
    }
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
    mic_->scene_ = 2;
    mic_->isStartStatus_ = true;
    const size_t capacity = 1;
    auto writeData = std::make_shared<AudioData>(capacity);
    mic_->dataQueue_.push_back(writeData);
    std::shared_ptr<AudioData> readData = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    mic_->dataQueue_.push_back(writeData);
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    mic_->isStartStatus_ = false;
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    mic_->scene_ = 3;
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
    mic_->avSyncParam_.isAVsync = 0;
    const size_t capacity = 1;
    std::shared_ptr<AudioData> readData = nullptr;
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    auto writeData = std::make_shared<AudioData>(capacity);
    mic_->dataQueue_.push_back(writeData);
    EXPECT_EQ(DH_SUCCESS, mic_->GetAudioDataFromQueue(readData));
    mic_->avSyncParam_.isAVsync = 1;
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
    AudioEvent event = AudioEvent(OPEN_MIC, "OPEN_MIC");
    int32_t dhId = 0;
    EXPECT_EQ(DH_SUCCESS, mic_->NotifyHdfAudioEvent(event, dhId));

    event.type = MIC_OPENED;
    dhId = DH_ID_MIC;
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
    AudioEventType event = DATA_OPENED;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    event = DATA_CLOSED;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    event = EVENT_UNKNOWN;
    EXPECT_EQ(DH_SUCCESS, mic_->OnStateChange(event));

    eventCb_ = nullptr;
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
    std::shared_ptr<AudioData> data = nullptr;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));
    mic_->avSyncParam_.isAVsync = 0;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));
    mic_->avSyncParam_.isAVsync = 1;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->OnDecodeTransDataDone(data));

    const size_t capacity = 1;
    data = std::make_shared<AudioData>(capacity);
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
    std::string content = "content";
    std::string dstDevId = "dstDevId";
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(MIC_OPENED, content, dstDevId));
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->SendMessage(OPEN_MIC, content, dstDevId));
    mic_->micTrans_ = std::make_shared<MockIAudioDataTransport>();
    mic_->InitCtrlTrans();
    EXPECT_EQ(DH_SUCCESS, mic_->SendMessage(OPEN_MIC, content, dstDevId));
    AVTransEvent event = { EventType::EVENT_START_SUCCESS, "", "" };
    mic_->OnCtrlTransEvent(event);
    event.type = EventType::EVENT_STOP_SUCCESS;
    mic_->OnCtrlTransEvent(event);
    event.type = EventType::EVENT_START_FAIL;
    mic_->OnCtrlTransEvent(event);
    event.type = EventType::EVENT_CHANNEL_CLOSED;
    mic_->OnCtrlTransEvent(event);
    event.type = EventType::EVENT_START_SUCCESS;
    mic_->OnCtrlTransEvent(event);
    mic_->micTrans_ = nullptr;
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
    std::vector<AudioCodecType> container;
    mic_->AddToVec(container, AudioCodecType::AUDIO_CODEC_AAC);
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
    std::vector<AudioCodecType> container = mic_->codec_;
    mic_->codec_.clear();
    mic_->GetCodecCaps(AAC);
    auto num = mic_->codec_.size();
    EXPECT_EQ(1, num);
    mic_->GetCodecCaps(OPUS);
    num = mic_->codec_.size();
    mic_->codec_ = container;
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
    std::vector<AudioCodecType> container = mic_->codec_;
    mic_->codec_.clear();
    mic_->GetCodecCaps(AAC);
    bool ret = mic_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_AAC_EN);
    EXPECT_EQ(ret, true);
    ret = mic_->IsMimeSupported(AudioCodecType::AUDIO_CODEC_OPUS);
    mic_->codec_ = container;
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
    int32_t streamId = 0;
    uint64_t frames = 0;
    CurrentTimeHDF time;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->MmapStart());
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
    int32_t fd = 10;
    int32_t ashmemLength = 10;
    EXPECT_EQ(ERR_DH_AUDIO_NULLPTR, mic_->AVsyncRefreshAshmem(fd, ashmemLength));
    mic_->AVsyncDeintAshmem();
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
    std::string devId = "devId";
    std::string dhId = "dhId";
    AudioAsyncParam param1{-1, 0, 0, 0};
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param1));
    AudioAsyncParam param2{-1, 0, 0, 1};
    EXPECT_EQ(DH_SUCCESS, mic_->UpdateWorkModeParam(devId, dhId, param2));
}
} // namespace DistributedHardware
} // namespace OHOS
