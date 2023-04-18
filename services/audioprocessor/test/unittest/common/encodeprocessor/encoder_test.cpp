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

#include <gtest/gtest.h>
#include <memory>

#define private public
#include "audio_encoder.h"
#undef private

#include "audio_data.h"
#include "audio_event.h"
#include "encoder_callback_test.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "audio_encoder.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class EncoderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AudioEncoder> audioEncoder_ = nullptr;
    std::shared_ptr<IAudioCodecCallback> encodeCb_ = nullptr;
};

const AudioCommonParam LOC_COMPARA_ENC_TEST = {SAMPLE_RATE_48000, STEREO, SAMPLE_S16LE, AUDIO_CODEC_AAC};

void EncoderTest::SetUpTestCase(void)
{
}

void EncoderTest::TearDownTestCase(void)
{
}

void EncoderTest::SetUp(void)
{
    audioEncoder_ = std::make_shared<AudioEncoder>();
    encodeCb_ = std::make_shared<AudioEncoderCallbackTest>();
}

void EncoderTest::TearDown(void)
{
    audioEncoder_ = nullptr;
    encodeCb_ = nullptr;
}

/**
 * @tc.name: encode_test_001
 * @tc.desc: Verify encode destruct function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, encode_test_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, encodeCb_));
    audioEncoder_ = std::make_shared<AudioEncoder>();
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audioEncoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, nullptr));
}

/**
 * @tc.name: encode_test_002
 * @tc.desc: Verify start stop encoder function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, encode_test_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audioEncoder_->StartAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->StopAudioCodec());
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> inputData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(EOK, memset_s(inputData->Data(), inputData->Size(), 0, inputData->Size()));
    EXPECT_EQ(ERR_DH_AUDIO_CODEC_INPUT, audioEncoder_->FeedAudioData(inputData));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, encodeCb_));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->StartAudioCodec());
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audioEncoder_->FeedAudioData(nullptr));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->StopAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: encode_test_003
 * @tc.desc: Verify encode data function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, encode_test_003, TestSize.Level1)
{
    audioEncoder_ = std::make_shared<AudioEncoder>();
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, encodeCb_));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->StartAudioCodec());

    for (int32_t i = 0; i < 200; i++) {
        size_t bufLen = 4096;
        std::shared_ptr<AudioData> inputData = std::make_shared<AudioData>(bufLen);
        EXPECT_EQ(EOK, memset_s(inputData->Data(), inputData->Size(), 0, inputData->Size()));
        EXPECT_EQ(DH_SUCCESS, audioEncoder_->FeedAudioData(inputData));
    }

    EXPECT_EQ(DH_SUCCESS, audioEncoder_->StopAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: encode_test_004
 * @tc.desc: Verify encode data function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, encode_test_004, TestSize.Level1)
{
    audioEncoder_ = std::make_shared<AudioEncoder>();
    for (int32_t i = 0; i < 200; i++) {
        audioEncoder_->OnInputBufferAvailable(1);
    }
    Media::AVCodecBufferInfo info;
    Media::AVCodecBufferFlag flag = static_cast<Media::AVCodecBufferFlag>(0);
    audioEncoder_->OnOutputBufferAvailable(1, info, flag);
    Media::Format format;
    AudioEvent event;
    audioEncoder_->OnOutputFormatChanged(format);
    audioEncoder_->OnError(event);
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, encodeCb_));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: EncodeDone_001
 * @tc.desc: Verify EncodeDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, EncodeDone_001, TestSize.Level1)
{
    audioEncoder_ = std::make_shared<AudioEncoder>();
    size_t bufLen = 4096;
    AudioEvent event;
    std::shared_ptr<AudioData> outputData = std::make_shared<AudioData>(bufLen);
    std::shared_ptr<IAudioCodecCallback> encodeCb = std::make_shared<AudioEncoderCallbackTest>();
    audioEncoder_->codecCallback_ = encodeCb;
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->EncodeDone(outputData));
}

/**
 * @tc.name: EncodeDone_002
 * @tc.desc: Verify EncodeDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, EncodeDone_002, TestSize.Level1)
{
    audioEncoder_ = std::make_shared<AudioEncoder>();
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> outputData = std::make_shared<AudioData>(bufLen);
    std::shared_ptr<IAudioCodecCallback> callback = nullptr;
    audioEncoder_->codecCallback_ = callback;
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audioEncoder_->EncodeDone(outputData));
}

/**
 * @tc.name: InitAudioDecoder_001
 * @tc.desc: Verify InitAudioDecoder function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, InitAudioDecoder_001, TestSize.Level1)
{
    AudioCommonParam codecParam;
    audioEncoder_ = std::make_shared<AudioEncoder>();
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->InitAudioEncoder(codecParam));
    EXPECT_EQ(DH_SUCCESS, audioEncoder_->SetEncoderFormat(codecParam));
}

/**
 * @tc.name: ProcessData_001
 * @tc.desc: Verify ProcessData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(EncoderTest, ProcessData_001, TestSize.Level1)
{
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> audioData = std::make_shared<AudioData>(bufLen);
    int32_t bufferIndex = 0;
    audioEncoder_ = std::make_shared<AudioEncoder>();
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audioEncoder_->ProcessData(audioData, bufferIndex));
}
} // namespace DistributedHardware
} // namespace OHOS