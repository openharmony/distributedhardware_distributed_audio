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
#include "audio_decoder.h"
#undef private

#include "audio_data.h"
#include "audio_event.h"
#include "decoder_callback_test.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"
#include "daudio_util.h"
#include "audio_decoder.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DecoderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AudioDecoder> audiodecoder_ = nullptr;
    std::shared_ptr<IAudioCodecCallback> decodeCb_ = nullptr;
};

const AudioCommonParam LOC_COMPARA_ENC_TEST = {SAMPLE_RATE_48000, STEREO, SAMPLE_S16LE, AUDIO_CODEC_AAC};

void DecoderTest::SetUpTestCase(void)
{
}

void DecoderTest::TearDownTestCase(void)
{
}

void DecoderTest::SetUp(void)
{
    audiodecoder_ = std::make_shared<AudioDecoder>();
    decodeCb_ = std::make_shared<AudioDecoderCallbackTest>();
}

void DecoderTest::TearDown(void)
{
    audiodecoder_ = nullptr;
    decodeCb_ = nullptr;
}

/**
 * @tc.name: decode_test_001
 * @tc.desc: Verify decode destruct function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, decode_test_001, TestSize.Level1)
{
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, decodeCb_));
    audiodecoder_ = std::make_shared<AudioDecoder>();
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audiodecoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, nullptr));
}

/**
 * @tc.name: decode_test_002
 * @tc.desc: Verify start stop decoder function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, decode_test_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audiodecoder_->StartAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->StopAudioCodec());
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> inputData = std::make_shared<AudioData>(bufLen);
    EXPECT_EQ(EOK, memset_s(inputData->Data(), inputData->Size(), 0, inputData->Size()));
    EXPECT_EQ(ERR_DH_AUDIO_CODEC_INPUT, audiodecoder_->FeedAudioData(inputData));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, decodeCb_));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->StartAudioCodec());
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audiodecoder_->FeedAudioData(nullptr));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->StopAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: decode_test_003
 * @tc.desc: Verify decode data function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, decode_test_003, TestSize.Level1)
{
    audiodecoder_ = std::make_shared<AudioDecoder>();
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, decodeCb_));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->StartAudioCodec());

    for (int32_t i = 0; i < 200; i++) {
        size_t bufLen = 4096;
        std::shared_ptr<AudioData> inputData = std::make_shared<AudioData>(bufLen);
        EXPECT_EQ(EOK, memset_s(inputData->Data(), inputData->Size(), 0, inputData->Size()));
        EXPECT_EQ(DH_SUCCESS, audiodecoder_->FeedAudioData(inputData));
    }

    EXPECT_EQ(DH_SUCCESS, audiodecoder_->StopAudioCodec());
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: decode_test_004
 * @tc.desc: Verify decode data function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, decode_test_004, TestSize.Level1)
{
    audiodecoder_ = std::make_shared<AudioDecoder>();
    for (int32_t i = 0; i < 200; i++) {
        audiodecoder_->OnInputBufferAvailable(1);
    }
    Media::AVCodecBufferInfo info;
    Media::AVCodecBufferFlag flag = static_cast<Media::AVCodecBufferFlag>(0);
    audiodecoder_->OnOutputBufferAvailable(1, info, flag);
    Media::Format format;
    AudioEvent event;
    audiodecoder_->OnOutputFormatChanged(format);
    audiodecoder_->OnError(event);
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ConfigureAudioCodec(LOC_COMPARA_ENC_TEST, decodeCb_));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->ReleaseAudioCodec());
}

/**
 * @tc.name: DecodeDone_001
 * @tc.desc: Verify DecodeDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, DecodeDone_001, TestSize.Level1)
{
    audiodecoder_ = std::make_shared<AudioDecoder>();
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> outputData = std::make_shared<AudioData>(bufLen);
    std::shared_ptr<IAudioCodecCallback> decodeCb = std::make_shared<AudioDecoderCallbackTest>();
    audiodecoder_->codecCallback_ = decodeCb;
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->DecodeDone(outputData));
    audiodecoder_->ReduceWaitDecodeCnt();
}

/**
 * @tc.name: DecodeDone_002
 * @tc.desc: Verify DecodeDone function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, DecodeDone_002, TestSize.Level1)
{
    AudioEvent event;
    audiodecoder_ = std::make_shared<AudioDecoder>();
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> outputData = std::make_shared<AudioData>(bufLen);
    std::shared_ptr<IAudioCodecCallback> callback = nullptr;
    audiodecoder_->codecCallback_ = callback;
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audiodecoder_->DecodeDone(outputData));
    audiodecoder_->OnError(event);
}

/**
 * @tc.name: InitAudioDecoder_001
 * @tc.desc: Verify InitAudioDecoder function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, InitAudioDecoder_001, TestSize.Level1)
{
    AudioCommonParam codecParam;
    audiodecoder_ = std::make_shared<AudioDecoder>();
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->InitAudioDecoder(codecParam));
    EXPECT_EQ(DH_SUCCESS, audiodecoder_->SetDecoderFormat(codecParam));
}

/**
 * @tc.name: ProcessData_001
 * @tc.desc: Verify ProcessData function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, ProcessData_001, TestSize.Level1)
{
    size_t bufLen = 4096;
    std::shared_ptr<AudioData> inputData = std::make_shared<AudioData>(bufLen);
    int32_t bufferIndex = 0;
    audiodecoder_ = std::make_shared<AudioDecoder>();
    uint32_t index = 1;
    Media::AVCodecBufferInfo info;
    Media::AVCodecBufferFlag flag = static_cast<Media::AVCodecBufferFlag>(0);
    EXPECT_EQ(ERR_DH_AUDIO_BAD_VALUE, audiodecoder_->ProcessData(inputData, bufferIndex));
    audiodecoder_->OnOutputBufferAvailable(index, info, flag);
}

/**
 * @tc.name: IsInDecodeRange_001
 * @tc.desc: Verify IsInDecodeRange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, IsInDecodeRange_001, TestSize.Level1)
{
    AudioCommonParam codecParam;
    EXPECT_EQ(false, audiodecoder_->IsInDecodeRange(codecParam));
}

/**
 * @tc.name: IsInDecodeRange_002
 * @tc.desc: Verify IsInDecodeRange function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E5U
 */
HWTEST_F(DecoderTest, IsInDecodeRange_002, TestSize.Level1)
{
    AudioCommonParam codecParam;
    codecParam.bitFormat = SAMPLE_S16LE;
    EXPECT_EQ(true, audiodecoder_->IsInDecodeRange(codecParam));
}
} // namespace DistributedHardware
} // namespace OHOS
