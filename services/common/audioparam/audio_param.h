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

#ifndef OHOS_DAUDIO_AUDIO_PARAM_H
#define OHOS_DAUDIO_AUDIO_PARAM_H

#include <string>

namespace OHOS {
namespace DistributedHardware {
typedef enum {
    SAMPLE_RATE_8000 = 8000,
    SAMPLE_RATE_11025 = 11025,
    SAMPLE_RATE_12000 = 12000,
    SAMPLE_RATE_16000 = 16000,
    SAMPLE_RATE_22050 = 22050,
    SAMPLE_RATE_24000 = 24000,
    SAMPLE_RATE_32000 = 32000,
    SAMPLE_RATE_44100 = 44100,
    SAMPLE_RATE_48000 = 48000,
    SAMPLE_RATE_64000 = 64000,
    SAMPLE_RATE_96000 = 96000
} AudioSampleRate;

typedef enum {
    SOURCE_TYPE_INVALID = -1,
    SOURCE_TYPE_MIC,
    SOURCE_TYPE_VOICE_CALL
} SourceType;

typedef enum {
    MONO = 1,
    STEREO = 2
} AudioChannel;

typedef enum {
    SAMPLE_U8 = 0,
    SAMPLE_S16LE = 1,
    SAMPLE_S24LE = 2,
    SAMPLE_S32LE = 3,
    SAMPLE_F32LE = 4,
    INVALID_WIDTH = -1
} AudioSampleFormat;

typedef enum {
    AUDIO_CODEC_AAC = 0,
    AUDIO_CODEC_FLAC = 1
} AudioCodecType;

typedef enum {
    CONTENT_TYPE_UNKNOWN = 0,
    CONTENT_TYPE_SPEECH = 1,
    CONTENT_TYPE_MUSIC = 2,
    CONTENT_TYPE_MOVIE = 3,
    CONTENT_TYPE_SONIFICATION = 4,
    CONTENT_TYPE_RINGTONE = 5
} ContentType;

typedef enum {
    STREAM_USAGE_UNKNOWN = 0,
    STREAM_USAGE_MEDIA = 1,
    STREAM_USAGE_VOICE_COMMUNICATION = 2,
    STREAM_USAGE_VOICE_ASSISTANT = 4,
    STREAM_USAGE_NOTIFICATION_RINGTONE = 6
} StreamUsage;

typedef struct AudioCommonParam {
    AudioSampleRate sampleRate = SAMPLE_RATE_8000;
    AudioChannel channelMask = MONO;
    AudioSampleFormat bitFormat = SAMPLE_U8;
    AudioCodecType codecType = AUDIO_CODEC_AAC;
} AudioCommonParam;


typedef struct AudioCaptureOptions {
    SourceType sourceType = SOURCE_TYPE_INVALID;
    int32_t capturerFlags = 0;
} AudioCaptureOptions;

typedef struct AudioRenderOptions {
    ContentType contentType = CONTENT_TYPE_UNKNOWN;
    StreamUsage streamUsage = STREAM_USAGE_UNKNOWN;
    int32_t renderFlags = 0;
} AudioRenderOptions;

typedef struct {
    AudioSampleRate sampleRate;
    AudioChannel channelMask;
    AudioSampleFormat bitFormat;
    StreamUsage streamUsage;
    uint32_t frameSize;
    uint32_t period;
    std::string ext;
} AudioParamHDF;

typedef struct {
    AudioCommonParam comParam;
    AudioCaptureOptions CaptureOpts;
    AudioRenderOptions renderOpts;
} AudioParam;

typedef enum {
    STATE_UNKOWN = -1,
    STATE_CHANNEL_OPEN = 0,
    STATE_CHANNEL_CLOSE = 1
} STATE;
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_AUDIO_PARAM_H
