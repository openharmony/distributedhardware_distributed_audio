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

#ifndef DISTRIBUTED_AUDIO_TEST_H
#define DISTRIBUTED_AUDIO_TEST_H

#include <chrono>
#include <iostream>
#include <string>
#include <cstdlib>
#include <sys/stat.h>
#include <thread>
#include <vector>

#include "audio_adapter.h"
#include "audio_manager.h"
#include "audio_types.h"
#include "daudio_errcode.h"

const std::string CMD_QUIT = "quit";
const std::string CMD_FIND = "find";
const std::string CMD_OPEN_SPK = "openspk";
const std::string CMD_CLOSE_SPK = "closespk";
const std::string CMD_START_SPK = "startspk";
const std::string CMD_STOP_SPK = "stopspk";
const std::string CMD_OPEN_MIC = "openmic";
const std::string CMD_CLOSE_MIC = "closemic";
const std::string CMD_START_MIC = "startmic";
const std::string CMD_STOP_MIC = "stopmic";
const std::string CMD_SET_VOL = "setvol";
const std::string CMD_GET_VOL = "getvol";

const std::string CMD_QUIT_EXT = "0";
const std::string CMD_FIND_EXT = "9";
const std::string CMD_OPEN_SPK_EXT = "1";
const std::string CMD_CLOSE_SPK_EXT = "2";
const std::string CMD_START_SPK_EXT = "3";
const std::string CMD_STOP_SPK_EXT = "4";
const std::string CMD_OPEN_MIC_EXT = "5";
const std::string CMD_CLOSE_MIC_EXT = "6";
const std::string CMD_START_MIC_EXT = "7";
const std::string CMD_STOP_MIC_EXT = "8";
const std::string CMD_SET_VOL_EXT = "11";
const std::string CMD_GET_VOL_EXT = "12";

const char DEV_TYPE_SPK = '1';
const char DEV_TYPE_MIC = '2';
const char SPK_FILE_PATH[128] = "/data/test.wav";
const char MIC_FILE_PATH[128] = "/data/mic.pcm";
constexpr int32_t TYPE_OFFSET = 12;
constexpr int32_t AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t VOLUME_MIN = 0;
constexpr int32_t VOLUME_MAX = 15;
constexpr int32_t VOLUME_BIT = 3;
constexpr int32_t RENDER_FRAME_SIZE = 4096;
constexpr int32_t RENDER_INTER_LEAVED = 1;
constexpr int32_t RENDER_STREAM_ID = 0;
constexpr int32_t RENDER_CHANNEL_MASK = 2;
constexpr int32_t CAPTURE_INTER_LEAVED = 1;
constexpr int32_t CAPTURE_STREAM_ID = 2;
constexpr int32_t CAPTURE_CHANNEL_MASK = 2;
constexpr int32_t MILLISECOND_PER_SECOND = 1000;
constexpr int64_t AUDIO_FRAME_TIME_INTERFAL_DEFAULT = 21333;
constexpr int32_t CMD_EXECUTING_RETURN_LENGHT_MAX = 500;

typedef enum {
    DEVICE_IDLE = 0,
    DEVICE_OPEN = 1,
    DEVICE_START = 2,
    DEVICE_STOP = 3,
} DeviceStatus;

struct WAV_HEADER {
    /* RIFF Chunk Descriptor */
    uint8_t riff[4] = {'R', 'I', 'F', 'F'};
    uint32_t chunkSize = 0;
    uint8_t wave[4] = {'W', 'A', 'V', 'E'};
    /* "fmt" sub-chunk */
    uint8_t fmt[4] = {'f', 'm', 't', ' '};
    uint32_t subchunk1Size = 16;
    uint16_t audioFormat = 1;
    uint16_t numOfChan = 2;
    uint32_t samplesPerSec = 44100;
    uint32_t bytesPerSec = 176400;
    uint16_t blockAlign = 2;
    uint16_t bitsPerSample = 16;
    /* "data" sub-chunk */
    uint8_t subchunk2ID[4] = {'d', 'a', 't', 'a'};
    uint32_t subchunk2Size = 0;
};
using WavHdr = struct WAV_HEADER;

#endif