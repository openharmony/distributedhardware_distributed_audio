/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <v1_0/iaudio_adapter.h>
#include <v1_0/iaudio_manager.h>
#include <v1_0/iaudio_callback.h>
#include <v1_0/audio_types.h>

enum class DeviceStatus : uint32_t {
    DEVICE_IDLE = 0,
    DEVICE_OPEN = 1,
    DEVICE_START = 2,
    DEVICE_STOP = 3,
};

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