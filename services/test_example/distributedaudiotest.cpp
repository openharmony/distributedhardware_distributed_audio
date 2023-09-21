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

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include <csignal>
#include <sys/stat.h>

#include <iostream>
#include <string>

#include <securec.h>
#include "unistd.h"
#include "distributedaudiotest.h"

namespace {
using namespace OHOS::DistributedHardware;
const int32_t CMD_QUIT = 0;
const int32_t CMD_FIND = 9;
const int32_t CMD_OPEN_SPK = 1;
const int32_t CMD_CLOSE_SPK = 2;
const int32_t CMD_START_SPK = 3;
const int32_t CMD_STOP_SPK = 4;
const int32_t CMD_OPEN_MIC = 5;
const int32_t CMD_CLOSE_MIC = 6;
const int32_t CMD_START_MIC = 7;
const int32_t CMD_STOP_MIC = 8;
const int32_t CMD_SET_VOL = 11;
const int32_t CMD_GET_VOL = 12;

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

static AudioManager *g_manager = nullptr;
static AudioAdapter *g_adapter = nullptr;
static AudioRender *g_render = nullptr;
static AudioCapture *g_capture = nullptr;
static AudioAdapterDescriptor *g_devices = nullptr;

static std::string g_devId = "";

static constexpr const char* PLAY_THREAD = "playThread";
static constexpr const char* CAPTURE_THREAD = "captureThread";

int32_t g_deviceNum = 0;
int32_t g_frameNum = 0;
int32_t g_frameIndex = 0;
int32_t g_micFrameNum = 0;
bool g_isInitRenderData = false;
static std::vector<uint8_t*> renderData;

static DeviceStatus g_spkStatus = DEVICE_IDLE;
static DeviceStatus g_micStatus = DEVICE_IDLE;

static std::thread g_playingThread;
static std::thread g_capingThread;
FILE *g_micFile = nullptr;

static std::string CloseSpk();
static std::string CloseMic();

static int64_t GetNowTimeUs()
{
    std::chrono::microseconds nowUs =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

static int32_t GetUserInput()
{
    int32_t res = -1;
    size_t count = 3;
    std::cout << ">>";
    std::cin >> res;
    while (std::cin.fail() && count-- > 0) {
        std::cin.clear();
        std::cin.ignore();
        std::cout << "invalid input, not a number! Please retry with a number." << std::endl;
        std::cout << ">>";
        std::cin >> res;
    }
    return res;
}

static void FindAudioDevice()
{
    if (g_manager == nullptr) {
        std::cout << "Audio manager is null, Please Check network!" << std::endl;
        return;
    }
    int32_t ret = g_manager->GetAllAdapters(g_manager, &g_devices, &g_deviceNum);
    if (ret != DH_SUCCESS) {
        std::cout << "Get audio devices failed!" << std::endl;
        return;
    }
    for (int32_t index = 0; index < g_deviceNum; index++) {
        const AudioAdapterDescriptor &desc = g_devices[index];
        if (index == 0) {
            g_devId = desc.adapterName;
            break;
        }
    }
}

static int32_t InitTestDemo()
{
    std::cout << "**********************************************************************************" << std::endl;
    std::cout << "Distributed Audio Test Demo Bin v1.3." << std::endl;
    std::cout << "**********************************************************************************" << std::endl;
    std::cout << std::endl;
    std::cout << "Init distributed audio hdf service." << std::endl;
    g_manager = GetAudioManagerFuncs();
    if (g_manager == nullptr) {
        std::cout << "Distributed audio manager is null, Please Check network!" << std::endl;
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    std::cout << "Load audio manager success." << std::endl;
    FindAudioDevice();
    if (g_devId.empty()) {
        std::cout << "Cannot find distributed device. Please input 9 to query distribtued device." << std::endl;
    } else {
        std::cout << "Find one distributed device: " << g_devId << std::endl;
    }
    return DH_SUCCESS;
}

static void HandleDevError(const char *condition, const char *value)
{
    if (condition[TYPE_OFFSET] == DEV_TYPE_SPK && g_spkStatus != DEVICE_IDLE) {
        CloseSpk();
    }

    if (condition[TYPE_OFFSET] == DEV_TYPE_MIC && g_micStatus == DEVICE_IDLE) {
        CloseMic();
    }

    std::cout << "Receive abnormal event, Demo quit." << std::endl;
}

static int32_t ParamEventCallback(AudioExtParamKey key, const char *condition, const char *value, void *reserved,
    void *cookie)
{
    std::string val(value);
    std::string con(condition);
    std::cout << std::endl;
    std::cout << "**********************************************************************************" << std::endl;
    std::cout << "Event recived: " << key << std::endl;
    std::cout << "Condition: " << con << std::endl;
    std::cout << "Value: " << val << std::endl;
    std::cout << "**********************************************************************************" << std::endl;
    std::cout << std::endl;

    if (key == AudioExtParamKey::AUDIO_EXT_PARAM_KEY_STATUS && con.rfind("ERR_EVENT", 0) == 0) {
        HandleDevError(condition, value);
    }
    return DH_SUCCESS;
}

static int32_t LoadSpkDev(const std::string &devId)
{
    struct AudioAdapterDescriptor *dev = nullptr;
    for (int32_t index = 0; index < g_deviceNum; index++) {
        struct AudioAdapterDescriptor &desc = g_devices[index];
        if (desc.adapterName == devId) {
            dev = &desc;
            break;
        }
    }
    if (dev == nullptr) {
        std::cout << "Input device id is wrong." << std::endl;
        FindAudioDevice();
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    if (g_manager == nullptr) {
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    if (g_adapter == nullptr) {
        int32_t ret = g_manager->LoadAdapter(g_manager, dev, &g_adapter);
        if (ret != DH_SUCCESS || g_adapter == nullptr) {
            std::cout << "Load audio device failed, ret: " << ret << std::endl;
            return ERR_DH_AUDIO_HDF_FAIL;
        }
    }
    return DH_SUCCESS;
}

static void OpenSpk(const std::string &devId)
{
    if (g_spkStatus != DEVICE_IDLE) {
        std::cout << "Speaker device is already opened." << std::endl;
        return;
    }
    if (LoadSpkDev(devId) != DH_SUCCESS) {
        std::cout << "Load spk failed" << std::endl;
        return;
    }
    ParamCallback callback = ParamEventCallback;
    int32_t ret = g_adapter->RegExtraParamObserver(g_adapter, callback, nullptr);
    if (ret != DH_SUCCESS) {
        std::cout << "Register observer failed, ret: " << ret << std::endl;
        return;
    }

    struct AudioDeviceDescriptor renderDesc;
    renderDesc.pins = AudioPortPin::PIN_OUT_SPEAKER;
    renderDesc.desc = nullptr;
    AudioSampleAttributes g_rattrs = {};
    g_rattrs.type = AUDIO_IN_MEDIA;
    g_rattrs.interleaved = RENDER_INTER_LEAVED;
    g_rattrs.streamId = RENDER_STREAM_ID;
    g_rattrs.channelCount = RENDER_CHANNEL_MASK;
    g_rattrs.sampleRate = AUDIO_SAMPLE_RATE;
    g_rattrs.format = AudioFormat::AUDIO_FORMAT_TYPE_PCM_16_BIT;
    ret = g_adapter->CreateRender(g_adapter, &renderDesc, &g_rattrs, &g_render);
    if (ret != DH_SUCCESS || g_render == nullptr) {
        std::cout << "Open SPK device failed, ret: " << ret << std::endl;
        return;
    }
    g_spkStatus = DEVICE_OPEN;
    std::cout << "Open SPK device success." << std::endl;
}

static void WriteStreamWait(const int64_t &startTime)
{
    int64_t endTime = GetNowTimeUs();
    int64_t passTime = endTime - startTime;

    if (passTime > AUDIO_FRAME_TIME_INTERFAL_DEFAULT) {
        return;
    }
    int64_t remainTime = AUDIO_FRAME_TIME_INTERFAL_DEFAULT - passTime;
    std::this_thread::sleep_for(std::chrono::microseconds(remainTime));
}

static void Play()
{
    if (g_render == nullptr) {
        std::cout << "SPK device is null." << std::endl;
        return;
    }
    if (pthread_setname_np(pthread_self(), PLAY_THREAD) != DH_SUCCESS) {
        std::cout << "Play thread setname failed." << std::endl;
    }
    std::cout << "Playing thread started." << std::endl;
    g_render->control.Start((AudioHandle)g_render);
    g_spkStatus = DEVICE_START;

    uint64_t size = 0;
    while (g_spkStatus == DEVICE_START) {
        int64_t startTime = GetNowTimeUs();
        int32_t ret = g_render->RenderFrame(g_render, renderData[g_frameIndex], RENDER_FRAME_SIZE, &size);
        if (ret != DH_SUCCESS) {
            std::cout<<"RenderFrame failed, index: "<< g_frameIndex << ", ret:  " << ret << std::endl;
        }
        g_frameIndex++;
        if (g_frameNum != 0 && g_frameIndex == g_frameNum) {
            g_frameIndex = 0;
        }
        WriteStreamWait(startTime);
    }
    std::cout << "Playing thread stopped." << std::endl;
}

static void StartRender()
{
    if (g_spkStatus == DEVICE_IDLE) {
        std::cout << "Speaker device is not opened, start render failed." << std::endl;
        return;
    }

    if (g_spkStatus == DEVICE_OPEN) {
        WavHdr wavHeader;
        size_t headerSize = sizeof(WavHdr);
        if (!g_isInitRenderData) {
            struct stat statbuf;
            stat(SPK_FILE_PATH, &statbuf);
            int32_t size = statbuf.st_size;
            g_frameNum = (size - headerSize) / RENDER_FRAME_SIZE;
            std::cout << "Audio file frame num: " << g_frameNum << std::endl;
            for (int32_t j = 0; j < g_frameNum; j++) {
                uint8_t *frame = new uint8_t[RENDER_FRAME_SIZE]();
                renderData.push_back(frame);
            }
            g_isInitRenderData = true;
        }
        FILE *wavFile = fopen(SPK_FILE_PATH, "rb");
        fread(&wavHeader, 1, headerSize, wavFile);
        for (int32_t i = 0; i < g_frameNum; i++) {
            fread(renderData[i], 1, RENDER_FRAME_SIZE, wavFile);
        }
        fclose(wavFile);
        g_frameIndex = 0;
        g_playingThread = std::thread(Play);
        return;
    }
    if (g_spkStatus == DEVICE_START) {
        std::cout << "Speaker device is started." << std::endl;
        return;
    }
    if (g_spkStatus == DEVICE_STOP) {
        g_playingThread = std::thread(Play);
    }
}

static void StopRender()
{
    if (g_render == nullptr) {
        std::cout << "SPK device is null." << std::endl;
        return;
    }

    if (g_spkStatus == DEVICE_IDLE) {
        std::cout << "Speaker device is not opened." << std::endl;
        return;
    }

    if (g_spkStatus == DEVICE_OPEN) {
        std::cout << "Speaker device is not started." << std::endl;
        return;
    }

    if (g_spkStatus == DEVICE_STOP) {
        std::cout << "Speaker device is already stoped." << std::endl;
        return;
    }

    g_spkStatus = DEVICE_STOP;
    if (g_playingThread.joinable()) {
        g_playingThread.join();
    }
    g_render->control.Stop((AudioHandle)g_render);
}

static void CloseSpk()
{
    if (g_spkStatus == DEVICE_IDLE) {
        std::cout << "Speaker device is not opened." << std::endl;
        return;
    }

    if (g_spkStatus == DEVICE_START) {
        StopRender();
    }

    int32_t ret = g_adapter->DestroyRender(g_adapter, g_render);
    if (ret != DH_SUCCESS) {
        std::cout << "Close speaker failed" << std::endl;
        return;
    }
    if (g_micStatus == DEVICE_IDLE) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        g_adapter = nullptr;
    }
    g_spkStatus = DEVICE_IDLE;

    if (g_isInitRenderData) {
        for (auto &p : renderData) {
            delete[] p;
        }
        renderData.clear();
        g_isInitRenderData = false;
    }
    std::cout << "Close SPK device success." << std::endl;
}

static int32_t LoadMicDev(const std::string &devId)
{
    struct AudioAdapterDescriptor *dev = nullptr;
    for (int32_t index = 0; index < g_deviceNum; index++) {
        struct AudioAdapterDescriptor &desc = g_devices[index];
        if (desc.adapterName == devId) {
            dev = &desc;
            break;
        }
    }
    if (dev == nullptr) {
        std::cout << "Input device id is wrong." << std::endl;
        FindAudioDevice();
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    if (g_manager == nullptr) {
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    if (g_adapter == nullptr) {
        int32_t ret = g_manager->LoadAdapter(g_manager, dev, &g_adapter);
        if (ret != DH_SUCCESS || g_adapter == nullptr) {
            std::cout << "Load audio device failed, ret: " << ret << std::endl;
            return ERR_DH_AUDIO_HDF_FAIL;
        }
    }
    return DH_SUCCESS;
}

static void OpenMic(const std::string &devId)
{
    if (g_micStatus != DEVICE_IDLE) {
        std::cout << "Mic device is already opened." << std::endl;
        return;
    }
    if (LoadMicDev(devId) != DH_SUCCESS) {
        std::cout << "Load audio device failed." << std::endl;
        return;
    }

    AudioDeviceDescriptor captureDesc;
    captureDesc.pins = AudioPortPin::PIN_IN_MIC;
    captureDesc.desc = nullptr;
    AudioSampleAttributes captureAttr;
    captureAttr.type = AUDIO_IN_MEDIA;
    captureAttr.interleaved = CAPTURE_INTER_LEAVED;
    captureAttr.streamId = CAPTURE_STREAM_ID;
    captureAttr.channelCount = CAPTURE_CHANNEL_MASK;
    captureAttr.sampleRate = AUDIO_SAMPLE_RATE;
    captureAttr.format = AudioFormat::AUDIO_FORMAT_TYPE_PCM_16_BIT;
    int32_t ret = g_adapter->CreateCapture(g_adapter, &captureDesc, &captureAttr, &g_capture);
    if (ret != DH_SUCCESS || g_capture == nullptr) {
        std::cout << "Open MIC device failed." << std::endl;
        return;
    }
    g_micStatus = DEVICE_OPEN;
    std::cout << "Open MIC device success." << std::endl;
}

static void ReadStreamWait(const int64_t &startTime)
{
    int64_t endTime = GetNowTimeUs();
    int32_t passTime = endTime - startTime;

    if (passTime > AUDIO_FRAME_TIME_INTERFAL_DEFAULT) {
        return;
    }
    int64_t remainTime = AUDIO_FRAME_TIME_INTERFAL_DEFAULT - passTime;
    std::this_thread::sleep_for(std::chrono::microseconds(remainTime));
}

static void Capture()
{
    if (g_capture == nullptr) {
        std::cout << "MIC device is null." << std::endl;
        return;
    }
    if (pthread_setname_np(pthread_self(), CAPTURE_THREAD) != DH_SUCCESS) {
        std::cout << "Capture thread setname failed." << std::endl;
    }
    std::cout << "Capturing thread started." << std::endl;
    g_capture->control.Start((AudioHandle)g_capture);
    g_micStatus = DEVICE_START;

    uint64_t size = 0;
    while (g_micStatus == DEVICE_START) {
        uint8_t *data[RENDER_FRAME_SIZE];
        int64_t startTime = GetNowTimeUs();
        int32_t ret = g_capture->CaptureFrame(g_capture, data, RENDER_FRAME_SIZE, &size);
        if (ret != DH_SUCCESS) {
            std::cout << "CaptureFrame failed, ret: " << ret << std::endl;
            return;
        }
        int32_t writeCnt = fwrite(data, 1, RENDER_FRAME_SIZE, g_micFile);
        if (writeCnt != RENDER_FRAME_SIZE) {
            std::cout << "fwrite data failed." << std::endl;
        }
        g_micFrameNum++;
        ReadStreamWait(startTime);
    }
    std::cout << "Capturing thread stopped." << std::endl;
}

static void StartCapture()
{
    if (g_micStatus == DEVICE_IDLE) {
        std::cout << "Mic device is not opened, start capture failed." << std::endl;
        return;
    }

    if (g_micStatus == DEVICE_OPEN) {
        g_micFile = fopen(MIC_FILE_PATH, "ab+");
        if (g_micFile == nullptr) {
            std::cout << "Open pcm file failed." << std::endl;
            return;
        }
        g_capingThread = std::thread(Capture);
        return;
    }

    if (g_micStatus == DEVICE_START) {
        std::cout << "Mic device is already started." << std::endl;
        return;
    }

    if (g_micStatus == DEVICE_STOP) {
        g_capingThread = std::thread(Capture);
    }
}

static void StopCapture()
{
    if (g_capture == nullptr) {
        std::cout << "MIC device is null." << std::endl;
        return;
    }
    if (g_micStatus == DEVICE_IDLE) {
        std::cout << "Mic device is not opened." << std::endl;
        return;
    }
    if (g_micStatus == DEVICE_OPEN) {
        std::cout << "Mic device is not started." << std::endl;
        return;
    }
    if (g_micStatus == DEVICE_STOP) {
        std::cout << "Mic device is already started." << std::endl;
        return;
    }
    g_micStatus = DEVICE_STOP;
    if (g_capingThread.joinable()) {
        g_capingThread.join();
    }
    g_capture->control.Stop((AudioHandle)g_capture);
}

static void CloseMic()
{
    if (g_micStatus == DEVICE_IDLE) {
        std::cout << "Mic device is not opened." << std::endl;
        return;
    }

    if (g_micStatus == DEVICE_START) {
        StopCapture();
    }

    int32_t ret = g_adapter->DestroyCapture(g_adapter, g_capture);
    if (ret != DH_SUCCESS) {
        std::cout << "Close mic failed." << std::endl;
        return;
    }
    if (g_spkStatus == DEVICE_IDLE) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        g_adapter = nullptr;
    }
    if (g_micFile != nullptr) {
        fclose(g_micFile);
        g_micFile = nullptr;
    }
    g_micStatus = DEVICE_IDLE;
    std::cout << "Close MIC device success." << std::endl;
}

static void SetVolume()
{
    if (g_spkStatus == DEVICE_IDLE) {
        std::cout << "Speaker is not opened, can not set volume." << std::endl;
        return;
    }
    std::cout << "Please input volum to set [0,15]." << std::endl;
    int32_t volInt = GetUserInput();
    if (volInt < VOLUME_MIN || volInt > VOLUME_MAX) {
        std::cout << "Volume is invalid." << std::endl;
        return;
    }
    std::cout << "Set volume: " << volInt << std::endl;
    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=1;AUDIO_VOLUME_TYPE=1;";
    int32_t ret = g_adapter->SetExtraParams(g_adapter, key, condition.c_str(), vol.c_str());
    if (ret != DH_SUCCESS) {
        std::cout << "Set volume failed" << std::endl;
    }
}

static void GetVolume()
{
    if (g_spkStatus == DEVICE_IDLE) {
        std::cout << "Speaker is not opened, can not get volume." << std::endl;
        return;
    }
    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=1;AUDIO_VOLUME_TYPE=1;";
    char vol[VOLUME_BIT];
    int32_t ret = g_adapter->GetExtraParams(g_adapter, key, condition.c_str(), vol, VOLUME_BIT);
    if (ret != DH_SUCCESS) {
        std::cout << "Get Volume failed." << std::endl;
        return;
    }
    std::cout << "Get volume success. volume: " << vol <<std::endl;
}

static void HandleAudioEvent(const int32_t cmd)
{
    switch (cmd) {
        case CMD_FIND:
            FindAudioDevice();
            break;
        case CMD_OPEN_SPK:
            OpenSpk(g_devId);
            break;
        case CMD_START_SPK:
            StartRender();
            break;
        case CMD_STOP_SPK:
            StopRender();
            break;
        case CMD_CLOSE_SPK:
            CloseSpk();
            break;
        case CMD_OPEN_MIC:
            OpenMic(g_devId);
            break;
        case CMD_START_MIC:
            StartCapture();
            break;
        case CMD_STOP_MIC:
            StopCapture();
            break;
        case CMD_CLOSE_MIC:
            CloseMic();
            break;
        case CMD_SET_VOL:
            SetVolume();
            break;
        case CMD_GET_VOL:
            GetVolume();
            break;
        default:
            std::cout << "Unkown opeartion." << std::endl;
            break;
    }
}

static void PrintInteractiveUsage()
{
    std::cout << std::endl << "=============== InteractiveRunTestSelect ================" << std::endl;
    std::cout << "You can respond to instructions for corresponding option:" << std::endl;
    std::cout <<  "\t enter 1 to open spk. " << std::endl;
    std::cout <<  "\t enter 2 to close spk. " << std::endl;
    std::cout <<  "\t enter 3 to start play. " << std::endl;
    std::cout <<  "\t enter 4 to stop play. " << std::endl;
    std::cout <<  "\t enter 5 to open mic. " << std::endl;
    std::cout <<  "\t enter 6 to clsoe mic. " << std::endl;
    std::cout <<  "\t enter 7 to start record. " << std::endl;
    std::cout <<  "\t enter 8 to stop record. " << std::endl;
    std::cout <<  "\t enter 9 to manullt find device. " << std::endl;
    std::cout <<  "\t enter 11 to set volume. " << std::endl;
    std::cout <<  "\t enter 12 to get volume. " << std::endl;
    std::cout <<  "\t enter 0 to exit. " << std::endl;
}
}

int main(int argc, char *argv[])
{
    if (InitTestDemo() != DH_SUCCESS) {
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    while (true) {
        PrintInteractiveUsage();
        int32_t cmd = GetUserInput();
        if (cmd == CMD_QUIT) {
            CloseSpk();
            CloseMic();
            break;
        }
        HandleAudioEvent(cmd);
    }
    return 0;
}