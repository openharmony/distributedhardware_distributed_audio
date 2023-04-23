/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

static const std::string SERVER_FIFO = "/data/seqnum_sv";
static const std::string CLIENT_FIFO_TEMPLATE = "/data/seqnum_cl.%ld";
const size_t CLIENT_FIFO_NAME_LEN = (sizeof(CLIENT_FIFO_TEMPLATE) + 20);

struct Request {
    pid_t pid;
    int commandNum;
    char reqString[70];
    int seqLen;
};

struct Response {
    int seqNum;
    char resString[CMD_EXECUTING_RETURN_LENGHT_MAX];
};

using namespace OHOS::DistributedHardware;
static AudioManager *g_manager = nullptr;
static AudioAdapter *g_adapter = nullptr;
static AudioRender *g_render = nullptr;
static AudioCapture *g_capture = nullptr;
static AudioAdapterDescriptor *g_devices = nullptr;

static constexpr const char* PLAY_THREAD = "playThread";
static constexpr const char* CAPTURE_THREAD = "captureThread";

int32_t g_deviceNum = 0;
int32_t g_frameNum = 0;
int32_t g_frameIndex = 0;
int32_t g_micFrameNum = 0;
bool g_isInitRenderData = false;
std::vector<uint8_t*> renderData;

static DeviceStatus g_spkStatus = DEVICE_IDLE;
static DeviceStatus g_micStatus = DEVICE_IDLE;

std::thread g_palyingThread;
std::thread g_capingThread;
FILE *g_micFile = nullptr;

static std::string CloseSpk();
static std::string CloseMic();

int64_t GetNowTimeUs()
{
    std::chrono::microseconds nowUs =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
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
        std::cout << "Distributed audio manager is null, quit!" << std::endl;
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    std::cout << "Load audio manager success." << std::endl;
    return DH_SUCCESS;
}

static std::string FindAudioDevice()
{
    if (g_manager == nullptr) {
        return "false";
    }
    int32_t ret = g_manager->GetAllAdapters(g_manager, &g_devices, &g_deviceNum);
    if (ret != DH_SUCCESS) {
        std::cout << "Get audio devices failed!";
        return "false";
    }
    std::string res = "true;";
    std::cout << "Get audio devices success, adapter size: " << g_deviceNum << std::endl;
    for (int32_t index = 0; index < g_deviceNum; index++) {
        const AudioAdapterDescriptor &desc = g_devices[index];
        std::cout << "Device[" << index << "] ID: " << desc.adapterName << std::endl;
        res = res + desc.adapterName;
        if (index != g_deviceNum - 1) {
            res = res + ";";
        }
        std::cout << "pin list: ";
        for (uint32_t i = 0; i < desc.portNum; i++) {
            std::cout << desc.ports[i].portId << ", ";
        }
        std::cout << std::endl;
    }
    return res;
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

static int32_t ParamEventCallback(enum AudioExtParamKey key, const char *condition, const char *value, void *reserved,
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
    std::cout << "Open SPK device , device Id:" << devId << std::endl;

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
    std::cout << "Load audio device success." << std::endl;
    return DH_SUCCESS;
}

static std::string OpenSpk(const std::string &devId)
{
    if (g_spkStatus != DEVICE_IDLE) {
        std::cout << "Speaker device is already opened." << std::endl;
        return "true";
    }
    if (LoadSpkDev(devId) != DH_SUCCESS) {
        return "false";
    }
    ParamCallback callback = ParamEventCallback;
    int32_t ret = g_adapter->RegExtraParamObserver(g_adapter, callback, nullptr);
    if (ret != DH_SUCCESS) {
        std::cout << "Register observer failed, ret: " << ret << std::endl;
        return "false";
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
        return "false";
    }
    g_spkStatus = DEVICE_OPEN;
    std::cout << "Open SPK device success." << std::endl;
    return "true";
}

void WriteStreamWait(const int64_t &startTime)
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

static std::string StartRender()
{
    if (g_spkStatus == DEVICE_IDLE) {
        return "Speaker device is not opened, start render failed.";
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
        g_palyingThread = std::thread(Play);
        return "true";
    }
    if (g_spkStatus == DEVICE_START) {
        return "Speaker device is started.";
    }
    if (g_spkStatus == DEVICE_STOP) {
        g_palyingThread = std::thread(Play);
    }
    return "true";
}

static std::string StopRender()
{
    if (g_render == nullptr) {
        return "SPK device is null.";
    }

    if (g_spkStatus == DEVICE_IDLE) {
        return "Speaker device is not opened.";
    }

    if (g_spkStatus == DEVICE_OPEN) {
        return "Speaker device is not started.";
    }

    if (g_spkStatus == DEVICE_STOP) {
        return "Speaker device is already stoped.";
    }

    g_spkStatus = DEVICE_STOP;
    if (g_palyingThread.joinable()) {
        g_palyingThread.join();
    }
    g_render->control.Stop((AudioHandle)g_render);
    return "true";
}

static std::string CloseSpk()
{
    if (g_spkStatus == DEVICE_IDLE) {
        return "Speaker device is not opened.";
    }

    if (g_spkStatus == DEVICE_START) {
        StopRender();
    }

    int32_t ret = g_adapter->DestroyRender(g_adapter, g_render);
    if (ret != DH_SUCCESS) {
        return "Close speaker failed";
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
    return "true";
}

static int32_t LoadMicDev(const std::string &devId)
{
    std::cout << "Open MIC device ,input device Id:" << devId << std::endl;

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
    std::cout << "Load audio device success." << std::endl;
    return DH_SUCCESS;
}

static std::string OpenMic(const std::string &devId)
{
    if (g_micStatus != DEVICE_IDLE) {
        return "Mic device is already opened.";
    }
    if (LoadMicDev(devId) != DH_SUCCESS) {
        return "Load audio device failed.";
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
        return "Open MIC device failed.";
    }
    g_micStatus = DEVICE_OPEN;
    return "true";
}

void ReadStreamWait(const int64_t &startTime)
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
        fwrite(data, 1, RENDER_FRAME_SIZE, g_micFile);
        g_micFrameNum++;
        ReadStreamWait(startTime);
    }
    std::cout << "Capturing thread stopped." << std::endl;
}

static std::string StartCapture()
{
    if (g_micStatus == DEVICE_IDLE) {
        return "Mic device is not opened, start capture failed.";
    }

    if (g_micStatus == DEVICE_OPEN) {
        g_micFile = fopen(MIC_FILE_PATH, "ab+");
        if (g_micFile == nullptr) {
            return "Open pcm file failed.";
        }
        g_capingThread = std::thread(Capture);
        return "true";
    }

    if (g_micStatus == DEVICE_START) {
        return "Mic device is already started.";
    }

    if (g_micStatus == DEVICE_STOP) {
        g_capingThread = std::thread(Capture);
    }
    return "true";
}

static std::string StopCapture()
{
    if (g_capture == nullptr) {
        return "MIC device is null.";
    }

    if (g_micStatus == DEVICE_IDLE) {
        return "Mic device is not opened.";
    }

    if (g_micStatus == DEVICE_OPEN) {
        return "Mic device is not started.";
    }

    if (g_micStatus == DEVICE_STOP) {
        return "Mic device is already started.";
    }

    g_micStatus = DEVICE_STOP;
    if (g_capingThread.joinable()) {
        g_capingThread.join();
    }
    g_capture->control.Stop((AudioHandle)g_capture);
    return "true";
}

static std::string CloseMic()
{
    if (g_micStatus == DEVICE_IDLE) {
        return "Mic device is not opened.";
    }

    if (g_micStatus == DEVICE_START) {
        StopCapture();
    }

    int32_t ret = g_adapter->DestroyCapture(g_adapter, g_capture);
    if (ret != DH_SUCCESS) {
        return "Close mic failed.";
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
    return "true";
}

static std::string SetVolume(std::string vol)
{
    if (g_spkStatus == DEVICE_IDLE) {
        return "Speaker is not opened, can not set volume.";
    }
    int32_t volInt = std::stoi(vol);
    if (volInt < VOLUME_MIN || volInt > VOLUME_MAX) {
        return "Volume is invalid";
    }
    enum AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=1;AUDIO_VOLUME_TYPE=1;";
    int32_t ret = g_adapter->SetExtraParams(g_adapter, key, condition.c_str(), vol.c_str());
    if (ret != DH_SUCCESS) {
        return "Set volume failed";
    }
    return "true";
}

static std::string GetVolume()
{
    if (g_spkStatus == DEVICE_IDLE) {
        return "Speaker is not opened, can not get volume.";
    }
    enum AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=1;AUDIO_VOLUME_TYPE=1;";
    char vol[VOLUME_BIT];
    int32_t ret = g_adapter->GetExtraParams(g_adapter, key, condition.c_str(), vol, VOLUME_BIT);
    if (ret != DH_SUCCESS) {
        return "Get Volume failed.";
    }
    std::string volStr(vol);
    return "true;"+volStr;
}

std::string SpkMicPlayEvent(const std::string &cmd)
{
    if (cmd == CMD_START_SPK || cmd == CMD_START_SPK_EXT) {
        return StartRender();
    }
    if (cmd == CMD_STOP_SPK || cmd == CMD_STOP_SPK_EXT) {
        return StopRender();
    }
    if (cmd == CMD_CLOSE_SPK || cmd == CMD_CLOSE_SPK_EXT) {
        return CloseSpk();
    }

    if (cmd == CMD_START_MIC || cmd == CMD_START_MIC_EXT) {
        return StartCapture();
    }
    if (cmd == CMD_STOP_MIC || cmd == CMD_STOP_MIC_EXT) {
        return StopCapture();
    }
    if (cmd == CMD_CLOSE_MIC || cmd == CMD_CLOSE_MIC_EXT) {
        return CloseMic();
    }
    return "";
}

void HandleAudioEvent(const std::string& cmd, std::string& cmdResString, struct Request& req)
{
    // find audio device
    if (cmd == CMD_FIND || cmd == CMD_FIND_EXT) {
        cmdResString = FindAudioDevice();
        return;
    }
    // Speaker open、play、pause and close
    if (cmd == CMD_OPEN_SPK || cmd == CMD_OPEN_SPK_EXT) {
        std::string reqdevId(req.reqString);
        cmdResString = OpenSpk(reqdevId);
        return;
    }
    cmdResString = SpkMicPlayEvent(cmd);

    // Mic open、record、pause and close
    if (cmd == CMD_OPEN_MIC || cmd == CMD_OPEN_MIC_EXT) {
        std::string reqdevId(req.reqString);
        cmdResString = OpenMic(reqdevId);
        return;
    }
    cmdResString = SpkMicPlayEvent(cmd);

    // set Speaker volume
    if (cmd == CMD_SET_VOL || cmd == CMD_SET_VOL_EXT) {
        std::string vol(req.reqString);
        cmdResString = SetVolume(vol);
        return;
    }
    // get Speaker volume
    if (cmd == CMD_GET_VOL || cmd == CMD_GET_VOL_EXT) {
        cmdResString = GetVolume();
    }
}

int GenerateFifoName(int& clientFd, char clientFifo[], struct Response& resp,
    std::string& cmdResString, struct Request& req)
{
    if (snprintf_s(clientFifo, CLIENT_FIFO_NAME_LEN, CLIENT_FIFO_NAME_LEN,
        CLIENT_FIFO_TEMPLATE.c_str(), (long)(req.pid)) < 0) {
        return -1;
    }
    clientFd = open(clientFifo, O_WRONLY);
    if (clientFd == -1) {
        perror("open");
        return -1;
    }
    if (strcpy_s(resp.resString, sizeof(resp.resString), cmdResString.c_str()) != 0) {
        return -1;
    }

    std::cout << "Write resString: " << resp.resString << std::endl;
    int writeLen = write(clientFd, &resp, sizeof(struct Response));
    std::cout << "Write Len: " << writeLen << "sizeof Response: " << sizeof(struct Response) << std::endl;
    if (writeLen != sizeof(struct Response)) {
        std::cout << "Write Len: " << writeLen << "sizeof Response: " << sizeof(struct Response) << std::endl;
    }
    if (close(clientFd) == -1) {
        perror("close");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int serverFd, dummyFd, clientFd, seqNum = 0;
    char clientFifo[CLIENT_FIFO_NAME_LEN];
    struct Request req;
    struct Response resp;

    if (InitTestDemo() != DH_SUCCESS) {
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    umask(0);
    if (mkfifo(SERVER_FIFO.c_str(), S_IRUSR | S_IWUSR | S_IWGRP) == -1 && errno != EEXIST) {
        perror("mkfifo");
    }
    serverFd = open(SERVER_FIFO.c_str(), O_RDONLY);
    if (serverFd == -1) {
        perror("open");
    }
    dummyFd = open(SERVER_FIFO.c_str(), O_WRONLY);
    if (dummyFd == -1) {
        perror("open");
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
    }
    bool testRunning = true;
    std::string cmd = "";
    while (testRunning) {
        int reLen = read(serverFd, &req, sizeof(struct Request));
        if (reLen != sizeof(struct Request)) {
            std::cout << "Read Len: " << reLen << "sizeof Request: " << sizeof(struct Request) << std::endl;
            continue;
        }

        std::cout << req.reqString << std::endl;
        std::cout << "Read Len: " << reLen << "sizeof Request: " << sizeof(struct Request) << std::endl;
        printf("receive msg from client pid:%d, commandNum: %d\n", req.pid, req.commandNum);
        cmd = std::to_string(req.commandNum);
        std::string cmdResString = "";

        // quit_test_demo
        if (cmd == CMD_QUIT || cmd == CMD_QUIT_EXT) {
            CloseSpk();
            CloseMic();
            testRunning = false;
            continue;
        }
        HandleAudioEvent(cmd, cmdResString, req);
        if (GenerateFifoName(clientFd, clientFifo, resp, cmdResString, req) != 0) {
            continue;
        }

        resp.seqNum = seqNum;
        seqNum += req.seqLen;           /* Update our sequence number */
    }
}
