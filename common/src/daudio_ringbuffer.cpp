/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "daudio_ringbuffer.h"

#include <cstdint>
#include <securec.h>

#undef DH_LOG_TAG
#define DH_LOG_TAG "DaudioRingBuffer"

namespace OHOS {
namespace DistributedHardware {
DaudioRingBuffer::~DaudioRingBuffer()
{
    if (array_ != nullptr) {
        delete[] array_;
        array_ = nullptr;
    }
}

int32_t DaudioRingBuffer::RingBufferInit(uint8_t *&audioData)
{
    array_ = new (std::nothrow) uint8_t[RINGBUFFERLEN] {0};
    CHECK_AND_RETURN_RET_LOG(array_ == nullptr, ERR_DH_AUDIO_FAILED, "Buffer is malloced failed.");
    writePos_ = 0;
    readPos_ = 0;
    tag_ = 0;
    audioData = new (std::nothrow) uint8_t[DAUDIO_DATA_SIZE] {0};
    CHECK_AND_RETURN_RET_LOG(audioData == nullptr, ERR_DH_AUDIO_FAILED, "Audio data is malloced failed.");
    return DH_SUCCESS;
}

bool DaudioRingBuffer::GetFullState()
{
    if ((writePos_ == readPos_) && tag_ == 1) {
        return true;
    }
    return false;
}

bool DaudioRingBuffer::GetEmptyState()
{
    if ((writePos_ == readPos_) && tag_ == 0) {
        return true;
    }
    return false;
}

int32_t DaudioRingBuffer::RingBufferInsert(uint8_t *data, int32_t len)
{
    int32_t avaliable = RINGBUFFERLEN - writePos_;
    if (avaliable < len) {
        int32_t ret = RingBufferInsertOnce(data, avaliable);
        CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED,
            "write first once error. errorcode: %{public}d", ret);
        ret = RingBufferInsertOnce(data + avaliable, len - avaliable);
        CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED,
            "write next once error. errorcode: %{public}d", ret);
    } else {
        int32_t ret = RingBufferInsertOnce(data, len);
        CHECK_AND_RETURN_RET_LOG(ret != DH_SUCCESS, ERR_DH_AUDIO_FAILED,
            "write only once error. errorcode: %{public}d", ret);
    }
    return DH_SUCCESS;
}

int32_t DaudioRingBuffer::RingBufferInsertOnce(uint8_t *data, int32_t len)
{
    CHECK_AND_RETURN_RET_LOG(array_ == nullptr, ERR_DH_AUDIO_NULLPTR, "buffer is nullptr.");
    CHECK_AND_RETURN_RET_LOG(data == nullptr, ERR_DH_AUDIO_NULLPTR, "data is nullptr.");
    if (len < 0) {
        DHLOGE("len < 0 error.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    if (GetFullState()) {
        DHLOGE("buffer is full.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t avaliable = RINGBUFFERLEN - writePos_;
    if (avaliable < len) {
        DHLOGE("buffer is not avaliable. now avaliable: %{public}d.", avaliable);
        return ERR_DH_AUDIO_FAILED;
    }
    if (writePos_ >= RINGBUFFERLEN || len >= RINGBUFFERLEN) {
        DHLOGE("writePos_ or len is out of range.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = memcpy_s(array_ + writePos_, len, data, len);
    CHECK_AND_RETURN_RET_LOG(ret!= EOK, ERR_DH_AUDIO_FAILED, "memcpy_s error.");
    writePos_ = (writePos_ + len) % RINGBUFFERLEN;
    if (writePos_ == readPos_) {
        tag_ = 1;
    }
    return DH_SUCCESS;
}

int32_t DaudioRingBuffer::RingBufferGetData(uint8_t *data, int32_t len)
{
    CHECK_AND_RETURN_RET_LOG(array_ == nullptr, ERR_DH_AUDIO_NULLPTR, "buffer is nullptr.");
    CHECK_AND_RETURN_RET_LOG(data == nullptr, ERR_DH_AUDIO_NULLPTR, "data is nullptr.");
    int32_t avaliable = writePos_ - readPos_;
    if (avaliable >= len) {
        int32_t ret = RingBufferGetDataOnce(data, len);
        CHECK_AND_RETURN_RET_LOG(ret!= DH_SUCCESS, ERR_DH_AUDIO_FAILED, "read only once error");
    } else if (avaliable > 0) {
        DHLOGI("buffer is not enough. avaliable: %{public}d. len: %{public}d.", avaliable, len);
        return ERR_DH_AUDIO_FAILED;
    } else {
        int32_t firstReadLen = RINGBUFFERLEN - readPos_;
        if (firstReadLen >= len) {
            int32_t ret = RingBufferGetDataOnce(data, len);
            CHECK_AND_RETURN_RET_LOG(ret!= DH_SUCCESS, ERR_DH_AUDIO_FAILED, "read only once error");
        } else {
            int32_t ret = RingBufferGetDataOnce(data, firstReadLen);
            CHECK_AND_RETURN_RET_LOG(ret!= DH_SUCCESS, ERR_DH_AUDIO_FAILED, "read first once error");
            ret = RingBufferGetDataOnce(data + firstReadLen, len - firstReadLen);
            CHECK_AND_RETURN_RET_LOG(ret!= DH_SUCCESS, ERR_DH_AUDIO_FAILED, "read next once error");
        }
    }
    return DH_SUCCESS;
}

int32_t DaudioRingBuffer::RingBufferGetDataOnce(uint8_t *data, int32_t len)
{
    CHECK_AND_RETURN_RET_LOG(array_ == nullptr, ERR_DH_AUDIO_NULLPTR, "buffer is nullptr.");
    CHECK_AND_RETURN_RET_LOG(data == nullptr, ERR_DH_AUDIO_NULLPTR, "data is nullptr.");
    if (len < 0) {
        DHLOGE("len < 0 error.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    int32_t avaliable = writePos_ - readPos_;
    if (GetEmptyState()) {
        DHLOGE("buffer is empty.");
        return ERR_DH_AUDIO_FAILED;
    }
    if ((avaliable < len && avaliable > 0) ||
        (avaliable < 0 && RINGBUFFERLEN - readPos_ + writePos_ < len)) {
        DHLOGE("buffer is not enough.");
        return ERR_DH_AUDIO_FAILED;
    }
    if (readPos_ >= RINGBUFFERLEN || len >= RINGBUFFERLEN) {
        DHLOGE("readPos_ or len is out of range.");
        return ERR_DH_AUDIO_FAILED;
    }
    int32_t ret = memcpy_s(data, len, array_ + readPos_, len);
    CHECK_AND_RETURN_RET_LOG(ret != EOK, ERR_DH_AUDIO_FAILED, "memcpy_s error.");
    readPos_ = (readPos_ + len) % RINGBUFFERLEN;
    if (readPos_ == writePos_) {
        tag_ = 0;
    }
    return DH_SUCCESS;
}

bool DaudioRingBuffer::CanBufferReadLen(int32_t readLen)
{
    if (GetEmptyState()) {
        DHLOGD("buffer is empty.");
        return false;
    }
    int32_t aval = writePos_ - readPos_;
    if ((aval < readLen) && (aval > 0)) {
        DHLOGD("remain : %{public}d, but not enough readLen: %{public}d", aval, readLen);
        return false;
    } else if (aval <= 0) {
        int32_t avalRead = RINGBUFFERLEN - readPos_ + writePos_;
        if (avalRead < readLen) {
            DHLOGD("avalRead : %{public}d, but not enough readLen: %{public}d", avalRead, readLen);
            return false;
        }
    }
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS