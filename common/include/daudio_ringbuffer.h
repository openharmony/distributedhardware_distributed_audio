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

#ifndef OHOS_DAUDIO_RING_BUFFER_H
#define OHOS_DAUDIO_RING_BUFFER_H

#include <memory>
#include <string>

#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

namespace OHOS {
namespace DistributedHardware {
class DaudioRingBuffer {
public:
    DaudioRingBuffer() = default;
    ~DaudioRingBuffer();
    int32_t RingBufferInit(uint8_t *&data);
    int32_t RingBufferInsert(uint8_t *data, int32_t len);
    int32_t RingBufferGetData(uint8_t *data, int32_t len);
    bool CanBufferReadLen(int32_t readLen);

private:
    bool GetFullState();
    bool GetEmptyState();
    int32_t RingBufferInsertOnce(uint8_t *data, int32_t len);
    int32_t RingBufferGetDataOnce(uint8_t *data, int32_t len);

private:
    const int32_t RINGBUFFERLEN = 40960;
    const int32_t DAUDIO_DATA_SIZE = 4096;
    uint8_t *array_ = nullptr;
    int32_t writePos_ = 0;
    int32_t readPos_ = 0;
    int32_t tag_ = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DAUDIO_RING_BUFFER_H