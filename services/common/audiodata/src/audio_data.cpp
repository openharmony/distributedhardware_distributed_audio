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

#include "audio_data.h"
#include "daudio_errorcode.h"

namespace OHOS {
namespace DistributedHardware {
AudioData::AudioData(const size_t capacity)
{
    if (capacity != 0) {
        data_ = new (std::nothrow) uint8_t[capacity] {0};
        if (data_ != nullptr) {
            capacity_ = capacity;
            rangeLength_ = capacity;
        }
    }
}

size_t AudioData::Capacity() const
{
    return capacity_;
}

size_t AudioData::Size() const
{
    return rangeLength_;
}

uint8_t *AudioData::Data() const
{
    return data_ + rangeOffset_;
}

int32_t AudioData::SetRange(size_t offset, size_t size)
{
    if (!(offset <= capacity_) || !(offset + size <= capacity_)) {
        return ERR_DH_AUDIO_BAD_VALUE;
    }

    rangeOffset_ = offset;
    rangeLength_ = size;
    return DH_SUCCESS;
}

void AudioData::SetInt64(const string name, int64_t value)
{
    int64Map_[name] = value;
}

bool AudioData::FindInt32(const string &name, int32_t &value)
{
    if (int32Map_.count(name) != 0) {
        value = int32Map_[name];
        return true;
    } else {
        value = 0;
        return false;
    }
}

bool AudioData::FindInt64(const string &name, int64_t &value)
{
    if (int64Map_.count(name) != 0) {
        value = int64Map_[name];
        return true;
    } else {
        value = 0;
        return false;
    }
}

bool AudioData::FindString(const string &name, string &value)
{
    if (stringMap_.count(name) != 0) {
        value = stringMap_[name];
        return true;
    } else {
        value = "";
        return false;
    }
}

AudioData::~AudioData()
{
    if (data_ != nullptr) {
        delete[] data_;
        data_ = nullptr;
    }

    capacity_ = 0;
}
} // namespace DistributedHardware
} // namespace OHOS
