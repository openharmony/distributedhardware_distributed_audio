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

#ifndef OHOS_AUDIO_IPC_COMMON_H
#define OHOS_AUDIO_IPC_COMMON_H

#include <string>

#include "daudio_errorcode.h"
#include "daudio_ipc_callback.h"
#include "daudio_ipc_callback_stub.h"
#include "daudio_source_handler.h"
#include "daudio_source_proxy.h"
#include "idaudio_ipc_callback.h"

namespace OHOS {
namespace DistributedHardware {
class RegisterCallbackTest : public RegisterCallback {
public:
    RegisterCallbackTest() = default;
    virtual ~RegisterCallbackTest() = default;

    int32_t OnRegisterResult(const std::string &uuid, const std::string &dhId, int32_t status,
        const std::string &data)
    {
        return DH_SUCCESS;
    }
};

class UnregisterCallbackTest : public UnregisterCallback {
public:
    UnregisterCallbackTest() = default;
    virtual ~UnregisterCallbackTest() = default;

    int32_t OnUnregisterResult(const std::string &uuid, const std::string &dhId, int32_t status,
        const std::string &data)
    {
        return DH_SUCCESS;
    }
};

class DistributedHardwareStateListenerTest : public DistributedHardwareStateListener {
public:
    DistributedHardwareStateListenerTest() = default;
    virtual ~DistributedHardwareStateListenerTest() = default;

    void OnStateChanged(const std::string &uuid, const std::string &dhId, const BusinessState state)
    {
        return;
    }
};

class DataSyncTriggerListenerTest : public DataSyncTriggerListener {
public:
    DataSyncTriggerListenerTest() = default;
    virtual ~DataSyncTriggerListenerTest() = default;

    void OnDataSyncTrigger(const std::string &uuid)
    {
        return;
    }
};

class MockIDAudioSource : public IDAudioSource {
public:
    ~MockIDAudioSource() = default;

    int32_t InitSource(const std::string &params, const sptr<IDAudioIpcCallback> &callback)
    {
        return DH_SUCCESS;
    }

    int32_t ReleaseSource()
    {
        return DH_SUCCESS;
    }

    int32_t RegisterDistributedHardware(const std::string &devId, const std::string &dhId, const EnableParam &param,
        const std::string &reqId)
    {
        return DH_SUCCESS;
    }

    int32_t UnregisterDistributedHardware(const std::string &devId, const std::string &dhId, const std::string &reqId)
    {
        return DH_SUCCESS;
    }

    int32_t ConfigDistributedHardware(const std::string &devId, const std::string &dhId, const std::string &key,
        const std::string &value)
    {
        return DH_SUCCESS;
    }

    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }

    void DAudioNotify(const std::string &devId, const std::string &dhId, const int32_t eventType,
        const std::string &eventContent) {}
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_AUDIO_IPC_COMMON_H