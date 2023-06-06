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

#include "task_queue.h"

#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "TaskQueue"

namespace OHOS {
namespace DistributedHardware {
void TaskQueue::Start()
{
    DHLOGI("Start task queue.");
    taskQueueReady_ = true;
    isQuitTaskQueue_ = false;
    mainThreadLoop_ = std::thread(&TaskQueue::Run, this);
    if (pthread_setname_np(mainThreadLoop_.native_handle(), MAIN_THREAD_LOOP) != DH_SUCCESS) {
        DHLOGE("Main thread loop setname failed.");
    }
    while (!mainThreadLoop_.joinable()) {
    }
    DHLOGI("Start task queue success.");
}

void TaskQueue::Stop()
{
    DHLOGI("Stop task queue.");
    isQuitTaskQueue_ = true;
    if (mainThreadLoop_.joinable()) {
        mainThreadLoop_.join();
    }
    DHLOGI("Stop task queue success.");
}

void TaskQueue::Run()
{
    DHLOGI("Task queue running.");
    while (taskQueueReady_) {
        if (isQuitTaskQueue_ && taskQueue_.empty()) {
            DHLOGI("Task queue quit.");
            break;
        }
        std::shared_ptr<TaskImplInterface> task = nullptr;
        {
            std::unique_lock<std::mutex> lck(taskQueueMutex_);
            taskQueueCond_.wait_for(lck, std::chrono::milliseconds(TASK_WAIT_TIME),
                [this]() { return !taskQueue_.empty(); });
            if (taskQueue_.empty()) {
                continue;
            }
            Consume(task);
        }
        if (task == nullptr) {
            continue;
        }
        task->Run();
    }
}

void TaskQueue::Consume(std::shared_ptr<TaskImplInterface> &task)
{
    task = taskQueue_.front();
    taskQueue_.pop();
}

int32_t TaskQueue::Produce(std::shared_ptr<TaskImplInterface> &task)
{
    if (task == nullptr) {
        DHLOGE("The parameter is empty.");
        return ERR_DH_AUDIO_NULLPTR;
    }
    std::lock_guard<std::mutex> lck(taskQueueMutex_);
    if (taskQueue_.size() >= maxSize_) {
        DHLOGD("task queue is full, size: %zu", taskQueue_.size());
        return ERR_DH_AUDIO_SA_TASKQUEUE_FULL;
    }
    taskQueue_.push(task);
    taskQueueCond_.notify_one();
    return DH_SUCCESS;
}
} // DistributedHardware
} // OHOS
