/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "critical_handler.h"

#include "dlp_permission_log.h"
#include "mem_mgr_client.h"
#include "mem_mgr_proxy.h"
#include <system_ability_definition.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "CriticalHandler"};
}

static uint32_t g_count = 0;
static bool g_hasBackgroundTask = false;
static std::mutex g_criticalMutex;
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

void NotifyProcessIsActive(void)
{
    DLP_LOG_INFO(LABEL, "start to notify memmgr sa active");
    OHOS::Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 1, SA_ID_DLP_PERMISSION_SERVICE);
}

void NotifyProcessIsStop(void)
{
    DLP_LOG_INFO(LABEL, "start to notify memmgr sa stop");
    OHOS::Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 0, SA_ID_DLP_PERMISSION_SERVICE);
}

void IncreaseCriticalCnt(void)
{
    std::lock_guard<std::mutex> lock(g_criticalMutex);
    if (g_count == 0 && !g_hasBackgroundTask) {
        DLP_LOG_INFO(LABEL, "Try to set critical to true");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, SA_ID_DLP_PERMISSION_SERVICE);
    }
    g_count = g_count + 1;
    DLP_LOG_DEBUG(LABEL, "IncreaseCriticalCnt g_count %{public}d g_hasBackgroundTask %{public}d",
        g_count, g_hasBackgroundTask);
}

void DecreaseCriticalCnt(void)
{
    std::lock_guard<std::mutex> lock(g_criticalMutex);
    g_count = g_count > 0 ? g_count - 1 : g_count;
    DLP_LOG_DEBUG(LABEL, "DecreaseCriticalCnt g_count %{public}d g_hasBackgroundTask %{public}d",
        g_count, g_hasBackgroundTask);
    if (g_count == 0 && !g_hasBackgroundTask) {
        DLP_LOG_INFO(LABEL, "Try to set critical to false");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, SA_ID_DLP_PERMISSION_SERVICE);
    }
}

uint32_t GetCriticalCnt(void)
{
    std::lock_guard<std::mutex> lock(g_criticalMutex);
    return g_count;
}

void SetHasBackgroundTask(bool hasBackgroundTask)
{
    std::lock_guard<std::mutex> lock(g_criticalMutex);
    DLP_LOG_DEBUG(LABEL,
        "SetHasBackgroundTask g_count %{public}d g_hasBackgroundTask %{public}d hasBackgroundTask %{public}d",
        g_count, g_hasBackgroundTask, hasBackgroundTask);
    if (hasBackgroundTask == g_hasBackgroundTask) {
        return;
    }
    if (g_count == 0 && hasBackgroundTask) {
        DLP_LOG_INFO(LABEL, "Try to set critical to true");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, SA_ID_DLP_PERMISSION_SERVICE);
    }
    if (g_count == 0 && !hasBackgroundTask) {
        DLP_LOG_INFO(LABEL, "Try to set critical to false");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, SA_ID_DLP_PERMISSION_SERVICE);
    }
    g_hasBackgroundTask = hasBackgroundTask;
}

bool GetHasBackgroundTask(void)
{
    std::lock_guard<std::mutex> lock(g_criticalMutex);
    return g_hasBackgroundTask;
}
