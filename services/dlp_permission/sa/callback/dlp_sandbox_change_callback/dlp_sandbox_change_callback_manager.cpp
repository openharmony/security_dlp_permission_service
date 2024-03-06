/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_sandbox_change_callback_manager.h"

#include <datetime_ex.h>
#include <future>
#include <pthread.h>
#include <thread>

#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_callback_info.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "i_dlp_sandbox_state_change_callback.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpSandboxChangeCallbackManager"};
static const time_t MAX_TIMEOUT_SEC = 30;
static const uint32_t MAX_CALLBACK_SIZE = 1024;
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
}

DlpSandboxChangeCallbackManager &DlpSandboxChangeCallbackManager::GetInstance()
{
    static DlpSandboxChangeCallbackManager instance;
    return instance;
}

DlpSandboxChangeCallbackManager::DlpSandboxChangeCallbackManager()
    : callbackDeathRecipient_(
    sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) DlpSandboxChangeCallbackDeathRecipient()))
{}

DlpSandboxChangeCallbackManager::~DlpSandboxChangeCallbackManager() {}

int32_t DlpSandboxChangeCallbackManager::AddCallback(int32_t pid, const sptr<IRemoteObject> &callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "input is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackInfoMap_.size() >= MAX_CALLBACK_SIZE) {
        DLP_LOG_ERROR(LABEL, "callback size has reached limitation");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    callback->AddDeathRecipient(callbackDeathRecipient_);
    auto goalCallback = callbackInfoMap_.find(pid);
    if (goalCallback != callbackInfoMap_.end()) {
        DLP_LOG_ERROR(LABEL, "already has the same callback");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    DlpSandboxChangeCallbackRecord recordInstance;
    recordInstance.callbackObject_ = callback;
    recordInstance.pid = pid;
    callbackInfoMap_[pid] = recordInstance;
    DLP_LOG_INFO(LABEL, "recordInstance is added");
    return DLP_OK;
}

int32_t DlpSandboxChangeCallbackManager::RemoveCallback(const sptr<IRemoteObject> &callback)
{
    DLP_LOG_INFO(LABEL, "enter RemoveCallback by kill");
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "callback is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = callbackInfoMap_.begin(); it != callbackInfoMap_.end(); ++it) {
        if (callback == it->second.callbackObject_) {
            DLP_LOG_INFO(LABEL, "find callback");
            if (callbackDeathRecipient_ != nullptr) {
                callback->RemoveDeathRecipient(callbackDeathRecipient_);
            }
            it->second.callbackObject_ = nullptr;
            callbackInfoMap_.erase(it);
            DLP_LOG_INFO(LABEL, "callbackInfo RemoveCallback from DeathRecipient succuss");
            return DLP_OK;
        }
    }
    DLP_LOG_INFO(LABEL, "RemoveCallback from DeathRecipient can not find callbackInfo");
    return DLP_OK;
}

int32_t DlpSandboxChangeCallbackManager::RemoveCallback(int32_t pid, bool &result)
{
    DLP_LOG_INFO(LABEL, "enter RemoveCallback");
    if (pid == 0) {
        DLP_LOG_ERROR(LABEL, "pid == 0");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto goalCallback = callbackInfoMap_.find(pid);
    if (goalCallback == callbackInfoMap_.end()) {
        DLP_LOG_ERROR(LABEL, "can not find pid:%{public}d callback", pid);
        result = false;
        return DLP_CALLBACK_PARAM_INVALID;
    }
    if (callbackDeathRecipient_ != nullptr && goalCallback->second.callbackObject_ != nullptr) {
        goalCallback->second.callbackObject_->RemoveDeathRecipient(callbackDeathRecipient_);
    }
    goalCallback->second.callbackObject_ = nullptr;
    callbackInfoMap_.erase(goalCallback);
    result = true;
    DLP_LOG_INFO(LABEL, "callbackInfo RemoveCallback succuss");
    return DLP_OK;
}

void DlpSandboxChangeCallbackManager::ExecuteCallbackAsync(const DlpSandboxInfo &dlpSandboxInfo)
{
    std::map<int32_t, DlpSandboxChangeCallbackRecord>::iterator goalCallback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        goalCallback = callbackInfoMap_.find(dlpSandboxInfo.pid);
        if (goalCallback == callbackInfoMap_.end()) {
            DLP_LOG_ERROR(LABEL, "can not find pid:%{public}d callback", dlpSandboxInfo.pid);
            return;
        }
    }
    auto callbackStart = [&goalCallback, &dlpSandboxInfo]() {
        std::string name = "DlpCallback";
        pthread_setname_np(pthread_self(), name.substr(0, MAX_PTHREAD_NAME_LEN).c_str());
        std::vector<sptr<IRemoteObject>> list;
        auto callback = iface_cast<IDlpSandboxStateChangeCallback>(goalCallback->second.callbackObject_);
        if (callback != nullptr) {
            DLP_LOG_INFO(LABEL, "callback excute");
            DlpSandboxCallbackInfo resInfo;
            resInfo.appIndex = dlpSandboxInfo.appIndex;
            resInfo.bundleName = dlpSandboxInfo.bundleName;
            callback->DlpSandboxStateChangeCallback(resInfo);
        }
    };
    DLP_LOG_INFO(LABEL, "Waiting for the callback execution complete...");
    std::packaged_task<void()> callbackTask(callbackStart);
    std::future<void> fut = callbackTask.get_future();
    std::make_unique<std::thread>(std::move(callbackTask))->detach();

    DLP_LOG_INFO(LABEL, "Waiting for the callback execution complete...");
    std::future_status status = fut.wait_for(std::chrono::seconds(MAX_TIMEOUT_SEC));
    if (status == std::future_status::timeout) {
        DLP_LOG_INFO(LABEL, "callbackTask callback execution timeout");
    }
    DLP_LOG_INFO(LABEL, "The callback execution is complete");
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
