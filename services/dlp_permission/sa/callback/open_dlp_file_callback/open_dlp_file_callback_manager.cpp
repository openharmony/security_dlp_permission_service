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

#include "open_dlp_file_callback_manager.h"

#include <datetime_ex.h>
#include <future>
#include <pthread.h>
#include <thread>

#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "open_dlp_file_callback_info.h"
#include "open_dlp_file_callback_death_recipient.h"
#include "i_open_dlp_file_callback.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "OpenDlpFileCallbackManager"};
static const uint32_t MAX_CALLBACK_SIZE = 100;
static const uint32_t MAX_CALLBACKS = 100;
const char THREAD_EVENT[] = "openDlpFile";
}  // namespace

OpenDlpFileCallbackManager& OpenDlpFileCallbackManager::GetInstance()
{
    static OpenDlpFileCallbackManager instance;
    return instance;
}

OpenDlpFileCallbackManager::OpenDlpFileCallbackManager()
    : callbackDeathRecipient_(
          sptr<IRemoteObject::DeathRecipient>(new(std::nothrow) OpenDlpFileCallbackDeathRecipient()))
{}

OpenDlpFileCallbackManager::~OpenDlpFileCallbackManager()
{}

int32_t OpenDlpFileCallbackManager::AddCallback(
    int32_t pid, int32_t userId, const std::string& bundleName, const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "input is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (openDlpFileCallbackMap_.size() >= MAX_CALLBACK_SIZE) {
        DLP_LOG_ERROR(LABEL, "callback size has reached limitation");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    callback->AddDeathRecipient(callbackDeathRecipient_);
    auto goalCallback = openDlpFileCallbackMap_.find(pid);
    if (goalCallback != openDlpFileCallbackMap_.end()) {
        DLP_LOG_INFO(LABEL, "callbacks in %{public}d not empty", pid);
        auto &callbackList = goalCallback->second;
        if (callbackList.size() >= MAX_CALLBACKS) {
            DLP_LOG_ERROR(LABEL, "callbacks in %{public}d has reached limitation", pid);
            return DLP_SERVICE_ERROR_VALUE_INVALID;
        }
        bool findCallBack = std::any_of(callbackList.begin(), callbackList.end(),
            [callback](const auto& callbackRecord) { return callbackRecord.callbackObject == callback; });
        if (findCallBack) {
            DLP_LOG_ERROR(LABEL, "same callback already in %{public}d", pid);
            return DLP_OK;
        }
    }
    OpenDlpFileCallbackRecord recordInstance;
    recordInstance.callbackObject = callback;
    recordInstance.userId = userId;
    recordInstance.bundleName = bundleName;
    openDlpFileCallbackMap_[pid].emplace_back(recordInstance);
    DLP_LOG_INFO(LABEL, "callback add in %{public}d", pid);
    return DLP_OK;
}

int32_t OpenDlpFileCallbackManager::RemoveCallback(const sptr<IRemoteObject>& callback)
{
    DLP_LOG_INFO(LABEL, "RemoveCallback by kill");
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "callback is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = openDlpFileCallbackMap_.begin(); it != openDlpFileCallbackMap_.end(); ++it) {
        auto &callbackList = it->second;
        auto callbackIter = callbackList.begin();
        while (callbackIter != callbackList.end()) {
            if (callbackIter->callbackObject != callback) {
                callbackIter++;
                continue;
            }
            DLP_LOG_INFO(LABEL, "find callback in %{public}d", it->first);
            if (callbackDeathRecipient_ != nullptr) {
                callback->RemoveDeathRecipient(callbackDeathRecipient_);
            }
            callbackList.erase(callbackIter);
            if (callbackList.empty()) {
                DLP_LOG_INFO(LABEL, "Remove empty callback list in %{public}d", it->first);
                openDlpFileCallbackMap_.erase(it);
            }
            return DLP_OK;
        }
    }
    DLP_LOG_INFO(LABEL, "Remove callback not found");
    return DLP_OK;
}

int32_t OpenDlpFileCallbackManager::RemoveCallback(int32_t pid, const sptr<IRemoteObject>& callback)
{
    DLP_LOG_INFO(LABEL, "RemoveCallback");
    if (pid == 0) {
        DLP_LOG_ERROR(LABEL, "pid == 0");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto goalCallback = openDlpFileCallbackMap_.find(pid);
    if (goalCallback == openDlpFileCallbackMap_.end()) {
        DLP_LOG_ERROR(LABEL, "can not find %{public}d's callback", pid);
        return DLP_CALLBACK_PARAM_INVALID;
    }
    auto &callbackList = goalCallback->second;
    auto callbackIter = callbackList.begin();
    while (callbackIter != callbackList.end()) {
        if (callbackIter->callbackObject != callback) {
            callbackIter++;
            continue;
        }
        DLP_LOG_INFO(LABEL, "find callback in %{public}d", pid);
        if ((callbackDeathRecipient_ != nullptr) && (callback != nullptr)) {
            callback->RemoveDeathRecipient(callbackDeathRecipient_);
        }
        callbackList.erase(callbackIter);
        if (callbackList.empty()) {
            DLP_LOG_INFO(LABEL, "Remove empty callback list in %{public}d", pid);
            openDlpFileCallbackMap_.erase(goalCallback);
        }
        return DLP_OK;
    }
    DLP_LOG_INFO(LABEL, "Remove callback not found");
    return DLP_OK;
}

bool OpenDlpFileCallbackManager::OnOpenDlpFile(
    sptr<IRemoteObject>& subscribeRecordPtr, const DlpSandboxInfo& dlpSandboxInfo)
{
    auto callback = iface_cast<IOpenDlpFileCallback>(subscribeRecordPtr);
    if (callback != nullptr) {
        DLP_LOG_INFO(LABEL, "callback excute");
        OpenDlpFileCallbackInfo resInfo;
        resInfo.uri = dlpSandboxInfo.uri;
        resInfo.timeStamp = dlpSandboxInfo.timeStamp;
        callback->OnOpenDlpFile(resInfo);
    }
    return false;
}

void OpenDlpFileCallbackManager::ExecuteCallbackAsync(const DlpSandboxInfo& dlpSandboxInfo)
{
    std::vector<sptr<IRemoteObject>> callbackList;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& iter : openDlpFileCallbackMap_) {
            auto list = iter.second;
            for (auto& it : list) {
                if ((it.bundleName == dlpSandboxInfo.bundleName) && (it.userId == dlpSandboxInfo.userId)) {
                    callbackList.emplace_back(it.callbackObject);
                }
            }
        }
    }
    if (callbackList.empty()) {
        DLP_LOG_INFO(LABEL, "no callback to execution");
        return;
    }
    uint32_t sendCnt = 0;
    for (auto& iter : callbackList) {
        auto task = std::bind(&OpenDlpFileCallbackManager::OnOpenDlpFile, this, iter, dlpSandboxInfo);
        std::thread taskThread(task);
        pthread_setname_np(taskThread.native_handle(), THREAD_EVENT);
        taskThread.detach();
        ++sendCnt;
    }
    DLP_LOG_INFO(LABEL, "callback execution is complete, total %{public}d", sendCnt);
}

bool OpenDlpFileCallbackManager::IsCallbackEmpty()
{
    std::lock_guard<std::mutex> lock(mutex_);
    size_t num = openDlpFileCallbackMap_.size();
    DLP_LOG_INFO(LABEL, "current callback %{public}zu", num);
    return num == 0;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
