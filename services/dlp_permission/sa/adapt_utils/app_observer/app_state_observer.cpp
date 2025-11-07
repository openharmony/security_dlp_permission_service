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

#include "app_state_observer.h"
#include <unistd.h>
#include "account_adapt.h"
#include "bundle_manager_adapter.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "bundle_mgr_client.h"
#include "dlp_sandbox_change_callback_manager.h"
#include "open_dlp_file_callback_manager.h"
#include "iservice_registry.h"
#include "idlp_permission_service.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using OHOS::AppExecFwk::AppProcessState;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppStateObserver"};
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
const std::string DLP_MANAGER_BUNDLE_NAME = "com.ohos.dlpmanager";
const std::string DLP_CREDMGR_BUNDLE_NAME = "com.huawei.hmos.dlpcredmgr";
const std::string DLP_CREDMGR_PROCESS_NAME = "com.huawei.hmos.dlpcredmgr:DlpCredActionExtAbility";
constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
}
AppStateObserver::AppStateObserver()
{}

AppStateObserver::~AppStateObserver()
{
    UninstallAllDlpSandbox();
}

void AppStateObserver::UninstallDlpSandbox(DlpSandboxInfo& appInfo)
{
    if (appInfo.appIndex <= 0) {  // never uninstall original hap
        return;
    }
    DLP_LOG_INFO(LABEL, "uninstall dlp sandbox %{public}s%{public}d, uid: %{public}d", appInfo.bundleName.c_str(),
        appInfo.appIndex, appInfo.uid);
    AppExecFwk::BundleMgrClient bundleMgrClient;
    bundleMgrClient.UninstallSandboxApp(appInfo.bundleName, appInfo.appIndex, appInfo.userId);
    RetentionFileManager::GetInstance().DelSandboxInfo(appInfo.tokenId);
}

void AppStateObserver::UninstallAllDlpSandboxForUser(int32_t userId)
{
    AppExecFwk::BundleMgrClient bundleMgrClient;
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end();) {
        auto& appInfo = iter->second;
        if (appInfo.userId != userId) {
            ++iter;
            continue;
        }
        if (RetentionFileManager::GetInstance().CanUninstall(appInfo.tokenId)) {
            UninstallDlpSandbox(appInfo);
        }
        EraseUidTokenIdMap(appInfo.tokenId);
        DLP_LOG_INFO(LABEL, "ExecuteCallbackAsync appInfo bundleName:%{public}s,appIndex:%{public}d,pid:%{public}d",
            appInfo.bundleName.c_str(), appInfo.appIndex, appInfo.pid);
        DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(appInfo);
        iter = sandboxInfo_.erase(iter);
    }
}

void AppStateObserver::UninstallAllDlpSandbox()
{
    DLP_LOG_INFO(LABEL, "service exit, uninstall all dlp sandbox");
    std::lock_guard<std::mutex> lock(userIdListLock_);
    for (const auto& iter : userIdList_) {
        UninstallAllDlpSandboxForUser(iter);
    }
    userIdList_.clear();
}

bool AppStateObserver::HasDlpSandboxForUser(int32_t userId)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end(); iter++) {
        auto& appInfo = iter->second;
        if (appInfo.userId == userId) {
            return true;
        }
    }
    return false;
}

void AppStateObserver::ExitSaAfterAllDlpManagerDie()
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    DLP_LOG_DEBUG(LABEL, "userIdList_ size:%{public}zu", userIdList_.size());
    if (userIdList_.empty() && CallbackListenerEmpty()) {
        DLP_LOG_INFO(LABEL, "all dlp manager app die, and callbacks are empty, start service exit");
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityMgr == nullptr) {
            DLP_LOG_ERROR(LABEL, "Failed to get SystemAbilityManager.");
            return;
        }
        int32_t ret = systemAbilityMgr->UnloadSystemAbility(SA_ID_DLP_PERMISSION_SERVICE);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Failed to UnloadSystemAbility service! errcode=%{public}d", ret);
            return;
        }
        DLP_LOG_INFO(LABEL, "UnloadSystemAbility successfully!");
    }
}

void AppStateObserver::EraseUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    auto iter = userIdList_.find(userId);
    if (iter != userIdList_.end()) {
        DLP_LOG_INFO(LABEL, "erase userId %{public}d", userId);
        userIdList_.erase(userId);
    }
}

void AppStateObserver::AddUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    if (userIdList_.count(userId) <= 0) {
        DLP_LOG_INFO(LABEL, "add userId %{public}d", userId);
        userIdList_.emplace(userId);
    }
    return;
}

bool AppStateObserver::GetSandboxInfo(int32_t uid, DlpSandboxInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    auto iter = sandboxInfo_.find(uid);
    if (iter != sandboxInfo_.end()) {
        appInfo = iter->second;
        return true;
    }
    return false;
}

void AppStateObserver::UpdatReadFlag(int32_t uid)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    auto iter = sandboxInfo_.find(uid);
    if (iter != sandboxInfo_.end()) {
        iter->second.hasRead = true;
    }
}

bool AppStateObserver::CheckSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (const auto& iter : sandboxInfo_) {
        if (iter.second.bundleName == bundleName && iter.second.appIndex == appIndex && iter.second.userId == userId) {
            return true;
        }
    }
    return false;
}

void AppStateObserver::EraseSandboxInfo(int32_t uid)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    auto iter = sandboxInfo_.find(uid);
    if (iter != sandboxInfo_.end()) {
        DLP_LOG_INFO(LABEL, "sandbox app %{public}s%{public}d info delete success, uid: %{public}d",
            iter->second.bundleName.c_str(), iter->second.appIndex, iter->second.uid);
        sandboxInfo_.erase(iter);
    }
}

void AppStateObserver::AddSandboxInfo(const DlpSandboxInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    if (sandboxInfo_.count(appInfo.uid) > 0) {
        DLP_LOG_ERROR(LABEL, "sandbox app %{public}s%{public}d is already insert, ignore it",
            appInfo.bundleName.c_str(), appInfo.appIndex);
    } else {
        sandboxInfo_[appInfo.uid] = appInfo;
        DLP_LOG_INFO(LABEL, "sandbox app %{public}s%{public}d info insert success, uid: %{public}d",
            appInfo.bundleName.c_str(), appInfo.appIndex, appInfo.uid);
    }
    return;
}

void AppStateObserver::AddDlpSandboxInfo(const DlpSandboxInfo& appInfo)
{
    if (appInfo.bundleName.empty() || appInfo.tokenId <= 0 || appInfo.appIndex <= 0) {
        DLP_LOG_ERROR(LABEL, "Param is error");
        return;
    }
    int32_t userId;
    if (GetUserIdFromUid(appInfo.uid, &userId) != 0) {
        DLP_LOG_WARN(LABEL, "has uid:%{public}d", appInfo.uid);
        return;
    }
    AddUserId(userId);
    AddSandboxInfo(appInfo);
    AddUidWithTokenId(appInfo.tokenId, appInfo.uid);
    RetentionInfo retentionInfo = {
        .appIndex = appInfo.appIndex,
        .tokenId = appInfo.tokenId,
        .bundleName = appInfo.bundleName,
        .dlpFileAccess = appInfo.dlpFileAccess,
        .userId = appInfo.userId,
        .isReadOnce = appInfo.isReadOnce
    };
    RetentionFileManager::GetInstance().AddSandboxInfo(retentionInfo);
    OpenDlpFileCallbackManager::GetInstance().ExecuteCallbackAsync(appInfo);
    return;
}

void AppStateObserver::SetAppProxy(const sptr<AppExecFwk::AppMgrProxy>& appProxy)
{
    appProxy_ = appProxy;
}

bool AppStateObserver::GetRunningProcessesInfo(std::vector<RunningProcessInfo>& infoVec)
{
    if (appProxy_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "AppProxy_ is nullptr");
        return false;
    }
    int32_t ret = appProxy_->GetAllRunningProcesses(infoVec);
    if (ret != ERR_OK) {
        DLP_LOG_ERROR(LABEL, "GetAllRunningProcesses failed, errorCode=%{public}d", ret);
        return false;
    }
    return true;
}

bool AppStateObserver::GetOpeningSandboxInfo(const std::string& bundleName, const std::string& uri,
    int32_t userId, SandboxInfo& sandboxInfo)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end(); iter++) {
        DlpSandboxInfo appInfo = iter->second;
        if (appInfo.userId != userId || appInfo.bundleName != bundleName || appInfo.uri != uri) {
            continue;
        }
        std::vector<RunningProcessInfo> infoVec;
        (void)GetRunningProcessesInfo(infoVec);
        for (auto it = infoVec.begin(); it != infoVec.end(); it++) {
            if (it->uid_ != appInfo.uid) {
                continue;
            }
            if (it->state_ == AppProcessState::APP_STATE_END || it->state_ == AppProcessState::APP_STATE_TERMINATED) {
                DLP_LOG_INFO(LABEL, "APP is dead, appName:%{public}s, state=%{public}d", it->processName_.c_str(),
                    it->state_);
                return false;
            }
            DLP_LOG_INFO(LABEL, "APP is running, appName:%{public}s, state=%{public}d", it->processName_.c_str(),
                it->state_);
            sandboxInfo.appIndex = appInfo.appIndex;
            sandboxInfo.tokenId = appInfo.tokenId;
            return true;
        }
        break;
    }
    return false;
}

bool AppStateObserver::CanUninstallByGid(DlpSandboxInfo& appInfo, const AppExecFwk::ProcessData& processData)
{
    std::vector<RunningProcessInfo> infoVec;
    (void)GetRunningProcessesInfo(infoVec);
    for (auto it = infoVec.begin(); it != infoVec.end(); it++) {
        if (it->uid_ != appInfo.uid || it->bundleNames[0] != appInfo.bundleName) {
            continue;
        }
        if (it->state_ == AppProcessState::APP_STATE_END || it->state_ == AppProcessState::APP_STATE_TERMINATED) {
            DLP_LOG_INFO(LABEL, "APP is dead, appName:%{public}s, state=%{public}d", it->processName_.c_str(),
                it->state_);
        }
        if (it->pid_ != processData.pid) {
            DLP_LOG_INFO(LABEL,
                "APP is running, appName:%{public}s, state=%{public}d, dead pid:%{public}d, running pid:%{public}d",
                it->processName_.c_str(), it->state_, processData.pid, it->pid_);
            return false;
        }
    }
    return true;
}

void AppStateObserver::GetOpeningReadOnlySandbox(const std::string& bundleName, int32_t userId, int32_t& appIndex)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end(); iter++) {
        DlpSandboxInfo appInfo = iter->second;
        if (appInfo.userId == userId && appInfo.bundleName == bundleName &&
            appInfo.dlpFileAccess == DLPFileAccess::READ_ONLY) {
            appIndex = appInfo.appIndex;
            return;
        }
    }
    appIndex = -1;
    return;
}

uint32_t AppStateObserver::EraseDlpSandboxInfo(int uid)
{
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(uid, appInfo)) {
        return 0;
    }

    EraseSandboxInfo(appInfo.uid);
    EraseUidTokenIdMap(appInfo.tokenId);
    return appInfo.tokenId;
}

void AppStateObserver::OnDlpmanagerDied(const AppExecFwk::ProcessData& processData)
{
    int32_t userId;
    if (GetUserIdFromUid(processData.uid, &userId) != 0) {
        return;
    }
    DLP_LOG_INFO(LABEL, "%{public}s in userId %{public}d is died", processData.bundleName.c_str(), userId);
    UninstallAllDlpSandboxForUser(userId);
    EraseUserId(userId);
    ExitSaAfterAllDlpManagerDie();
}


void AppStateObserver::OnProcessDied(const AppExecFwk::ProcessData& processData)
{
    DLP_LOG_DEBUG(LABEL, "%{public}s is died, uid: %{public}d", processData.bundleName.c_str(), processData.uid);

    // current died process is dlpmanager
    if (processData.bundleName == DLP_MANAGER_BUNDLE_NAME &&
        processData.processName == DLP_MANAGER_BUNDLE_NAME &&
        BundleManagerAdapter::GetInstance().CheckHapPermission(processData.bundleName, PERMISSION_ACCESS_DLP_FILE)) {
        OnDlpmanagerDied(processData);
        return;
    }
    // current died process is dlpcredmgr
    if (processData.bundleName == DLP_CREDMGR_BUNDLE_NAME &&
        processData.processName.size() >= DLP_CREDMGR_PROCESS_NAME.size() &&
        processData.processName.find(DLP_CREDMGR_PROCESS_NAME) == 0) {
        int32_t userId;
        if (GetUserIdFromUid(processData.uid, &userId) != 0) {
            return;
        }
        if (!HasDlpSandboxForUser(userId)) {
            ExitSaAfterAllDlpManagerDie();
        }
    }
    // if current died process is a listener
    if (RemoveCallbackListener(processData.pid)) {
        ExitSaAfterAllDlpManagerDie();
        return;
    }
    if (processData.renderUid != -1) {
        DLP_LOG_INFO(LABEL, "Ignore render process death, renderUid: %{public}d", processData.renderUid);
        return;
    }
    // current died process is dlp sandbox app
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(processData.uid, appInfo)) {
        return;
    }
    if (!CanUninstallByGid(appInfo, processData)) {
        DLP_LOG_INFO(LABEL, "Can not uninstall dlp sandbox by gid");
        return;
    }
    if (RetentionFileManager::GetInstance().CanUninstall(appInfo.tokenId)) {
        UninstallDlpSandbox(appInfo);
    }
    EraseDlpSandboxInfo(appInfo.uid);
    DLP_LOG_INFO(LABEL, "ExecuteCallbackAsync appInfo bundleName:%{public}s,appIndex:%{public}d,pid:%{public}d",
        appInfo.bundleName.c_str(), appInfo.appIndex, appInfo.pid);
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(appInfo);
}

void AppStateObserver::EraseUidTokenIdMap(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    auto iter = tokenIdToUidMap_.find(tokenId);
    if (iter != tokenIdToUidMap_.end()) {
        DLP_LOG_INFO(LABEL, "erase tokenId: %{public}d", tokenId);
        tokenIdToUidMap_.erase(iter);
    }
}

void AppStateObserver::AddUidWithTokenId(uint32_t tokenId, int32_t uid)
{
    if (tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "tokenId is invalid");
        return;
    }
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    if (tokenIdToUidMap_.count(tokenId) > 0) {
        return;
    }
    DLP_LOG_INFO(LABEL, "add tokenId: %{public}d, uid: %{public}d", tokenId, uid);
    tokenIdToUidMap_[tokenId] = uid;
}

bool AppStateObserver::GetUidByTokenId(uint32_t tokenId, int32_t& uid)
{
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    auto iter = tokenIdToUidMap_.find(tokenId);
    if (iter != tokenIdToUidMap_.end()) {
        uid = iter->second;
        DLP_LOG_INFO(LABEL, "tokenId: %{public}d, uid: %{public}d", tokenId, uid);
        return true;
    }
    return false;
}

bool AppStateObserver::CallbackListenerEmpty()
{
    std::lock_guard<std::mutex> lock(callbackListLock_);
    return callbackList_.empty();
}

bool AppStateObserver::RemoveCallbackListener(int32_t pid)
{
    std::lock_guard<std::mutex> lock(callbackListLock_);
    auto iter = callbackList_.find(pid);
    if (iter != callbackList_.end()) {
        (*iter).second--;
        if ((*iter).second <= 0) {
            DLP_LOG_INFO(LABEL, "erase pid %{public}d", pid);
            callbackList_.erase(pid);
            return callbackList_.empty();
        }
    }
    return false;
}

void AppStateObserver::AddCallbackListener(int32_t pid)
{
    std::lock_guard<std::mutex> lock(callbackListLock_);
    DLP_LOG_INFO(LABEL, "add pid %{public}d", pid);
    callbackList_[pid]++;
}

static bool IsCopyable(DLPFileAccess dlpFileAccess)
{
    switch (dlpFileAccess) {
        case DLPFileAccess::READ_ONLY:
            return false;
        case DLPFileAccess::CONTENT_EDIT:
            return true;
        case DLPFileAccess::FULL_CONTROL:
            return true;
        default:
            return false;
    }
}

int32_t AppStateObserver::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    int32_t uid;
    copyable = false;
    if (!GetUidByTokenId(tokenId, uid)) {
        DLP_LOG_WARN(LABEL, "current tokenId %{public}d is not a sandbox app", tokenId);
        copyable = false;
        return DLP_SERVICE_ERROR_APPOBSERVER_ERROR;
    }
    DLPFileAccess dlpFileAccess = DLPFileAccess::NO_PERMISSION;
    int32_t res = QueryDlpFileAccessByUid(dlpFileAccess, uid);
    if (res != DLP_OK) {
        copyable = false;
    } else {
        copyable = IsCopyable(dlpFileAccess);
    }
    return res;
}

int32_t AppStateObserver::QueryDlpFileAccessByUid(DLPFileAccess& dlpFileAccess, int32_t uid)
{
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(uid, appInfo) || appInfo.dlpFileAccess == DLPFileAccess::NO_PERMISSION) {
        DLP_LOG_ERROR(LABEL, "current uid %{public}d is not a sandbox app", uid);
        dlpFileAccess = DLPFileAccess::NO_PERMISSION;
        return DLP_SERVICE_ERROR_APPOBSERVER_ERROR;
    }
    dlpFileAccess = appInfo.dlpFileAccess;
    DLP_LOG_INFO(LABEL, "current dlp sandbox %{public}s%{public}d's perm type is %{public}d",
        appInfo.bundleName.c_str(), appInfo.appIndex, dlpFileAccess);
    return DLP_OK;
}

int32_t AppStateObserver::IsInDlpSandbox(bool& inSandbox, int32_t uid)
{
    inSandbox = false;
    DlpSandboxInfo appInfo;
    if (GetSandboxInfo(uid, appInfo)) {
        inSandbox = appInfo.appIndex > 0 ? true : false;
    }
    DLP_LOG_INFO(LABEL, "uid: %{public}d, inSandbox: %{public}d", uid, inSandbox);
    return DLP_OK;
}

void AppStateObserver::DumpSandbox(int fd)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    dprintf(fd, "DlpSandbox:\n");
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end(); iter++) {
        DlpSandboxInfo& appInfo = iter->second;
        dprintf(fd, "    userId:%d;bundleName:%s;sandboxIndex:%d;dlpFileAccess:%s\n",
            appInfo.userId, appInfo.bundleName.c_str(), appInfo.appIndex,
            appInfo.dlpFileAccess == DLPFileAccess::READ_ONLY ? "ReadOnly" : "FullControl");
    }
}

void AppStateObserver::EraseReadOnceUriInfoByUri(const std::string& uri)
{
    std::lock_guard<std::mutex> lock(readOnceUriMapLock_);
    auto iter = readOnceUriMap_.find(uri);
    if (iter != readOnceUriMap_.end()) {
        DLP_LOG_INFO(LABEL, "erase ReadOnce");
        readOnceUriMap_.erase(iter);
    }
}

bool AppStateObserver::AddUriAndNotOwnerAndReadOnce(const std::string& uri, bool isNotOwnerAndReadOnce)
{
    if (uri.empty()) {
        DLP_LOG_ERROR(LABEL, "uri is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(readOnceUriMapLock_);
    DLP_LOG_INFO(LABEL, "add readOnceUriMap, isNotOwnerAndReadOnce: %{public}d", isNotOwnerAndReadOnce);
    readOnceUriMap_[uri] = isNotOwnerAndReadOnce;
    return true;
}

bool AppStateObserver::GetNotOwnerAndReadOnceByUri(const std::string& uri, bool& isNotOwnerAndReadOnce)
{
    std::lock_guard<std::mutex> lock(readOnceUriMapLock_);
    auto iter = readOnceUriMap_.find(uri);
    if (iter != readOnceUriMap_.end()) {
        isNotOwnerAndReadOnce = iter->second;
        DLP_LOG_INFO(LABEL, "isNotOwnerAndReadOnce: %{public}d", isNotOwnerAndReadOnce);
        return true;
    }
    return false;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
