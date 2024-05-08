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

#ifndef DLP_PERMISSION_SERVICE_SERVICES_DLP_PERMISSION_SA_APP_STATE_OBSERVER_APP_STATE_OBSERVER_H
#define DLP_PERMISSION_SERVICE_SERVICES_DLP_PERMISSION_SA_APP_STATE_OBSERVER_APP_STATE_OBSERVER_H

#include <unordered_map>
#include <mutex>
#include "application_state_observer_stub.h"
#include "app_mgr_interface.h"
#include "app_mgr_proxy.h"
#include "dlp_sandbox_info.h"
#include "iremote_object.h"
#include "retention_file_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class AppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    explicit AppStateObserver();
    virtual ~AppStateObserver();

    void OnProcessDied(const AppExecFwk::ProcessData& processData) override;
    int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId);
    int32_t QueryDlpFileAccessByUid(DLPFileAccess& dlpFileAccess, int32_t uid);
    int32_t IsInDlpSandbox(bool& inSandbox, int32_t uid);
    void AddDlpSandboxInfo(const DlpSandboxInfo& appInfo);
    uint32_t EraseDlpSandboxInfo(int uid);
    bool CheckSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId);
    void DumpSandbox(int fd);
    void ExitSaAfterAllDlpManagerDie();
    void GetOpeningReadOnlySandbox(const std::string& bundleName, int32_t userId, int32_t& appIndex);
    void AddCallbackListener(int32_t pid);
    bool RemoveCallbackListener(int32_t pid);
    bool CallbackListenerEmpty();

private:
    void UninstallDlpSandbox(DlpSandboxInfo& appInfo);
    void UninstallAllDlpSandboxForUser(int32_t userId);
    void UninstallAllDlpSandbox();

    void EraseUserId(int32_t userId);
    void AddUserId(int32_t userId);

    void AddSandboxInfo(const DlpSandboxInfo& appInfo);
    bool GetSandboxInfo(int32_t uid, DlpSandboxInfo& appInfo);
    void EraseSandboxInfo(int32_t uid);

    void AddUidWithTokenId(uint32_t tokenId, int32_t uid);
    bool GetUidByTokenId(uint32_t tokenId, int32_t& uid);
    void EraseUidTokenIdMap(uint32_t tokenId);

    void UpdateSandboxAppStatus(int32_t uid, int32_t state);

    std::unordered_map<uint32_t, int32_t> tokenIdToUidMap_;
    std::mutex tokenIdToUidMapLock_;
    std::unordered_map<int32_t, DlpSandboxInfo> sandboxInfo_;
    std::mutex sandboxInfoLock_;
    std::set<int32_t> userIdList_;
    std::mutex userIdListLock_;
    std::map<int32_t, int32_t> callbackList_;
    std::mutex callbackListLock_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // DLP_PERMISSION_SERVICE_SERVICES_DLP_PERMISSION_SA_APP_STATE_OBSERVER_APP_STATE_OBSERVER_H
