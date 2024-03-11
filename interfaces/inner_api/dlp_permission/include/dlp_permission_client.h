/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef DLP_PERMISSION_CLIENT_H
#define DLP_PERMISSION_CLIENT_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

#include "dlp_permission_death_recipient.h"
#include "dlp_permission.h"
#include "i_dlp_permission_service.h"
#include "dlp_permission_callback.h"
#include "dlp_sandbox_change_callback_customize.h"
#include "dlp_sandbox_change_callback.h"
#include "open_dlp_file_callback_customize.h"
#include "open_dlp_file_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionClient final {
public:
    static DlpPermissionClient& GetInstance();

    int32_t GenerateDlpCertificate(
        const PermissionPolicy& policy, std::shared_ptr<GenerateDlpCertificateCallback> callback);
    int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, std::shared_ptr<ParseDlpCertificateCallback> callback,
        const std::string& appId, const bool& offlineAccess);
    int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        SandboxInfo& sandboxInfo, const std::string& uri);
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId);
    int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType);
    int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId);
    int32_t QueryDlpFileAccess(DLPPermissionInfo& permInfo);
    int32_t IsInDlpSandbox(bool& inSandbox);
    int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType);
    int32_t RegisterDlpSandboxChangeCallback(const std::shared_ptr<DlpSandboxChangeCallbackCustomize>& customizedCb);
    int32_t UnregisterDlpSandboxChangeCallback(bool& result);
    int32_t RegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback);
    int32_t UnRegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback);
    int32_t GetDlpGatheringPolicy(bool& isGathering);
    int32_t SetRetentionState(const std::vector<std::string>& docUriVec);
    int32_t CancelRetentionState(const std::vector<std::string>& docUriVec);
    int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec);
    int32_t ClearUnreservedSandbox();
    int32_t GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec);
    int32_t SetMDMPolicy(const std::vector<std::string>& appIdList);
    int32_t GetMDMPolicy(std::vector<std::string>& appIdList);
    int32_t RemoveMDMPolicy();
    int32_t SetSandboxAppConfig(const std::string& configInfo);
    int32_t CleanSandboxAppConfig();
    int32_t GetSandboxAppConfig(std::string& configInfo);
    int32_t IsDLPFeatureProvided(bool& isProvideDLPFeature);
    void FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject);
    void FinishStartSAFail();
    void OnRemoteDiedHandle();

private:
    DlpPermissionClient();
    virtual ~DlpPermissionClient();
    DISALLOW_COPY_AND_MOVE(DlpPermissionClient);
    int32_t CreateDlpSandboxChangeCallback(const std::shared_ptr<DlpSandboxChangeCallbackCustomize> &customizedCb,
        sptr<DlpSandboxChangeCallback> &callback);
    int32_t CreateOpenDlpFileCallback(
        const std::shared_ptr<OpenDlpFileCallbackCustomize>& customizedCb, sptr<OpenDlpFileCallback>& callback);
    bool StartLoadDlpPermissionSa();
    void WaitForDlpPermissionSa();
    void GetDlpPermissionSa();
    void LoadDlpPermissionSa();

    sptr<IDlpPermissionService> GetProxy(bool doLoadSa);
    void GetProxyFromRemoteObject(const sptr<IRemoteObject>& remoteObject);

    std::mutex cvLock_;
    bool readyFlag_ = false;
    std::condition_variable dlpPermissionCon_;
    std::mutex proxyMutex_;
    sptr<IDlpPermissionService> proxy_ = nullptr;
    sptr<DlpPermissionDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex callbackMutex_;
    std::map<std::shared_ptr<OpenDlpFileCallbackCustomize>, sptr<OpenDlpFileCallback>> callbackMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_CLIENT_H
