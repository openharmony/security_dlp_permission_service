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

#ifndef DLP_PERMISSION_SERVICE_H
#define DLP_PERMISSION_SERVICE_H

#include <atomic>
#include <string>
#include <vector>
#include "app_state_observer.h"
#include "app_uninstall_observer.h"
#include "dlp_permission_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "retention_file_manager.h"
#include "sandbox_config_kv_data_storage.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

#ifdef DLP_GATHERING_SANDBOX
#define GATHERING_POLICY true
#else
#define GATHERING_POLICY false
#endif

class DlpPermissionService final : public SystemAbility, public DlpPermissionStub {
    DECLARE_DELAYED_SINGLETON(DlpPermissionService);
    DECLEAR_SYSTEM_ABILITY(DlpPermissionService);

public:
    DlpPermissionService(int saId, bool runOnCreate);
    void OnStart() override;
    void OnStop() override;

    bool RegisterAppStateObserver();
    void UnregisterAppStateObserver();

    int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) override;
    int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
        const std::string& appId, const bool& offlineAccess) override;
    int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        SandboxInfo &sandboxInfo, const std::string& uri) override;
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) override;
    int32_t GetSandboxExternalAuthorization(
        int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& authType) override;

    int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId) override;
    int32_t QueryDlpFileAccess(DLPPermissionInfoParcel& permInfoParcel) override;
    int32_t IsInDlpSandbox(bool& inSandbox) override;
    int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType) override;
    int32_t RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterDlpSandboxChangeCallback(bool& result) override;
    int32_t RegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback) override;

    int32_t GetDlpGatheringPolicy(bool& isGathering) override;
    int32_t SetRetentionState(const std::vector<std::string>& docUriVec) override;
    int32_t CancelRetentionState(const std::vector<std::string>& docUriVec) override;
    int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec) override;
    int32_t ClearUnreservedSandbox() override;
    int32_t GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec) override;
    int32_t SetSandboxAppConfig(const std::string& configInfo) override;
    int32_t CleanSandboxAppConfig() override;
    int32_t GetSandboxAppConfig(std::string& configInfo) override;
    int32_t IsDLPFeatureProvided(bool& isProvideDLPFeature) override;

    int32_t SetMDMPolicy(const std::vector<std::string>& appIdList) override;
    int32_t GetMDMPolicy(std::vector<std::string>& appIdList) override;
    int32_t RemoveMDMPolicy() override;
    void StartTimer() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;

private:
    void RemoveUninstallInfo();
    bool InsertDlpSandboxInfo(DlpSandboxInfo& sandboxInfo, bool hasRetention);
    uint32_t DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId);
    bool GetCallerBundleName(const uint32_t tokenId, std::string& bundleName);
    bool RemoveRetentionInfo(std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, RetentionInfo& info);
    int32_t UninstallDlpSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId);
    int32_t SandboxConfigOperate(std::string& configInfo, SandboxConfigOperationEnum operationEnum);
    void TerminalService();
    void GetCfgFilesList(std::vector<std::string> &cfgFilesList);
    void GetConfigFileValue(const std::string &cfgFile, std::vector<std::string> &typeList);
    std::vector<std::string> InitConfig();

    std::atomic<int32_t> repeatTime_;
    std::shared_ptr<std::thread> thread_;
    std::mutex mutex_;
    std::mutex terminalMutex_;
    bool isGathering_ = GATHERING_POLICY;
    ServiceRunningState state_;
    sptr<AppExecFwk::IAppMgr> iAppMgr_;
    sptr<AppStateObserver> appStateObserver_;
    std::shared_ptr<DlpEventSubSubscriber> dlpEventSubSubscriber_ = nullptr;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERVICE_H
