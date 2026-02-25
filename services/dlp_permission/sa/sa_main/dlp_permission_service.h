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
#include <map>
#include "app_state_observer.h"
#include "app_uninstall_observer.h"
#include "dlp_permission_service_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "retention_file_manager.h"
#include "sandbox_config_kv_data_storage.h"
#include "singleton.h"
#include "system_ability.h"
#include "transaction/rs_interfaces.h"
#include "window_manager_lite.h"
#include "wm_common.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
typedef struct GetAppIndexParams {
    const std::string bundleName;
    bool isReadOnly;
    const std::string uri;
    bool isNotOwnerAndReadOnce;
} GetAppIndexParams;

struct WaterMarkInfo {
public:
    std::string accountAndUserId = "";
    std::shared_ptr<Media::PixelMap> waterMarkImg = nullptr;
    int32_t waterMarkFd = -1;
    std::string maskInfo = "";
};

class DlpPermissionService final : public SystemAbility, public DlpPermissionServiceStub {
    DECLARE_DELAYED_SINGLETON(DlpPermissionService);
    DECLEAR_SYSTEM_ABILITY(DlpPermissionService);

public:
    DlpPermissionService(int saId, bool runOnCreate);
    void OnStart() override;
    void OnStop() override;

    bool RegisterAppStateObserver();
    void UnregisterAppStateObserver();

    int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, const sptr<IDlpPermissionCallback>& callback) override;
    int32_t ParseDlpCertificate(const sptr<CertParcel>& certParcel, const sptr<IDlpPermissionCallback>& callback,
        const std::string& appId, bool offlineAccess) override;
    int32_t GetWaterMark(const bool waterMarkConfig,
        const sptr<IDlpPermissionCallback>& callback) override;
    int32_t GetDomainAccountNameInfo(std::string& accountNameInfo) override;
    int32_t GetAbilityInfos(const AAFwk::Want& want, int32_t flags, int32_t userId,
        std::vector<AppExecFwk::AbilityInfo> &abilityInfos) override;
    int32_t SetWaterMark(const int32_t pid) override;
    int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        SandboxInfo& sandboxInfo, const std::string& uri) override;
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
    int32_t SetReadFlag(uint32_t uid) override;
    int32_t SetMDMPolicy(const std::vector<std::string>& appIdList) override;
    int32_t GetMDMPolicy(std::vector<std::string>& appIdList) override;
    int32_t RemoveMDMPolicy() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;
    int32_t SetDlpFeature(const uint32_t dlpFeatureInfo, bool& statusSetInfo) override;
    int32_t SetEnterprisePolicy(const std::string& policy) override;
    int32_t SetFileInfo(const std::string& uri, const FileInfo& fileInfo) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    bool InsertDlpSandboxInfo(DlpSandboxInfo& sandboxInfo, bool hasRetention, const FileInfo& fileInfo);
    uint32_t DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId);
    bool GetCallerBundleName(const uint32_t tokenId, std::string& bundleName);
    bool RemoveRetentionInfo(std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, RetentionInfo& info);
    int32_t UninstallDlpSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId);
    int32_t SandConfigOperateCheck(SandboxConfigOperationEnum operationEnum, std::string& bundleName,
        int32_t& userId, AccessToken::AccessTokenID& originalTokenId);
    int32_t SandboxConfigOperate(std::string& configInfo, SandboxConfigOperationEnum operationEnum);
    void GetCfgFilesList(std::vector<std::string>& cfgFilesList);
    void GetConfigFileValue(const std::string& cfgFile, std::vector<std::string>& typeList);
    void InitConfig(std::vector<std::string>& typeList);
    int32_t CheckIfEnterpriseAccount();
    int32_t CheckWaterMarkInfo();
    int32_t InstallSandboxApp(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        DlpSandboxInfo& dlpSandboxInfo);
    int32_t ChangeWaterMarkInfo();
    void UnregisterAccount();
    void RegisterAccount();
    int32_t InitAccountListenerCallback();
    void DelSandboxInfoByAccount(bool isRegister);

    std::atomic<int32_t> repeatTime_;
    std::shared_ptr<std::thread> thread_ = nullptr;
    std::mutex mutex_;
    std::shared_mutex dlpSandboxDataMutex_;
    std::mutex waterMarkInfoMutex_;
    std::condition_variable waterMarkInfoCv_;
    ServiceRunningState state_;
    sptr<AppExecFwk::IAppMgr> iAppMgr_;
    sptr<AppStateObserver> appStateObserver_;
    std::shared_ptr<DlpEventSubSubscriber> dlpEventSubSubscriber_ = nullptr;
    std::map<int, DLPFileAccess> dlpSandboxData_;
    WaterMarkInfo waterMarkInfo_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERVICE_H
