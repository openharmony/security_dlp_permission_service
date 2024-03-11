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

#ifndef DLP_PERMISSION_PROXY_H
#define DLP_PERMISSION_PROXY_H

#include <string>
#include <vector>
#include "iremote_proxy.h"
#include "dlp_permission.h"
#include "i_dlp_permission_service.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionProxy : public IRemoteProxy<IDlpPermissionService> {
public:
    explicit DlpPermissionProxy(const sptr<IRemoteObject>& impl);
    ~DlpPermissionProxy() override;

    int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) override;
    int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
        const std::string& appId, const bool& offlineAccess) override;
    int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        SandboxInfo& sandboxInfo, const std::string& uri) override;
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) override;
    int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType) override;
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
    int32_t SetMDMPolicy(const std::vector<std::string>& appIdList) override;
    int32_t GetMDMPolicy(std::vector<std::string>& appIdList) override;
    int32_t RemoveMDMPolicy() override;
    int32_t SetSandboxAppConfig(const std::string& configInfo) override;
    int32_t CleanSandboxAppConfig() override;
    int32_t GetSandboxAppConfig(std::string& configInfo) override;
    int32_t IsDLPFeatureProvided(bool& isProvideDLPFeature) override;

private:
    static inline BrokerDelegator<DlpPermissionProxy> delegator_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_PROXY_H
