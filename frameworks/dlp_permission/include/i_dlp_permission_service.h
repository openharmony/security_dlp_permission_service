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

#ifndef I_DLP_PERMISSION_SERVICE_H
#define I_DLP_PERMISSION_SERVICE_H

#include <string>
#include "cert_parcel.h"
#include "dlp_permission_info_parcel.h"
#include "dlp_permission_service_ipc_interface_code.h"
#include "dlp_policy_parcel.h"
#include "i_dlp_permission_callback.h"
#include "iremote_broker.h"
#include "retention_sandbox_info.h"
#include "visited_dlp_file_info.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

class IDlpPermissionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.IDlpPermissionService");

    virtual int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) = 0;

    virtual int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
        const std::string& appId, const bool& offlineAccess) = 0;

    virtual int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
        SandboxInfo& sandboxInfo, const std::string& uri) = 0;

    virtual int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) = 0;
    virtual int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType) = 0;

    virtual int32_t QueryDlpFileAccess(DLPPermissionInfoParcel& permInfoParcel) = 0;

    virtual int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId) = 0;

    virtual int32_t IsInDlpSandbox(bool& inSandbox) = 0;

    virtual int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType) = 0;

    virtual int32_t RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject>& callback) = 0;

    virtual int32_t UnRegisterDlpSandboxChangeCallback(bool& result) = 0;

    virtual int32_t RegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback) = 0;

    virtual int32_t UnRegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback) = 0;

    virtual int32_t GetDlpGatheringPolicy(bool& isGathering) = 0;

    virtual int32_t SetRetentionState(const std::vector<std::string>& docUriVec) = 0;

    virtual int32_t CancelRetentionState(const std::vector<std::string>& docUriVec) = 0;

    virtual int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec) = 0;

    virtual int32_t ClearUnreservedSandbox() = 0;

    virtual int32_t GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec) = 0;

    virtual int32_t SetMDMPolicy(const std::vector<std::string>& appIdList) = 0;

    virtual int32_t GetMDMPolicy(std::vector<std::string>& appIdList) = 0;

    virtual int32_t RemoveMDMPolicy() = 0;

    virtual int32_t SetSandboxAppConfig(const std::string& configInfo) = 0;

    virtual int32_t CleanSandboxAppConfig() = 0;

    virtual int32_t GetSandboxAppConfig(std::string& configInfo) = 0;

    virtual int32_t IsDLPFeatureProvided(bool& isProvideDLPFeature) = 0;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // I_DLP_PERMISSION_SERVICE_H
