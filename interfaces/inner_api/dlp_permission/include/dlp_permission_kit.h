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

#ifndef INTERFACES_INNER_API_DLP_PERMISSION_KIT_H
#define INTERFACES_INNER_API_DLP_PERMISSION_KIT_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>
#include "cert_parcel.h"
#include "dlp_permission_callback.h"
#include "dlp_sandbox_change_callback_customize.h"
#include "open_dlp_file_callback_customize.h"
#include "parcel.h"
#include "permission_policy.h"
#include "retention_sandbox_info.h"
#include "visited_dlp_file_info.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class ClientGenerateDlpCertificateCallback : public GenerateDlpCertificateCallback {
public:
    ClientGenerateDlpCertificateCallback() = default;
    virtual ~ClientGenerateDlpCertificateCallback() = default;

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override;

    int32_t result_ = -1;
    std::vector<uint8_t> cert_;
    bool isCallBack_ = false;
    std::mutex generateMtx_;
    std::condition_variable generateCv_;
};

class ClientParseDlpCertificateCallback : public ParseDlpCertificateCallback {
public:
    ClientParseDlpCertificateCallback() = default;
    virtual ~ClientParseDlpCertificateCallback() = default;

    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override;

    int32_t result_ = -1;
    PermissionPolicy policy_;
    std::vector<uint8_t> offlineCert_;
    bool isCallBack_ = false;
    std::mutex parseMtx_;
    std::condition_variable parseCv_;
};

class DlpPermissionKit {
public:
    static int32_t GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert);
    static int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, PermissionPolicy& policy,
        const std::string& appId, const bool& offlineAccess);
    static int32_t InstallDlpSandbox(const std::string& bundleName, DLPFileAccess access, int32_t userId,
        SandboxInfo& sandboxInfo, const std::string& uri);
    static int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId);
    static int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType);
    static int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId);
    static int32_t QueryDlpFileAccess(DLPPermissionInfo& permInfo);
    static int32_t IsInDlpSandbox(bool& inSandbox);
    static int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType);
    static int32_t RegisterDlpSandboxChangeCallback(const std::shared_ptr<DlpSandboxChangeCallbackCustomize>& callback);
    static int32_t UnregisterDlpSandboxChangeCallback(bool& result);
    static int32_t RegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback);
    static int32_t UnRegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback);
    static int32_t GetDlpGatheringPolicy(bool& isGathering);
    static int32_t SetRetentionState(const std::vector<std::string>& docUriVec);
    static int32_t CancelRetentionState(const std::vector<std::string>& docUriVec);
    static int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec);
    static int32_t ClearUnreservedSandbox();
    static int32_t GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec);
    static int32_t SetMDMPolicy(const std::vector<std::string>& appIdList);
    static int32_t GetMDMPolicy(std::vector<std::string>& appIdList);
    static int32_t RemoveMDMPolicy();
    static int32_t SetSandboxAppConfig(const std::string& configInfo);
    static int32_t CleanSandboxAppConfig();
    static int32_t GetSandboxAppConfig(std::string& configInfo);
    static int32_t IsDLPFeatureProvided(bool& isProvideDLPFeature);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // INTERFACES_INNER_API_DLP_PERMISSION_KIT_H
