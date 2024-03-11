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

#include "dlp_permission_kit.h"
#include <string>
#include <thread>
#include <vector>
#include "datetime_ex.h"
#include "dlp_permission_client.h"
#include "dlp_permission_log.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKit"};
const int64_t TIME_WAIT_TIME_OUT = 10;
}  // namespace

void ClientGenerateDlpCertificateCallback::OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
    this->result_ = result;
    if (result == DLP_OK) {
        this->cert_ = cert;
    }
    std::unique_lock<std::mutex> lck(generateMtx_);
    this->isCallBack_ = true;
    generateCv_.notify_all();
}

void ClientParseDlpCertificateCallback::OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
    const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
    this->result_ = result;
    if (result == DLP_OK) {
        this->policy_.CopyPermissionPolicy(policy);
        this->offlineCert_ = cert;
    }
    std::unique_lock<std::mutex> lck(parseMtx_);
    this->isCallBack_ = true;
    parseCv_.notify_all();
}

int32_t DlpPermissionKit::GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert)
{
    std::shared_ptr<ClientGenerateDlpCertificateCallback> callback =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    int32_t res = DlpPermissionClient::GetInstance().GenerateDlpCertificate(policy, callback);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "begin generate cert fail, error: %{public}d", res);
        return res;
    }

    // wait callback
    {
        std::unique_lock<std::mutex> lck(callback->generateMtx_);
        if (!callback->isCallBack_) {
            callback->generateCv_.wait_for(lck, std::chrono::seconds(TIME_WAIT_TIME_OUT));
        }
    }
    if (!callback->isCallBack_) {
        DLP_LOG_ERROR(LABEL, "service did not call back! timeout!");
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT;
    }
    DLP_LOG_INFO(LABEL, "get callback succeed!");
    if (callback->result_ == DLP_OK) {
        cert = callback->cert_;
    }
    return callback->result_;
}

int32_t DlpPermissionKit::ParseDlpCertificate(sptr<CertParcel>& certParcel, PermissionPolicy& policy,
    const std::string& appId, const bool& offlineAccess)
{
    std::shared_ptr<ClientParseDlpCertificateCallback> callback = std::make_shared<ClientParseDlpCertificateCallback>();
    int32_t res = DlpPermissionClient::GetInstance().ParseDlpCertificate(certParcel, callback, appId, offlineAccess);
    if (res != DLP_OK) {
        DLP_LOG_INFO(LABEL, "ParseDlpCertificate return %{public}d", res);
        return res;
    }

    // wait callback
    {
        std::unique_lock<std::mutex> lck(callback->parseMtx_);
        if (!callback->isCallBack_) {
            callback->parseCv_.wait_for(lck, std::chrono::seconds(TIME_WAIT_TIME_OUT));
        }
    }

    if (!callback->isCallBack_) {
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT;
    }

    if (callback->result_ == DLP_OK) {
        policy.CopyPermissionPolicy(callback->policy_);
        certParcel->offlineCert = callback->offlineCert_;
    }

    return callback->result_;
}

int32_t DlpPermissionKit::InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId,
    SandboxInfo& sandboxInfo, const std::string& uri)
{
    return DlpPermissionClient::GetInstance().InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
}

int32_t DlpPermissionKit::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    return DlpPermissionClient::GetInstance().UninstallDlpSandbox(bundleName, appIndex, userId);
}

int32_t DlpPermissionKit::GetSandboxExternalAuthorization(int sandboxUid,
    const AAFwk::Want& want, SandBoxExternalAuthorType& authType)
{
    return DlpPermissionClient::GetInstance().GetSandboxExternalAuthorization(sandboxUid, want, authType);
}

int32_t DlpPermissionKit::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    return DlpPermissionClient::GetInstance().QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

int32_t DlpPermissionKit::QueryDlpFileAccess(DLPPermissionInfo& permInfo)
{
    return DlpPermissionClient::GetInstance().QueryDlpFileAccess(permInfo);
}

int32_t DlpPermissionKit::IsInDlpSandbox(bool& inSandbox)
{
    return DlpPermissionClient::GetInstance().IsInDlpSandbox(inSandbox);
}

int32_t DlpPermissionKit::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    return DlpPermissionClient::GetInstance().GetDlpSupportFileType(supportFileType);
}

int32_t DlpPermissionKit::RegisterDlpSandboxChangeCallback(
    const std::shared_ptr<DlpSandboxChangeCallbackCustomize> &callback)
{
    return DlpPermissionClient::GetInstance().RegisterDlpSandboxChangeCallback(callback);
}

int32_t DlpPermissionKit::UnregisterDlpSandboxChangeCallback(bool &result)
{
    return DlpPermissionClient::GetInstance().UnregisterDlpSandboxChangeCallback(result);
}

int32_t DlpPermissionKit::RegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback)
{
    return DlpPermissionClient::GetInstance().RegisterOpenDlpFileCallback(callback);
}

int32_t DlpPermissionKit::UnRegisterOpenDlpFileCallback(const std::shared_ptr<OpenDlpFileCallbackCustomize>& callback)
{
    return DlpPermissionClient::GetInstance().UnRegisterOpenDlpFileCallback(callback);
}

int32_t DlpPermissionKit::GetDlpGatheringPolicy(bool& isGathering)
{
    return DlpPermissionClient::GetInstance().GetDlpGatheringPolicy(isGathering);
}

int32_t DlpPermissionKit::SetRetentionState(const std::vector<std::string>& docUriVec)
{
    return DlpPermissionClient::GetInstance().SetRetentionState(docUriVec);
}

int32_t DlpPermissionKit::CancelRetentionState(const std::vector<std::string>& docUriVec)
{
    return DlpPermissionClient::GetInstance().CancelRetentionState(docUriVec);
}

int32_t DlpPermissionKit::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    return DlpPermissionClient::GetInstance().GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
}

int32_t DlpPermissionKit::ClearUnreservedSandbox()
{
    return DlpPermissionClient::GetInstance().ClearUnreservedSandbox();
}

int32_t DlpPermissionKit::GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec)
{
    return DlpPermissionClient::GetInstance().GetDLPFileVisitRecord(infoVec);
}

int32_t DlpPermissionKit::SetMDMPolicy(const std::vector<std::string>& appIdList)
{
    return DlpPermissionClient::GetInstance().SetMDMPolicy(appIdList);
}

int32_t DlpPermissionKit::GetMDMPolicy(std::vector<std::string>& appIdList)
{
    return DlpPermissionClient::GetInstance().GetMDMPolicy(appIdList);
}

int32_t DlpPermissionKit::RemoveMDMPolicy()
{
    return DlpPermissionClient::GetInstance().RemoveMDMPolicy();
}

int32_t DlpPermissionKit::SetSandboxAppConfig(const std::string& configInfo)
{
    return DlpPermissionClient::GetInstance().SetSandboxAppConfig(configInfo);
}

int32_t DlpPermissionKit::CleanSandboxAppConfig()
{
    return DlpPermissionClient::GetInstance().CleanSandboxAppConfig();
}

int32_t DlpPermissionKit::GetSandboxAppConfig(std::string& configInfo)
{
    return DlpPermissionClient::GetInstance().GetSandboxAppConfig(configInfo);
}

int32_t DlpPermissionKit::IsDLPFeatureProvided(bool& isProvideDLPFeature)
{
    return DlpPermissionClient::GetInstance().IsDLPFeatureProvided(isProvideDLPFeature);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
