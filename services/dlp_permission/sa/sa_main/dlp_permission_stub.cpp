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

#include "dlp_permission_stub.h"
#include "accesstoken_kit.h"
#include "dlp_dfx_define.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionStub"};
static const std::string FOUNDATION_SERVICE_NAME = "foundation";
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
}  // namespace

static bool CheckPermission(const std::string& permission)
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingToken, permission);
    if (res == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        DLP_LOG_INFO(LABEL, "Check permission %{public}s pass", permission.c_str());
        return true;
    }

    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::DLP, "DLP_PERMISSION_REPORT",
        HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", DLP_PERMISSION_VERIFY_ERROR,
        "CALLER_TOKENID", callingToken);

    DLP_LOG_ERROR(LABEL, "Check permission %{public}s fail", permission.c_str());
    return false;
}

static bool IsSaCall()
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::TypeATokenTypeEnum res = Security::AccessToken::AccessTokenKit::GetTokenType(callingToken);
    return (res == Security::AccessToken::TOKEN_NATIVE);
}

static int32_t CheckSandboxFlag(AccessToken::AccessTokenID tokenId, bool& sandboxFlag)
{
    int32_t res = AccessToken::AccessTokenKit::GetHapDlpFlag(tokenId);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Invalid tokenId");
        return res;
    }
    sandboxFlag = (res == 1);
    return DLP_OK;
}

int32_t DlpPermissionStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DLP_LOG_INFO(LABEL, "Called, code: 0x%{public}x, pid: %{public}d, uid: %{public}d", code,
        IPCSkeleton::GetCallingRealPid(), IPCSkeleton::GetCallingUid());

    std::u16string descripter = DlpPermissionStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        DLP_LOG_ERROR(LABEL, "Deal remote request fail, descriptor is not matched");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second.funcType;
        if (requestFunc != nullptr) {
            int32_t res = (this->*requestFunc)(data, reply);
#ifndef DLP_FUZZ_TEST
            if (itFunc->second.isNeedStartTimer) {
                DLP_LOG_DEBUG(LABEL, "enter StartTimer");
                this->StartTimer();
            }
#endif
            return res;
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DlpPermissionStub::GenerateDlpCertificateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    sptr<DlpPolicyParcel> policyParcel = data.ReadParcelable<DlpPolicyParcel>();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read dlp policy parcel fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read generate cert callback object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Iface cast generate cert callback fail");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->GenerateDlpCertificate(policyParcel, callback);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write generate cert result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::ParseDlpCertificateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    std::string appId;
    if (!data.ReadString(appId)) {
        DLP_LOG_ERROR(LABEL, "Read appId fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    sptr<CertParcel> certParcel = data.ReadParcelable<CertParcel>();
    if (certParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read certParcel fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read parse cert callback object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    bool offlineAccess = false;
    if (!data.ReadBool(offlineAccess)) {
        DLP_LOG_ERROR(LABEL, "Read offlineAccess fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Iface cast parse cert callback fail");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->ParseDlpCertificate(certParcel, callback, appId, offlineAccess);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write parse cert result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::InstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Read bundle name fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    uint32_t type;
    if (!data.ReadUint32(type)) {
        DLP_LOG_ERROR(LABEL, "Read auth perm type fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    DLPFileAccess dlpFileAccess = static_cast<DLPFileAccess>(type);

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read user id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    std::string uri;
    if (!data.ReadString(uri)) {
        DLP_LOG_ERROR(LABEL, "Read uri fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    SandboxInfo sandboxInfo;
    int32_t res = this->InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write install sandbox result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteInt32(sandboxInfo.appIndex)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox index fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteUint32(sandboxInfo.tokenId)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox tokenId fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::UninstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Read bundle name fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t appIndex;
    if (!data.ReadInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Read sandbox index fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read user id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t res = this->UninstallDlpSandbox(bundleName, appIndex, userId);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write uninstall sandbox result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetSandboxExternalAuthorizationInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSaCall() && !CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        DLP_LOG_ERROR(LABEL, "Caller is not SA or has no ACCESS_DLP_FILE permission");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t sandboxUid;
    if (!data.ReadInt32(sandboxUid)) {
        DLP_LOG_ERROR(LABEL, "Read sandbox uid fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    std::unique_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read want fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    SandBoxExternalAuthorType authType;
    int32_t res = this->GetSandboxExternalAuthorization(sandboxUid, *want, authType);
    if (res != DLP_OK) {
        return res;
    }

    if (!reply.WriteInt32(authType)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox external auth type fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::QueryDlpFileCopyableByTokenIdInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        DLP_LOG_ERROR(LABEL, "Read token id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    bool copyable = false;
    int32_t res = this->QueryDlpFileCopyableByTokenId(copyable, tokenId);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write copyalbe query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(copyable)) {
        DLP_LOG_ERROR(LABEL, "Write copyalbe fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::QueryDlpFileAccessInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a non-sandbox app");
        return DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR;
    }
    DLPPermissionInfoParcel permInfoParcel;
    int32_t res = this->QueryDlpFileAccess(permInfoParcel);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write dlp file access query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteParcelable(&permInfoParcel)) {
        DLP_LOG_ERROR(LABEL, "WriteParcelable fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::IsInDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    bool inSandbox = false;
    int32_t res = this->IsInDlpSandbox(inSandbox);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(inSandbox)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetDlpSupportFileTypeInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> supportFileType;
    int32_t res = this->GetDlpSupportFileType(supportFileType);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write support dlp file type query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    size_t listNum = supportFileType.size();
    if (!reply.WriteUint32(listNum)) {
        DLP_LOG_ERROR(LABEL, "Write support dlp file type list num fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    for (const auto& iter : supportFileType) {
        if (!reply.WriteString(iter)) {
            DLP_LOG_ERROR(LABEL, "Write support dlp file type string fail");
            return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::RegisterDlpSandboxChangeCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "read callback fail");
        reply.WriteInt32(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t result = this->RegisterDlpSandboxChangeCallback(callback);
    reply.WriteInt32(result);
    return DLP_OK;
}

int32_t DlpPermissionStub::UnRegisterDlpSandboxChangeCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    bool res = false;
    int32_t result = this->UnRegisterDlpSandboxChangeCallback(res);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(res)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::RegisterOpenDlpFileCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "read callback fail");
        reply.WriteInt32(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t result = this->RegisterOpenDlpFileCallback(callback);
    reply.WriteInt32(result);
    return DLP_OK;
}

int32_t DlpPermissionStub::UnRegisterOpenDlpFileCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "read callback fail");
        reply.WriteInt32(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t result = this->UnRegisterOpenDlpFileCallback(callback);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write un-register open dlp file callback result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetDlpGatheringPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    bool isGathering = false;
    int32_t res = this->GetDlpGatheringPolicy(isGathering);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write GetDlpGatheringPolicy result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(isGathering)) {
        DLP_LOG_ERROR(LABEL, "Write isGathering fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    return DLP_OK;
}

int32_t DlpPermissionStub::SetRetentionStateInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a non-sandbox app");
        return DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR;
    }
    std::vector<std::string> docUriVec;
    if (!data.ReadStringVector(&docUriVec)) {
        DLP_LOG_ERROR(LABEL, "Read docUriVec id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t result = this->SetRetentionState(docUriVec);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(result == DLP_OK)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::CancelRetentionStateInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> docUriVec;
    if (!data.ReadStringVector(&docUriVec)) {
        DLP_LOG_ERROR(LABEL, "Read token id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t result = this->CancelRetentionState(docUriVec);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(result == DLP_OK)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetRetentionSandboxListInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Read bundle name fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    int32_t result = this->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteUint32(retentionSandBoxInfoVec.size())) {
        DLP_LOG_ERROR(LABEL, "Write sandbox size result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    for (const auto& info : retentionSandBoxInfoVec) {
        if (!reply.WriteParcelable(&info)) {
            DLP_LOG_ERROR(LABEL, "Write sandbox size info fail");
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::ClearUnreservedSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::AccessTokenID bmsTokon =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId(FOUNDATION_SERVICE_NAME);
    DLP_LOG_ERROR(LABEL, "callingToken:%{public}d bmsTokon:%{public}d", callingToken, bmsTokon);
    if (callingToken != bmsTokon) {
        DLP_LOG_ERROR(LABEL, "callingToken:%{public}d bmsTokon:%{public}d", callingToken, bmsTokon);
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    this->ClearUnreservedSandbox();
    return DLP_OK;
}

int32_t DlpPermissionStub::GetDLPFileVisitRecordInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t res = this->GetDLPFileVisitRecord(infoVec);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write support visit file record query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (res != DLP_OK) {
        return DLP_OK;
    }
    size_t listNum = infoVec.size();
    if (!reply.WriteUint32(listNum)) {
        DLP_LOG_ERROR(LABEL, "Write support visit file record list num fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    for (const auto& iter : infoVec) {
        if (!reply.WriteParcelable(&iter)) {
            DLP_LOG_ERROR(LABEL, "Write support visit file record docUri string fail");
            return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::SetMDMPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> appIdList;
    if (!data.ReadStringVector(&appIdList)) {
        DLP_LOG_ERROR(LABEL, "Read appId List fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t result = this->SetMDMPolicy(appIdList);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write set policy result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetMDMPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> appIdList;
    int32_t result = this->GetMDMPolicy(appIdList);
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write get policy result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    size_t listNum = appIdList.size();
    if (!reply.WriteUint32(listNum)) {
        DLP_LOG_ERROR(LABEL, "Write appId list num fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteStringVector(appIdList)) {
        DLP_LOG_ERROR(LABEL, "Write string vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::RemoveMDMPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t result = this->RemoveMDMPolicy();
    if (!reply.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write remove policy result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::SetSandboxAppConfigInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    std::string configInfo;
    if (!data.ReadString(configInfo)) {
        DLP_LOG_ERROR(LABEL, "Read configInfo fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t res = this->SetSandboxAppConfig(configInfo);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write SetSandboxAppConfig result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionStub::CleanSandboxAppConfigInner(MessageParcel& data, MessageParcel& reply)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    int32_t res = this->CleanSandboxAppConfig();
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write CleanSandboxAppConfig result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionStub::GetSandboxAppConfigInner(MessageParcel& data, MessageParcel& reply)
{
    std::string configInfo;
    int32_t res = this->GetSandboxAppConfig(configInfo);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write support sandbox app config query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (res != DLP_OK) {
        return res;
    }
    if (!reply.WriteString(configInfo)) {
        DLP_LOG_ERROR(LABEL, "Write configInfo fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::IsDLPFeatureProvidedInner(MessageParcel& data, MessageParcel& reply)
{
    bool isProvideDLPFeature;
    this->IsDLPFeatureProvided(isProvideDLPFeature);
    if (!reply.WriteBool(isProvideDLPFeature)) {
        DLP_LOG_ERROR(LABEL, "Write isProvideDLPFeature fail.");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

void DlpPermissionStub::InitMDMPolicy()
{
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::SET_MDM_POLICY)] =
        {.funcType = &DlpPermissionStub::SetMDMPolicyInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_MDM_POLICY)] =
        {.funcType = &DlpPermissionStub::GetMDMPolicyInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::REMOVE_MDM_POLICY)] =
        {.funcType = &DlpPermissionStub::RemoveMDMPolicyInner};
}

void DlpPermissionStub::InitTimerFuncMap()
{
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::SET_SANDBOX_APP_CONFIG)] =
        {.funcType = &DlpPermissionStub::SetSandboxAppConfigInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::CLEAN_SANDBOX_APP_CONFIG)] =
        {.funcType = &DlpPermissionStub::CleanSandboxAppConfigInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_SANDBOX_APP_CONFIG)] =
        {.funcType = &DlpPermissionStub::GetSandboxAppConfigInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_DLP_SUPPORT_FILE_TYPE)] =
        {.funcType = &DlpPermissionStub::GetDlpSupportFileTypeInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::UN_REGISTER_OPEN_DLP_FILE_CALLBACK)] =
        {.funcType = &DlpPermissionStub::UnRegisterOpenDlpFileCallbackInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::SET_NOT_RETENTION_STATE)] =
        {.funcType = &DlpPermissionStub::CancelRetentionStateInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::CLEAR_UNRESERVED_SANDBOX)] =
        {.funcType = &DlpPermissionStub::ClearUnreservedSandboxInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_VISTI_FILE_RECORD_LIST)] =
        {.funcType = &DlpPermissionStub::GetDLPFileVisitRecordInner, .isNeedStartTimer = true};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::IS_DLP_FEATURE_PROVIDED)] =
        {.funcType = &DlpPermissionStub::IsDLPFeatureProvidedInner, .isNeedStartTimer = true};
}

DlpPermissionStub::DlpPermissionStub()
{
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GENERATE_DLP_CERTIFICATE)] =
        {.funcType = &DlpPermissionStub::GenerateDlpCertificateInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::PARSE_DLP_CERTIFICATE)] =
        {.funcType = &DlpPermissionStub::ParseDlpCertificateInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::INSTALL_DLP_SANDBOX)] =
        {.funcType = &DlpPermissionStub::InstallDlpSandboxInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::UNINSTALL_DLP_SANDBOX)] =
        {.funcType = &DlpPermissionStub::UninstallDlpSandboxInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_SANDBOX_EXTERNAL_AUTH)] =
        {.funcType = &DlpPermissionStub::GetSandboxExternalAuthorizationInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::QUERY_DLP_FILE_ACCESS_BY_TOKEN_ID)] =
        {.funcType = &DlpPermissionStub::QueryDlpFileCopyableByTokenIdInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::QUERY_DLP_FILE_ACCESS)] =
        {.funcType = &DlpPermissionStub::QueryDlpFileAccessInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::IS_IN_DLP_SANDBOX)] =
        {.funcType = &DlpPermissionStub::IsInDlpSandboxInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::REGISTER_DLP_SANDBOX_CHANGE_CALLBACK)] =
        {.funcType = &DlpPermissionStub::RegisterDlpSandboxChangeCallbackInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK)] =
        {.funcType = &DlpPermissionStub::UnRegisterDlpSandboxChangeCallbackInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_DLP_GATHERING_POLICY)] =
        {.funcType = &DlpPermissionStub::GetDlpGatheringPolicyInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::SET_RETENTION_STATE)] =
        {.funcType = &DlpPermissionStub::SetRetentionStateInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_RETENTION_SANDBOX_LIST)] =
        {.funcType = &DlpPermissionStub::GetRetentionSandboxListInner};
    requestFuncMap_[static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::REGISTER_OPEN_DLP_FILE_CALLBACK)] =
        {.funcType = &DlpPermissionStub::RegisterOpenDlpFileCallbackInner};
    InitMDMPolicy();
    InitTimerFuncMap();
}

DlpPermissionStub::~DlpPermissionStub()
{
    requestFuncMap_.clear();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
