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

#include "dlp_permission_async_stub.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_service_ipc_interface_code.h"
#include "dlp_policy_parcel.h"
#include "ipc_skeleton.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionAsyncStub"};
}
DlpPermissionAsyncStub::DlpPermissionAsyncStub(std::shared_ptr<GenerateDlpCertificateCallback>& impl)
    : generateDlpCertificateCallback_(impl)
{}

DlpPermissionAsyncStub::DlpPermissionAsyncStub(std::shared_ptr<ParseDlpCertificateCallback>& impl)
    : parseDlpCertificateCallback_(impl)
{}

int32_t DlpPermissionAsyncStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DLP_LOG_INFO(LABEL, "Called, code: 0x%{public}x, pid: %{public}d, uid: %{public}d", code,
        IPCSkeleton::GetCallingRealPid(), IPCSkeleton::GetCallingUid());

    std::u16string descripter = DlpPermissionAsyncStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        DLP_LOG_ERROR(LABEL, "OnRemoteRequest failed, descriptor is not matched");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(DlpPermissionCallbackInterfaceCode::ON_GENERATE_DLP_CERTIFICATE):
            return OnGenerateDlpCertificateStub(data, reply);
        case static_cast<int32_t>(DlpPermissionCallbackInterfaceCode::ON_PARSE_DLP_CERTIFICATE):
            return OnParseDlpCertificateStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t DlpPermissionAsyncStub::OnGenerateDlpCertificateStub(MessageParcel& data, MessageParcel& reply)
{
    std::vector<uint8_t> cert;
    int32_t result;

    if (!data.ReadInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        this->OnGenerateDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (result != DLP_OK) {
        this->OnGenerateDlpCertificate(result, {});
        return DLP_OK;
    }
    if (!data.ReadUInt8Vector(&cert)) {
        DLP_LOG_ERROR(LABEL, "Read int8 vector fail");
        this->OnGenerateDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    this->OnGenerateDlpCertificate(result, cert);
    return DLP_OK;
}

void DlpPermissionAsyncStub::OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    if (generateDlpCertificateCallback_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return;
    }

    generateDlpCertificateCallback_->OnGenerateDlpCertificate(result, cert);
}

int32_t DlpPermissionAsyncStub::OnParseDlpCertificateStub(MessageParcel& data, MessageParcel& reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        PermissionPolicy policyNull;
        this->OnParseDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, policyNull, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (result != DLP_OK) {
        PermissionPolicy policyNull;
        this->OnParseDlpCertificate(result, policyNull, {});
        return DLP_OK;
    }
    sptr<DlpPolicyParcel> policyParcel = data.ReadParcelable<DlpPolicyParcel>();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read parcel fail");
        PermissionPolicy policyNull;
        this->OnParseDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, policyNull, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    std::vector<uint8_t> cert;
    if (!data.ReadUInt8Vector(&cert)) {
        DLP_LOG_ERROR(LABEL, "Read int8 vector fail");
        this->OnGenerateDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    this->OnParseDlpCertificate(result, policyParcel->policyParams_, cert);
    return DLP_OK;
}

void DlpPermissionAsyncStub::OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
    const std::vector<uint8_t>& cert)
{
    if (parseDlpCertificateCallback_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return;
    }

    parseDlpCertificateCallback_->OnParseDlpCertificate(result, policy, cert);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
