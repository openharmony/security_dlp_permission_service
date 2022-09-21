/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "dlp_policy.h"
#include "dlp_policy_parcel.h"
#include "ipc_skeleton.h"

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
        IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid());

    std::u16string descripter = DlpPermissionAsyncStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        DLP_LOG_ERROR(LABEL, "OnRemoteRequest failed, descriptor is not matched");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IDlpPermissionCallback::InterfaceCode::ON_GENERATE_DLP_CERTIFICATE):
            return onGenerateDlpCertificateStub(data, reply);
        case static_cast<int32_t>(IDlpPermissionCallback::InterfaceCode::ON_PARSE_DLP_CERTIFICATE):
            return onParseDlpCertificateStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t DlpPermissionAsyncStub::onGenerateDlpCertificateStub(MessageParcel& data, MessageParcel& reply)
{
    std::vector<uint8_t> cert;
    int32_t result;

    if (!data.ReadInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        this->onGenerateDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (result != DLP_OK) {
        this->onGenerateDlpCertificate(result, {});
        return DLP_OK;
    }
    if (!data.ReadUInt8Vector(&cert)) {
        DLP_LOG_ERROR(LABEL, "Read int8 vector fail");
        this->onGenerateDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, {});
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    this->onGenerateDlpCertificate(result, cert);
    return DLP_OK;
}

void DlpPermissionAsyncStub::onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    if (generateDlpCertificateCallback_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return;
    }

    generateDlpCertificateCallback_->onGenerateDlpCertificate(result, cert);
}

int32_t DlpPermissionAsyncStub::onParseDlpCertificateStub(MessageParcel& data, MessageParcel& reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        PermissionPolicy policyNull;
        this->onParseDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, policyNull);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (result != DLP_OK) {
        PermissionPolicy policyNull;
        this->onParseDlpCertificate(result, policyNull);
        return DLP_OK;
    }
    sptr<DlpPolicyParcel> policyParcel = data.ReadParcelable<DlpPolicyParcel>();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read parcel fail");
        PermissionPolicy policyNull;
        this->onParseDlpCertificate(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, policyNull);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    this->onParseDlpCertificate(result, policyParcel->policyParams_);
    return DLP_OK;
}

void DlpPermissionAsyncStub::onParseDlpCertificate(int32_t result, const PermissionPolicy& policy)
{
    if (parseDlpCertificateCallback_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return;
    }

    parseDlpCertificateCallback_->onParseDlpCertificate(result, policy);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
