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

#include "dlp_permission_async_proxy.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_service_ipc_interface_code.h"
#include "dlp_policy_parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionAsyncProxy"};
}

void DlpPermissionAsyncProxy::OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionAsyncProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return;
    }
    if (!data.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return;
    }
    if (result == DLP_OK) {
        if (!data.WriteUInt8Vector(cert)) {
            DLP_LOG_ERROR(LABEL, "Write uint8 vector fail");
            return;
        }
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_GENERATE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", requestResult);
        return;
    }
}

void DlpPermissionAsyncProxy::OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
    const std::vector<uint8_t>& cert)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionAsyncProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return;
    }

    if (!data.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return;
    }

    if (result == DLP_OK) {
        DlpPolicyParcel policyParcel;
        policyParcel.policyParams_.CopyPermissionPolicy(policy);
        if (!data.WriteParcelable(&policyParcel)) {
            DLP_LOG_ERROR(LABEL, "Write parcel fail");
            return;
        }

        if (!data.WriteUInt8Vector(cert)) {
            DLP_LOG_ERROR(LABEL, "Write uint8 vector fail");
            return;
        }
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_PARSE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", requestResult);
        return;
    }
}

void DlpPermissionAsyncProxy::OnGetDlpWaterMark(int32_t result, const GeneralInfo& info)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionAsyncProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return;
    }
    if (!data.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return;
    }
    
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_GET_DLP_WATERMARK), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", requestResult);
        return;
    }
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
