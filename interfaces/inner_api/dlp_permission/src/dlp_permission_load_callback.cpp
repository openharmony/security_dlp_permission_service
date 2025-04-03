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

#include "dlp_permission_load_callback.h"
#include "dlp_permission_client.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionClient"};
static constexpr int32_t DLP_PERMISSION_SERVICE_SA_ID = 3521;
}  // namespace
DlpPermissionLoadCallback::DlpPermissionLoadCallback() {}

void DlpPermissionLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject)
{
    if (systemAbilityId != DLP_PERMISSION_SERVICE_SA_ID) {
        DLP_LOG_ERROR(LABEL, "start systemabilityId is not dlp_permission!");
        return;
    }

    if (remoteObject == nullptr) {
        DLP_LOG_ERROR(LABEL, "remoteObject is null.");
        DlpPermissionClient::GetInstance().FinishStartSAFail();
        return;
    }

    DLP_LOG_INFO(LABEL, "Start systemAbilityId: %{public}d success!", systemAbilityId);

    DlpPermissionClient::GetInstance().FinishStartSASuccess(remoteObject);
}

void DlpPermissionLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    if (systemAbilityId != DLP_PERMISSION_SERVICE_SA_ID) {
        DLP_LOG_ERROR(LABEL, "start systemabilityId is not dlp_permission!");
        return;
    }

    DLP_LOG_ERROR(LABEL, "Start systemAbilityId: %{public}d failed.", systemAbilityId);

    DlpPermissionClient::GetInstance().FinishStartSAFail();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS