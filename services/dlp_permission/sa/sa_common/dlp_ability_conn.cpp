/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_ability_conn.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpAbilityConnection" };
}

DlpAbilityConnection::DlpAbilityConnection(ConnectCallback connectCallback,
    DisconnectCallback disconnectCallback)
{
    if (connectCallback == nullptr) {
        DLP_LOG_ERROR(LABEL, "connectCallback is nullptr.");
    }
    if (disconnectCallback == nullptr) {
        DLP_LOG_ERROR(LABEL, "disconnectCallback is nullptr.");
    }
    connectCallback_ = connectCallback;
    disconnectCallback_ = disconnectCallback;
}

DlpAbilityConnection::~DlpAbilityConnection()
{
    connectCallback_ = nullptr;
    disconnectCallback_ = nullptr;
}

sptr<IRemoteObject> DlpAbilityConnection::GetProxy()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return remoteObj_;
}

void DlpAbilityConnection::ClearProxy()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    remoteObj_ = nullptr;
}

void DlpAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObj, int res)
{
    (void)res;
    if (remoteObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invaild Ability Connection.");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    remoteObj_ = remoteObj;
    DLP_LOG_INFO(LABEL, "Get Ability Connection.");
    if (connectCallback_ != nullptr) {
        connectCallback_(remoteObj_);
        return;
    }
    DLP_LOG_ERROR(LABEL, "connectCallback is nullptr.");
}

void DlpAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int res)
{
    (void)res;
    if (disconnectCallback_ != nullptr && isDestroyFlag_ == false) {
        disconnectCallback_(DDLP_HAP_DISCONN_ERROR, 0, nullptr, 0);
    } else {
        DLP_LOG_ERROR(LABEL, "disConnectCallback is nullptr or be destroyed.");
    }
    ClearProxy();
    DLP_LOG_INFO(LABEL, "Disconnect ability, DestroyFlag is %{public}d", isDestroyFlag_);
}

bool DlpAbilityConnection::IsConnected()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return remoteObj_ != nullptr;
}

void DlpAbilityConnection::SetIsDestroyFlag(bool flag)
{
    isDestroyFlag_ = flag;
    DLP_LOG_INFO(LABEL, "Set DestroyFlag to %{public}d", flag);
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
