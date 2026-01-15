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

#include "dlp_ability_adapter.h"
#include <string>
#include <extension_manager_client.h>
#include "dlp_ability_proxy.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpAbilityAdapter" };
static const std::string BUNDLE_NAME = "com.huawei.hmos.dlpcredmgr";
static const std::string PERM_ABILITY_NAME = "DlpPermServiceAbility";
}

DlpAbilityAdapter::DlpAbilityAdapter(ReceiveDataCallback &callback)
{
    callback_ = callback;
}

int32_t DlpAbilityAdapter::ConnectPermServiceAbility(int32_t userId,
    std::function<void(sptr<IRemoteObject>)> connectCallback)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnection_ != nullptr && abilityConnection_->IsConnected()) {
        DLP_LOG_INFO(LABEL, "Connected Ability Before, get exist instance.");
        connectCallback(abilityConnection_->GetProxy());
        return DLP_OK;
    }

    AAFwk::Want want;
    want.SetElementName(BUNDLE_NAME, PERM_ABILITY_NAME);
    abilityConnection_ = new (std::nothrow) DlpAbilityConnection(connectCallback, callback_);
    if (abilityConnection_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Create AbilityConnection failed.");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t connect = AAFwk::ExtensionManagerClient::
        GetInstance().ConnectServiceExtensionAbility(want, abilityConnection_, userId);
    if (connect != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Connect Ability failed, errorCode = %{public}d", connect);
        abilityConnection_.clear();
        return DLP_ABILITY_CONNECT_ERROR;
    }
    return DLP_OK;
}

void DlpAbilityAdapter::DisconnectPermServiceAbility()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnection_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "AbilityConnection is nullptr.");
        return;
    }
    ErrCode disconnect = AAFwk::ExtensionManagerClient::
        GetInstance().DisconnectAbility(abilityConnection_);
    if (disconnect != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Disconnect Ability failed, errCode: %{public}d", disconnect);
    }
    if (abilityConnection_ != nullptr) {
        abilityConnection_.clear();
    }
    return;
}

int32_t DlpAbilityAdapter::HandleGetWaterMark(int32_t userId,
    WaterMarkInfo &waterMarkInfo, std::condition_variable &waterMarkInfoCv)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t res = ConnectPermServiceAbility(userId,
        [this, &waterMarkInfo, &waterMarkInfoCv](sptr<IRemoteObject> remoteObj) -> void {
        do {
            if (remoteObj == nullptr) {
                DLP_LOG_ERROR(LABEL, "ConnectCallback is nullptr.");
                break;
            }
            DlpAbilityProxy proxy(remoteObj);
            sptr<DlpAbilityStub> stub = DlpAbilityStub::GetInstance(callback_);
            if (stub == nullptr) {
                DLP_LOG_ERROR(LABEL, "DlpAbilityStub is nullptr.");
                break;
            }
            int32_t waterMarkFd = proxy.HandleGetWaterMark(stub);
            if (waterMarkFd < 0) {
                DLP_LOG_ERROR(LABEL, "HandleGetWaterMark failed, fd: %{public}d", waterMarkFd);
            }
            waterMarkInfo.waterMarkFd = waterMarkFd;
            DLP_LOG_DEBUG(LABEL, "Get watermark success.");
        } while (0);
        waterMarkInfoCv.notify_all();
        DisconnectPermServiceAbility();
        return;
    });
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL,
            "ConnectPermServiceAbility failed, errCode: %{public}d", res);
        waterMarkInfoCv.notify_all();
    }
    return res;
}

void DlpAbilityAdapter::SetIsDestroyFlag(bool flag)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnection_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "No any ability connection.");
        return;
    }
    abilityConnection_->SetIsDestroyFlag(flag);
}

DlpAbilityAdapter::~DlpAbilityAdapter()
{
    DisconnectPermServiceAbility();
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS