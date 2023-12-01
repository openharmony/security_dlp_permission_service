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

#include "bundle_manager_adapter.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
    "BundleManagerAdapter" };
}
BundleManagerAdapter& BundleManagerAdapter::GetInstance()
{
    static BundleManagerAdapter instance;
    return instance;
}

BundleManagerAdapter::BundleManagerAdapter() :proxy_(nullptr)
{}

BundleManagerAdapter::~BundleManagerAdapter()
{}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    int32_t result = Connect();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "failed to connect bundle manager service.");
        return false;
    }
    return proxy_->GetBundleInfo(bundleName, flag, bundleInfo, userId);
}

int32_t BundleManagerAdapter::GetBundleInfoV9(const std::string &bundleName, AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    int32_t result = Connect();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "failed to connect bundle manager service.");
        return false;
    }
    return proxy_->GetBundleInfoV9(bundleName, flag, bundleInfo, userId);
}

int32_t BundleManagerAdapter::Connect()
{
    if (proxy_ != nullptr) {
        return DLP_OK;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to get system ability manager");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Fail to connect bundle manager service.");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    proxy_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    if (proxy_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to get bundle mgr service remote object");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }
    return DLP_OK;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS