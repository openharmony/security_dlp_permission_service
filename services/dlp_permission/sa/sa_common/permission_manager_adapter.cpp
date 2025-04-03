/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "permission_manager_adapter.h"
#include "accesstoken_kit.h"
#include "dlp_dfx_define.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "bundle_manager_adapter.h"
#include "bundle_mgr_client.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "PermissionManagerAdapter" };
static const std::string CRED_HAP_IDENTIFIER = "5765880207854232861";
}
static int32_t GetOsAccountId(int32_t &osAccountId)
{
    using OHOS::AccountSA::OsAccountManager;
    std::vector<int32_t> ids;
    int32_t ret = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != OHOS::ERR_OK) {
        DLP_LOG_ERROR(LABEL, "Call QueryActiveOsAccountIds from OsAccountKits failed. ret:%{public}d.", ret);
        return DLP_HAP_ID_GET_ERROR;
    }
    if (ids.empty() || (ids.at(0) < 0)) {
        DLP_LOG_ERROR(LABEL, "The ids from OsAccountKits is invalid.");
        return DLP_HAP_ID_GET_ERROR;
    }
    osAccountId = ids.at(0);
    return DLP_OK;
}

static sptr<AppExecFwk::IBundleMgr> GetBundleMgrsa()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetBundleMgr GetSystemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetBundleMgr GetSystemAbility is null.");
        return nullptr;
    }

    return iface_cast<AppExecFwk::IBundleMgr>(bundleMgrSa);
}

static bool GetAppIdentifier(const std::string &bundleName, std::string &appIdentifier, int32_t userId)
{
    auto bundleMgr = GetBundleMgrsa();
    if (bundleMgr == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier cant get bundleMgr.");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int ret = bundleMgr->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier failed to get bundle info for %{public}s due to errCode %{public}d.",
            bundleName.c_str(), ret);
        return false;
    }
    if (bundleInfo.signatureInfo.appIdentifier.empty()) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier cant get appIdentifier.");
        return false;
    }
    appIdentifier = bundleInfo.signatureInfo.appIdentifier;
    return true;
}

static int32_t CheckPermissionForConnect(uint32_t callerTokenId)
{
    int32_t osAccountId = 0;
    int32_t ret = GetOsAccountId(osAccountId);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Failed to GetOsAccountId.");
        return ret;
    }

    HapTokenInfo hapTokenInfo;
    int32_t result = AccessTokenKit::GetHapTokenInfo(callerTokenId, hapTokenInfo);
    if (result != 0) {
        DLP_LOG_ERROR(LABEL, "Failed to GetHapTokenInfo.");
        return DLP_HAP_ID_GET_ERROR;
    }

    std::string appIdentifier;
    if (GetAppIdentifier(hapTokenInfo.bundleName, appIdentifier, osAccountId) == false) {
        DLP_LOG_ERROR(LABEL, "Failed to check appIdentifier.");
        return DLP_HAP_ID_GET_ERROR;
    }

    if (appIdentifier != CRED_HAP_IDENTIFIER) {
        DLP_LOG_ERROR(LABEL, "Failed to match appIdentifier.");
        return DLP_HAP_ID_GET_ERROR;
    }
    return DLP_OK;
}

bool PermissionManagerAdapter::CheckPermission(const std::string& permission)
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    if (CheckPermissionForConnect(callingToken) == DLP_OK) {
        DLP_LOG_INFO(LABEL, "Check permission %{public}s pass due to authenticated hap.", permission.c_str());
        return true;
    }
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

int32_t PermissionManagerAdapter::CheckSandboxFlagWithService(AccessToken::AccessTokenID tokenId, bool& sandboxFlag)
{
    int32_t res = AccessToken::AccessTokenKit::GetHapDlpFlag(tokenId);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Invalid tokenId");
        return res;
    }
    sandboxFlag = (res == 1);
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS