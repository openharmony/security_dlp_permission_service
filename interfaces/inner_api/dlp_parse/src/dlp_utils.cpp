/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlp_utils.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpUtils"};
static const std::string DLP_FILE_SUFFIXS = ".dlp";
static const std::string DEFAULT_STRINGS = "";
}

sptr<AppExecFwk::IBundleMgr> DlpUtils::GetBundleMgrProxy(void)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to get system ability manager");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Fail to connect bundle manager service.");
        return nullptr;
    }

    return iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
}

bool DlpUtils::GetWhitelistWithType(const std::string &cfgFile, const std::string &type,
    std::vector<std::string> &whitelist)
{
    std::string content;
    (void)FileOperator().GetFileContentByPath(cfgFile, content);
    if (content.empty()) {
        return false;
    }
    auto jsonObj = nlohmann::json::parse(content, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_WARN(LABEL, "JsonObj is discarded");
        return false;
    }
    auto result = jsonObj.find(type);
    if (result != jsonObj.end() && result->is_array() && !result->empty() && (*result)[0].is_string()) {
        whitelist = result->get<std::vector<std::string>>();
    }
    if (whitelist.size() != 0) {
        return true;
    }
    return false;
}

std::string DlpUtils::GetFileTypeBySuffix(const std::string& suffix)
{
    auto iter = FILE_TYPE_MAP.find(suffix);
    if (iter != FILE_TYPE_MAP.end()) {
        return iter->second;
    }
    return DEFAULT_STRINGS;
}

std::string DlpUtils::GetDlpFileRealSuffix(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIXS.size();
    std::string realFileName = dlpFileName.substr(0, dlpFileName.size() - dlpSuffixLen);
    char escape = '.';
    std::size_t escapeLocate = realFileName.find_last_of(escape);
    if (escapeLocate >= realFileName.size()) {
        DLP_LOG_ERROR(LABEL, "Get file suffix fail, no '.' in file name");
        return DEFAULT_STRINGS;
    }

    return realFileName.substr(escapeLocate + 1);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
