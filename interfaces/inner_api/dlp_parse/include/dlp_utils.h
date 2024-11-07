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

#ifndef INTERFACES_INNER_API_DLP_UTILS_H
#define INTERFACES_INNER_API_DLP_UTILS_H

#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "file_operator.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

static const std::string DLP_AUTH_POLICY = "/system/etc/dlp_auth_policy.json";
static const std::string DLP_DEFAULT_AUTH_POLICY = "default";

static const std::unordered_map<std::string, std::string> FILE_TYPE_MAP = {
    {"txt", "support_txt_dlp"},
    {"pdf", "support_pdf_dlp"},
    {"doc", "support_office_dlp"},
    {"docx", "support_office_dlp"},
    {"ppt", "support_office_dlp"},
    {"pptx", "support_office_dlp"},
    {"xls", "support_office_dlp"},
    {"xlsx", "support_office_dlp"},
};

class DlpUtils {
public:
    static sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy(void);
    static bool GetAuthPolicyWithType(const std::string &cfgFile, const std::string &type,
        std::vector<std::string> &authPolicy);
    static std::string GetFileTypeBySuffix(const std::string& suffix);
    static std::string GetDlpFileRealSuffix(const std::string& dlpFileName);
    static int32_t GetFileNameWithFd(const int32_t &fd, std::string &srcFileName);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_UTILS_H */
