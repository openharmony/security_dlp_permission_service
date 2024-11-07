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
#include <unistd.h>
#include "dlp_permission.h"
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
    return nullptr;
}

bool DlpUtils::GetAuthPolicyWithType(const std::string &cfgFile, const std::string &type,
    std::vector<std::string> &authPolicy)
{
    return false;
}

std::string DlpUtils::GetFileTypeBySuffix(const std::string& suffix)
{
    return "test.txt.dlp";
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

int32_t DlpUtils::GetFileNameWithFd(const int32_t &fd, std::string &srcFileName)
{
    srcFileName = "test.txt.dlp";
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
