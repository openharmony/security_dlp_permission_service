/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DLP_PERMISSION_SERVICE_COMMON_H
#define DLP_PERMISSION_SERVICE_COMMON_H

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionService" };
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
const std::string PERMISSION_ENTERPRISE_ACCESS_DLP_FILE = "ohos.permission.ENTERPRISE_ACCESS_DLP_FILE";
inline constexpr const char* HIPREVIEW_HIGH = "com.huawei.hmos.hipreview";
inline constexpr const char* HIPREVIEW_LOW = "com.huawei.hmos.hipreviewext";
inline const std::string FOUNDATION_SERVICE_NAME = "foundation";
inline const std::string MDM_APPIDENTIFIER = "6917562860841254665";
inline const std::string DLP_ENABLE = "const.dlp.dlp_enable";
inline const std::string TRUE_VALUE = "true";
inline const std::string MDM_ENABLE_VALUE = "status";
inline const std::string MDM_BUNDLE_NAME = "appId";
constexpr uint32_t MAX_APPID_SIZE = 1024;
constexpr uint32_t MAX_URI_SIZE = 4095;

inline bool ValidateStringList(const std::vector<std::string>& stringList, const uint32_t maxLen)
{
    return std::all_of(stringList.begin(), stringList.end(),
        [maxLen](const std::string& strEle) { return strEle.size() < maxLen; });
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif // DLP_PERMISSION_SERVICE_COMMON_H
