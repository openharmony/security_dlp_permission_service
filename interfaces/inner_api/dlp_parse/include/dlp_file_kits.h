/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_DLP_FILE_KITS_H
#define INTERFACES_INNER_API_DLP_FILE_KITS_H
#include <cstdint>
#include <string>
#include "want.h"
#include "ability_info.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const std::string TAG_ACTION_VIEW = "ohos.want.action.viewData";
static const std::string TAG_ACTION_EDIT = "ohos.want.action.editData";

static const std::string TAG_KEY_FD = "keyFd";
static const std::string TAG_KEY_FD_TYPE = "type";
static const std::string TAG_KEY_FD_VALUE = "value";
static const std::string VALUE_KEY_FD_TYPE = "FD";
static const int INVALID_FD = -1;

static const std::string TAG_FILE_NAME = "fileName";
static const std::string TAG_FILE_NAME_VALUE = "name";
static const std::string DLP_FILE_SUFFIX = ".dlp";
static const std::string DEFAULT_STRING = "";

class DlpFileKits {
public:
    static bool GetSandboxFlag(AAFwk::Want &want);
    static bool IsDlpFile(int32_t dlpFd);
    static bool IsDlpFileBySuffix(const std::string &fileSuffix);
    static void ConvertAbilityInfoWithSupportDlp(AAFwk::Want& want,
        std::vector<AppExecFwk::AbilityInfo> &abilityInfos);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_KITS_H */
