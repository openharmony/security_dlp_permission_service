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

#ifndef PERMISSION_MANAGER_ADAPTER_H
#define PERMISSION_MANAGER_ADAPTER_H

#include "permission_policy.h"
#include "access_token.h"
 
namespace OHOS {
namespace Security {
namespace DlpPermission {

class PermissionManagerAdapter {
public:
    static bool CheckPermission(const std::string& permission);
    static bool CheckPermissionAndGetAppId(std::string& appId);
    static int32_t CheckSandboxFlagWithService(AccessToken::AccessTokenID tokenId, bool& sandboxFlag);
    static bool GetAppIdentifierForCalling(std::string &appIdentifier);
    static int32_t CheckAuthPolicy(const std::string& appId, const std::string& realFileType);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // PERMISSION_MANAGER_ADAPTER_H
 