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
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "dlp_permission_service_test.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;

static const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
static const std::string PERMISSION_ENTERPRISE_ACCESS_DLP_FILE = "ohos.permission.ENTERPRISE_ACCESS_DLP_FILE";
static const int32_t TWO = 2;

bool DlpPermissionServiceTest::isSandbox = true;
bool DlpPermissionServiceTest::isCheckSandbox = true;
int32_t DlpPermissionServiceTest::permType = 0;

bool PermissionManagerAdapter::CheckPermission(const std::string& permission)
{
    switch (DlpPermissionServiceTest::permType) {
        case -1:
            return false;
        case 0:
            return true;
        case 1:
            if (permission == PERMISSION_ACCESS_DLP_FILE) {
                return true;
            }
            return false;
        case TWO:
            if (permission == PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) {
                return true;
            }
            return false;
        default:
            break;
    }
    return true;
}

bool PermissionManagerAdapter::CheckPermissionAndGetAppId(std::string& appId)
{
    appId = "6917562860841254665";
    return true;
}

int32_t PermissionManagerAdapter::CheckSandboxFlagWithService(AccessToken::AccessTokenID tokenId, bool& sandboxFlag)
{
    if (!DlpPermissionServiceTest::isCheckSandbox) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    sandboxFlag = DlpPermissionServiceTest::isSandbox;
    return DLP_OK;
}

bool PermissionManagerAdapter::GetAppIdentifierForCalling(std::string &appIdentifier)
{
    appIdentifier = "1234567890";
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS