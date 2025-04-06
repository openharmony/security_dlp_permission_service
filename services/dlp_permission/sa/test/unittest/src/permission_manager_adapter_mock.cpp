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

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;

bool DlpPermissionServiceTest::isSandbox = true;

bool PermissionManagerAdapter::CheckPermission(const std::string& permission)
{
    return true;
}

int32_t PermissionManagerAdapter::CheckSandboxFlagWithService(AccessToken::AccessTokenID tokenId, bool& sandboxFlag)
{
    sandboxFlag = DlpPermissionServiceTest::isSandbox;
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS