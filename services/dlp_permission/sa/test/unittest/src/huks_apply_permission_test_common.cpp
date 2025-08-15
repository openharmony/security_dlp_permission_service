/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "huks_apply_permission_test_common.h"

#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include <thread>
#include <iostream>

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "HuksApplyPermissionCommon" };
}

static constexpr uint32_t WAIT_FOR_ACCESS_TOKEN_START = 500;
#define AC_TKN_SVC "accesstoken_service"
#define SVC_CTRL "service_control"
static constexpr char PID_OF_ACCESS_TOKEN_SERVICE[] = "pidof " AC_TKN_SVC;
static constexpr char HUKS_SKIP_RESTART_ACCESS_TOKEN_SERVICE[] = "HUKS_SKIP_RESTART_ACCESS_TOKEN_SERVICE";

static void RestartAccessTokenService()
{
    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " stop " AC_TKN_SVC);

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " start " AC_TKN_SVC);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_ACCESS_TOKEN_START));

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);
}

int32_t SetIdsTokenForAcrossAccountsPermissionInner()
{
    uint64_t tokenId;
    const char *acls[] = {
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    const char *perms[] = {
        "ohos.permission.PLACE_CALL", // system_basic
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };
    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "test_across_local_account";
    tokenId = GetAccessTokenId(&infoInstance);
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "SetSelfTokenID fail, ret is %{public}d", ret);
        return ret;
    }
    ret = OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return ret;
}

int32_t SetIdsTokenForAcrossAccountsPermission()
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermissionInner();
    if (std::getenv(HUKS_SKIP_RESTART_ACCESS_TOKEN_SERVICE) != nullptr) {
        return ret;
    }
    RestartAccessTokenService();
    return SetIdsTokenForAcrossAccountsPermissionInner();
}