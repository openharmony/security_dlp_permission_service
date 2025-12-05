/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "napi_dlp_permission.h"
#include "napi_dlp_permission_tool.h"
#include <functional>
#include <string>
#include "accesstoken_kit.h"
#include "application_context.h"
#include "dlp_fuse_helper.h"
#include "dlp_file_kits.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "dlp_file_manager.h"
#include "dlp_file_operator.h"
#include "ipc_skeleton.h"
#include "js_native_api_types.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "permission_policy.h"
#include "securec.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "napi_dlp_connection_plugin.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS::Security::DlpConnection;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
static thread_local napi_ref dlpFileRef_;
}  // namespace

  bool NapiDlpPermissionTools::CheckPermission(napi_env env, const std::string& permission)
{
    Security::AccessToken::AccessTokenID selfToken = GetSelfTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(selfToken, permission);
    if (res == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        DLP_LOG_INFO(LABEL, "Check permission %{public}s pass", permission.c_str());
        return true;
    }
    DLP_LOG_ERROR(LABEL, "Check permission %{public}s fail", permission.c_str());
    int32_t jsErrCode = ERR_JS_PERMISSION_DENIED;
    NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode))), false);
    return false;
}

 napi_value NapiDlpPermissionTools::BindingJsWithNative(napi_env env, napi_value* argv, size_t argc)
{
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    if (napi_get_reference_value(env, dlpFileRef_, &constructor) != napi_ok) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "Get a reference to the global variable dlpFileRef_ complete");
    if (napi_new_instance(env, constructor, argc, argv, &instance) != napi_ok) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "New the js instance complete");
    return instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS