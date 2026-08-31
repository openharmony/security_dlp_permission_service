/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <string>
#include "dlp_permission_log.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "napi_dlp_permission_common.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
}  // namespace

bool NapiDlpPermission::ParseStartDLPManagerParams(napi_env env, napi_callback_info cbInfo,
    size_t &argc, napi_value *argv, napi_value &result)
{
    argc = PARAM_SIZE_THREE;
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_undefined(env, &result), false);
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc != PARAM_SIZE_TWO && argc != PARAM_SIZE_THREE) {
        DLP_LOG_ERROR(LABEL, "params number mismatch");
        return false;
    }
    return true;
}

napi_value NapiDlpPermission::StartDLPManagerForResult(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    DLP_LOG_INFO(LABEL, "begin StartDLPManagerForResult");
    size_t argc = 0;
    napi_value argv[PARAM3] = {nullptr};
    napi_value result = nullptr;
    if (!ParseStartDLPManagerParams(env, cbInfo, argc, argv, result)) {
        std::string errMsg = "Parameter Error. Params number mismatch, need 2 or 3, given " +
            std::to_string(argc);
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg);
        return nullptr;
    }

    auto asyncContext = std::make_shared<UIExtensionRequestContext>(env);
    if (argc == PARAM_SIZE_THREE) {
        // 3-param overload: context(common.Context), want, window
        // context only needs basic object validation, UIContent comes from window
        if (!ParseContextReq(env, argv[PARAM0], asyncContext->context)) {
            DLP_LOG_ERROR(LABEL, "ParseContextReq failed");
            DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "get context failed");
            return nullptr;
        }
    } else {
        // 2-param overload: context(common.UIAbilityContext), want
        if (!ParseUIAbilityContextReq(env, argv[PARAM0], asyncContext->context)) {
            DLP_LOG_ERROR(LABEL, "ParseUIAbilityContextReq failed");
            DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "get context failed");
            return nullptr;
        }
    }
    if (!ParseWantReq(env, argv[PARAM1], asyncContext->requestWant)) {
        DLP_LOG_ERROR(LABEL, "ParseWantReq failed");
        return nullptr;
    }

    if (argc == PARAM_SIZE_THREE) {
        // 3-param overload: context(common.Context), want, window
        if (!GetCustomShowingWindow(env, argv[PARAM2], asyncContext->window)) {
            DLP_LOG_ERROR(LABEL, "GetCustomShowingWindow failed");
            DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "get window failed");
            return nullptr;
        }
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
        StartUIExtensionAbilityWithWindow(asyncContext);
    } else {
        // 2-param overload: context(common.UIAbilityContext), want
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
        StartUIExtensionAbility(asyncContext);
    }
    DLP_LOG_DEBUG(LABEL, "end StartDLPManagerForResult");
    return result;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
