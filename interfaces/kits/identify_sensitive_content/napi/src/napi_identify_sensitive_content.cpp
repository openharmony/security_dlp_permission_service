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

#include "napi_identify_sensitive_content.h"
#include "napi_dia_log_adapter.h"
#include "napi_dia_error_msg.h"
#include "napi_dia_common.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#ifdef FILE_IDENTIFY_ENABLE
#include "dia_fi_interface.h"
#endif

namespace OHOS::Security::DIA{
const std::string PERMISSION_ENTERPRISE_DATA_IDENTIFY_FILE = "ohos.permission.ENTERPRISE_DATA_IDENTIFY_FILE";

static bool CheckPermission(napi_env env, const std::string &permission)
{
    Security::AccessToken::AccessTokenID selfToken = GetSelfTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(selfToken, permission);
    if (res == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        LOG_INFO("check permission %{public}s pass", permission.c_str());
        return true;
    }
    LOG_ERROR("check permission %{public}s fail", permission.c_str());
    NAPI_CALL_BASE(env, napi_throw(env,
        GenerateBusinessError(env, ERR_DIA_JS_PERMISSION_DENIED, GetJsErrMsg(ERR_DIA_JS_PERMISSION_DENIED))), false);
    return false;
}

#ifdef FILE_IDENTIFY_ENABLE
static napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

bool ParseFileOperationContext(napi_value env, napi_callback_info info, ScanFileAsyncContext &asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_get_cb_info(env, info, &argc, &grgv, nullptr, nullptr);

    if (argc == ARG_SIZE_TWO) {
        if (!NapiParseString(env, asyncContext.filePath, argv[PARAM_ZERO])) {
            LOG_ERROR("parameter filePath error");
            return false;
        }
        if (!NapiParsePolicyArray(env, asyncContext.policies, argv[PARAM_ONE])) {
            LOG_ERROR("parameter policies error");
            return false;
        }
        return true;
    }
    LOG_ERROR("parameter number error");
    return false;
}

void NapiIdentifySensitiveFileExcute(napi_value env, void *data)
{
    LOG_INFO("NapiIdentifySensitiveFileExcute napi_create_async_work runing");
    auto scanFileAsyncContext = reinterpret_cast<ScanFileAsyncContext *>(data);
    if (!scanFileAsyncContext) {
        LOG_ERROR("scanFileAsyncContext is nullptr");
        return;
    }
    scanFileAsyncContext->errCode = IdentifySensitiveFile(
        scanFileAsyncContext->policies, scanFileAsyncContext->filePath, scanFileAsyncContext->matchResultList);
    return;
}

void NapiIdentifySensitiveFileComplete(napi_value env, napi_status status, void *data)
{
    LOG_INFO("NapiIdentifySensitiveFileExcute napi_create_async_work complete");
    auto scanFileAsyncContext = reinterpret_cast<ScanFileAsyncContext *>(data);
    if (!scanFileAsyncContext) {
        LOG_ERROR("scanFileAsyncContext is nullptr");
        return;
    }
    std::unique_ptr<ScanFileAsyncContext> asyncContextPtr {scanFileAsyncContext};
    int32_t errCode = NativeCodeToDIAJsCode(asyncContextPtr->errCode);
    napi_value result = nullptr;
    if (errCode == ERR_DIA_JS_SUCCESS) {
        result = NapiComposeMarchResultArray(env, asyncContextPtr->matchResultList);
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContextPtr->deferred, result));
    } else {
        LOG_ERROR("identify sensitive file error");
        result = GenerateBusinessError(env, errCode, GetDIAJsErrMsg(errCode));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContextPtr->deferred, result));
    }
}
#endif

napi_value NapiIdentifySensitiveContent::ScanFile(napi_env env, napi_callback_info info)
{
    if (!CheckPermission(env, PERMISSION_ENTERPRISE_DATA_IDENTIFY_FILE)) {
        return NapiGetNull(env);
    }
    napi_value result = nullptr;
#ifdef FILE_IDENTIFY_ENABLE
    LOG_INFO("scan file start");
    ScanFileAsyncContext *asyncContext = new (std::nothrow) ScanFileAsyncContext(env);
    if (!asyncContext) {
        LOG_ERROR("insufficient memory for asyncContext!");
        return;
    }
    std::unique_ptr<ScanFileAsyncContext> asyncContextPtr {asyncContext};
    if (!ParseFileOperationContext(env, info, *asyncContextPtr)) {
        LOG_ERROR("parse file operation context error!");
        DIANapiThrow(env, ERR_DIA_JS_PARAMETER_ERROR, GetDIAJsErrMsg(ERR_DIA_JS_PARAMETER_ERROR));
        return NapiGetNull(env);
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "ScanFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, NapiIdentifySensitiveFileExcute,
        NapiIdentifySensitiveFileComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
#else
    LOG_ERROR("capability not supported");
    DIANapiThrow(env, ERR_DIA_JS_CAPABILITY_NOT_SUPPORTED, GetDIAJsErrMsg(ERR_DIA_JS_CAPABILITY_NOT_SUPPORTED));
#endif
    return result;
}

napi_value NapiIdentifySensitiveContent::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("scanFile", NapiIdentifySensitiveContent::ScanFile);
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
} // namespace OHOS::Security::DIA
EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    return OHOS::Security::DIA::NapiIdentifySensitiveContent::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "identifySensitiveContent",
    .nm_priv = ((void*)0),
    .reserved = {0}};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void DlpPermissionModuleRegister(void)
{
    napi_module_register(&_module);
}