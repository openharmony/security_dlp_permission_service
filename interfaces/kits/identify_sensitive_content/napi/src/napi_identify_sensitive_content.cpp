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
#include <dlfcn.h>
#include "napi_dia_log_adapter.h"
#include "napi_dia_error_msg.h"
#include "napi_dia_common.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

namespace OHOS::Security::DIA {
const std::string PERMISSION_ENTERPRISE_DATA_IDENTIFY_FILE = "ohos.permission.ENTERPRISE_DATA_IDENTIFY_FILE";
#ifdef FILE_IDENTIFY_ENABLE
typedef int (*IdentifySensitiveFileFunction)(const PolicyC *policies, int policyLength, const DIA_String *filePath,
    MatchResultC **matchResults, int *matchResultLength);
typedef void (*ReleaseMatchResultListFunction)(MatchResultC **matchResults, int matchResultLength);
static void *g_diaCredentialSdkHandle = nullptr;
static int sdkCount = 0;
std::mutex g_lockDIACredSdk;
static const std::string DIA_SDK_PATH_64_BIT = "/system/lib64/platformsdk/libdia_sdk.z.so";
#endif

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
        GenerateBusinessError(env, ERR_DIA_JS_PERMISSION_DENIED, GetDIAJsErrMsg(ERR_DIA_JS_PERMISSION_DENIED))), false);
    return false;
}

static napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

#ifdef FILE_IDENTIFY_ENABLE
static void *GetDIACredSdkLibFunc(const char *funcName)
{
    LOG_INFO("start GetDIACredSdkLibFunc.");
    std::lock_guard<std::mutex> lock(g_lockDIACredSdk);
    if (g_diaCredentialSdkHandle == nullptr) {
        g_diaCredentialSdkHandle = dlopen(DIA_SDK_PATH_64_BIT.c_str(), RTLD_LAZY);
        if (g_diaCredentialSdkHandle == nullptr) {
            LOG_ERROR("dlopen file");
            return nullptr;
        }
    }
    sdkCount++;
    void *func = dlsym(g_diaCredentialSdkHandle, funcName);
    return func;
}

static void *GetDIASdkLibFunc(const char *funcName)
{
    LOG_INFO("start GetDIASdkLibFunc.");
    std::lock_guard<std::mutex> lock(g_lockDIACredSdk);
    if (g_diaCredentialSdkHandle) {
        return dlsym(g_diaCredentialSdkHandle, funcName);
    }
    return nullptr;
}

static void DestroyDIACredentialSdk()
{
    LOG_INFO("start DestroyDIACredentialSdk.");
    std::lock_guard<std::mutex> lock(g_lockDIACredSdk);
    sdkCount--;
    if (g_diaCredentialSdkHandle != nullptr && !sdkCount) {
        dlclose(g_diaCredentialSdkHandle);
        g_diaCredentialSdkHandle = nullptr;
        LOG_INFO("dlclose diaSdk end.");
    }
}

bool ParseFileOperationContext(napi_env env, napi_callback_info info, ScanFileAsyncContext &asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

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

int PoliciesToPolicyC(std::vector<PolicyC> &policyCTmp, ScanFileAsyncContext *scanFileAsyncContext)
{
    int ret = DIA_SUCCESS;
    for (size_t i = 0; i < scanFileAsyncContext->policies.size(); i++) {
        // sensitiveLabel
        policyCTmp[i].sensitiveLabel.data =
            const_cast<char *>(scanFileAsyncContext->policies[i].sensitiveLabel.c_str());
        policyCTmp[i].sensitiveLabel.dataLength = scanFileAsyncContext->policies[i].sensitiveLabel.length();
        // keyword;
        size_t keywordsVecSize = scanFileAsyncContext->policies[i].keywords.size();
        policyCTmp[i].keywords = new (std::nothrow) DIA_String[keywordsVecSize];
        if (!policyCTmp[i].keywords) {
            LOG_ERROR("new keywords error");
            ret = DIA_ERR_MALLOC;
            break;
        }
        policyCTmp[i].keywordsLength = keywordsVecSize;
        for (size_t j = 0; j < keywordsVecSize; j++) {
            policyCTmp[i].keywords[j].data = const_cast<char *>(scanFileAsyncContext->policies[i].keywords[j].c_str());
            policyCTmp[i].keywords[j].dataLength = scanFileAsyncContext->policies[i].keywords[j].length();
        }
        // regex
        policyCTmp[i].regex.data = const_cast<char *>(scanFileAsyncContext->policies[i].regex.c_str());
        policyCTmp[i].regex.dataLength = scanFileAsyncContext->policies[i].regex.length();
    }
    return ret;
}

void DestroyPolicyC(std::vector<PolicyC> &policyCTmp)
{
    for (size_t i = 0; i < policyCTmp.size(); i++) {
        if (policyCTmp[i].keywords) {
            delete[] policyCTmp[i].keywords;
            policyCTmp[i].keywords = nullptr;
        }
    }
}

void NapiIdentifySensitiveFileExcute(napi_env env, void *data)
{
    LOG_INFO("NapiIdentifySensitiveFileExcute napi_create_async_work runing");
    auto scanFileAsyncContext = reinterpret_cast<ScanFileAsyncContext *>(data);
    if (!scanFileAsyncContext) {
        LOG_ERROR("scanFileAsyncContext is nullptr");
        return;
    }
    //dlopen
    IdentifySensitiveFileFunction identifySensitiveFileFunction =
        reinterpret_cast<IdentifySensitiveFileFunction>(GetDIACredSdkLibFunc("IdentifySensitiveFileC"));
    if (!identifySensitiveFileFunction) {
        LOG_ERROR("identifySensitiveFileFunction is nullptr.");
        DestroyDIACredentialSdk();
        scanFileAsyncContext->errCode = ERR_DIA_JS_SYSTEM_SERVICE_EXCEPTION;
        return;
    }
    std::vector<PolicyC> policyCTmp(scanFileAsyncContext->policies.size());
    if (PoliciesToPolicyC(policyCTmp, scanFileAsyncContext) != DIA_SUCCESS) {
        LOG_ERROR("PoliciesToPolicyC error.");
        DestroyDIACredentialSdk();
        DestroyPolicyC(policyCTmp);
        return;
    }
    DIA_String filePathTmp;
    filePathTmp.data = const_cast<char *>(scanFileAsyncContext->filePath.c_str());
    filePathTmp.dataLength = scanFileAsyncContext->filePath.length();
    MatchResultC *matchResults = nullptr;
    int matchResultLength = 0;
    scanFileAsyncContext->errCode = (*identifySensitiveFileFunction)(
        policyTmp.data(), policyTmp.size(), &filePathTmp, &matchResults, &matchResultLength);
    DestroyPolicyC(policyTmp);
    if (matchResults) {
        for (int i = 0; i < matchResultLength; i++) {
            MatchResult matchResult;
            matchResult.sensitiveLabel =
                std::string(matchResults[i].sensitiveLabel.data, matchResults[i].sensitiveLabel.dataLength);
            matchResult.matchContent =
                std::string(matchResults[i].matchContent.data, matchResults[i].matchContent.dataLength);
            matchResult.matchNumber = matchResults[i].matchNumber;
            scanFileAsyncContext->matchResultList.push_back(matchResult);
        }
        ReleaseMatchResultListFunction releaseMatchResultListFunction =
            reinterpret_cast<ReleaseMatchResultListFunction>(GetDIASdkLibFunc("ReleaseMatchResultList"));
        if (releaseMatchResultListFunction) {
            (*releaseMatchResultListFunction)(&matchResults, matchResultLength);
        }
    }
    DestroyDIACredentialSdk();
    return;
}

void NapiIdentifySensitiveFileComplete(napi_env env, napi_status status, void *data)
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
        result = NapiComposeMatchResultArray(env, asyncContextPtr->matchResultList);
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
        return NapiGetNull(env);
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
        DECLARE_NAPI_FUNCTION("scanFile", NapiIdentifySensitiveContent::ScanFile),
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
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "security.identifySensitiveContent",
    .nm_priv = ((void*)0),
    .reserved = {0}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void IdentifySensitiveContentModuleRegister(void)
{
    napi_module_register(&_module);
}