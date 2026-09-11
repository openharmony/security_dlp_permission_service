/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"
#include "js_native_api_types.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "napi_dlp_permission_common.h"
#include "permission_policy.h"
#include "securec.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "napi_dlp_connection_plugin.h"
#include "napi_dlp_transparent_enc.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

using namespace OHOS::Security::DlpConnection;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
static thread_local napi_ref dlpFileRef_;
const std::string DLP_FILE_CLASS_NAME = "dlpFile";
}  // namespace

napi_value NapiDlpPermission::GenerateDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GenerateDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
        return nullptr;
    }
    std::unique_ptr<GenerateDlpFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetGenerateDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GenerateDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GenerateDlpFileExcute, GenerateDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GenerateDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GenerateDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    if (context == nullptr) {
        DLP_LOG_ERROR(LABEL, "get application context is nullptr");
        return;
    }

    std::string workDir = context->GetFilesDir();
    if (workDir.empty() || access(workDir.c_str(), 0) != 0) {
        DLP_LOG_ERROR(LABEL, "path is null or workDir doesn't exist");
        return;
    }

    char realPath[PATH_MAX] = {0};
    if ((realpath(workDir.c_str(), realPath) == nullptr) && (errno != ENOENT)) {
        DLP_LOG_ERROR(LABEL, "realpath, %{public}s, workDir %{private}s", strerror(errno), workDir.c_str());
        return;
    }
    std::string rPath(realPath);

    asyncContext->errCode = DlpFileManager::GetInstance().GenerateDlpFile(
        asyncContext->plaintextFd, asyncContext->ciphertextFd, asyncContext->property,
        asyncContext->dlpFileNative, rPath);
}

void NapiDlpPermission::GenerateDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GenerateDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GenerateDlpFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        napi_value nativeObjJs;
        if (napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()),
            &nativeObjJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_create_int64 failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &resJs);
        } else {
            napi_value dlpPropertyJs = DlpPropertyToJs(env, asyncContext->property);
            napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
            napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO, dlpFileRef_);
            if (instance == nullptr) {
                DLP_LOG_ERROR(LABEL, "native instance binding fail");
                asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
                napi_get_undefined(env, &resJs);
            } else {
                resJs = instance;
            }
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::OpenDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetOpenDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "OpenDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, OpenDlpFileExcute, OpenDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::OpenDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    if (context == nullptr) {
        DLP_LOG_ERROR(LABEL, "get applicationContext fail");
        return;
    }

    std::string workDir = context->GetFilesDir();
    if (workDir.empty() || access(workDir.c_str(), 0) != 0) {
        DLP_LOG_ERROR(LABEL, "path is null or workDir doesn't exist");
        return;
    }

    char realPath[PATH_MAX] = {0};
    if (realpath(workDir.c_str(), realPath) == nullptr) {
        DLP_LOG_ERROR(LABEL, "realpath, %{public}s, workDir %{private}s", strerror(errno), workDir.c_str());
        return;
    }
    std::string rPath(realPath);
    asyncContext->errCode =
        DlpFileManager::GetInstance().OpenDlpFile(asyncContext->ciphertextFd, asyncContext->dlpFileNative, rPath,
            asyncContext->appId);
}

static napi_value HandleOpenDlpFileSuccess(napi_env env, DlpFileAsyncContext* asyncContext)
{
    if (asyncContext->dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext dlpFileNative is nullptr");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        return nullptr;
    }
    napi_value nativeObjJs;
    if (napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()),
        &nativeObjJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_create_int64 failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        return nullptr;
    }
    DlpProperty property;
    GetDlpProperty(asyncContext->dlpFileNative, property);
    napi_value dlpPropertyJs = DlpPropertyToJs(env, property);
    napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
    napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO, dlpFileRef_);
    if (instance == nullptr) {
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        return nullptr;
    }
    return instance;
}

static napi_value HandleOpenDlpFileError(napi_env env, DlpFileAsyncContext* asyncContext)
{
    if (asyncContext->dlpFileNative == nullptr) {
        return nullptr;
    }
    if (asyncContext->errCode != DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR &&
        asyncContext->errCode != DLP_CREDENTIAL_ERROR_TIME_EXPIRED) {
        return nullptr;
    }
    std::string contactAccount = "";
    asyncContext->dlpFileNative->GetContactAccount(contactAccount);
    if (contactAccount.empty()) {
        return nullptr;
    }
    napi_value resJs = nullptr;
    if (napi_create_string_utf8(env, contactAccount.c_str(), NAPI_AUTO_LENGTH, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_create_string_utf8 failed");
    }
    return resJs;
}

void NapiDlpPermission::OpenDlpFileComplete(napi_env env, napi_status status, void* data)
{
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        resJs = HandleOpenDlpFileSuccess(env, asyncContext);
    } else {
        resJs = HandleOpenDlpFileError(env, asyncContext);
    }
    if (resJs == nullptr) {
        napi_get_undefined(env, &resJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::IsDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetIsDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, IsDlpFileExcute, IsDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::IsDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->isDlpFile = DlpFileKits::IsDlpFile(asyncContext->ciphertextFd);
}

void NapiDlpPermission::IsDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr { asyncContext };

    napi_value isDlpFileJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        if (napi_get_boolean(env, asyncContext->isDlpFile, &isDlpFileJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_boolean failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &isDlpFileJs);
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, isDlpFileJs);
}

napi_value NapiDlpPermission::DlpFile(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value constructor = nullptr;

    if (napi_get_reference_value(env, dlpFileRef_, &constructor) != napi_ok) {
        return nullptr;
    }

    DLP_LOG_DEBUG(LABEL, "Get a reference to the global variable dlpFileRef_ complete");

    if (napi_new_instance(env, constructor, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    DLP_LOG_DEBUG(LABEL, "New the js instance complete");

    return instance;
}

bool NapiDlpPermission::IsSystemApp(napi_env env)
{
    uint64_t fullTokenId = IPCSkeleton::GetSelfTokenID();
    bool isSystemApp = AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    if (!isSystemApp) {
        int32_t jsErrCode = ERR_JS_NOT_SYSTEM_APP;
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode))), false);
        return false;
    }
    return true;
}

void NapiDlpPermission::InitFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("isDLPFile", IsDlpFile),
        DECLARE_NAPI_FUNCTION("getDLPPermissionInfo", GetDLPPermissionInfo),
        DECLARE_NAPI_FUNCTION("getDLPSuffix", GetDLPSuffix),
        DECLARE_NAPI_FUNCTION("getOriginalFileName", GetOriginalFileName),
        DECLARE_NAPI_FUNCTION("isInSandbox", IsInSandbox),
        DECLARE_NAPI_FUNCTION("getDlpSupportFileType", GetDlpSupportFileType),
        DECLARE_NAPI_FUNCTION("getDLPSupportedFileTypes", GetDlpSupportFileType),
        DECLARE_NAPI_FUNCTION("setRetentionState", SetRetentionState),
        DECLARE_NAPI_FUNCTION("cancelRetentionState", CancelRetentionState),
        DECLARE_NAPI_FUNCTION("getRetentionSandboxList", GetRetentionSandboxList),
        DECLARE_NAPI_FUNCTION("getDLPFileAccessRecords", GetDLPFileVisitRecord),
        DECLARE_NAPI_FUNCTION("startDLPManagerForResult", StartDLPManagerForResult),

        DECLARE_NAPI_FUNCTION("generateDLPFile", GenerateDlpFile),
        DECLARE_NAPI_FUNCTION("openDLPFile", OpenDlpFile),
        DECLARE_NAPI_FUNCTION("installDLPSandbox", InstallDlpSandbox),
        DECLARE_NAPI_FUNCTION("uninstallDLPSandbox", UninstallDlpSandbox),
        DECLARE_NAPI_FUNCTION("on", Subscribe),
        DECLARE_NAPI_FUNCTION("off", UnSubscribe),
        DECLARE_NAPI_FUNCTION("getDLPGatheringPolicy", GetDlpGatheringPolicy),
        DECLARE_NAPI_FUNCTION("setSandboxAppConfig", SetSandboxAppConfig),
        DECLARE_NAPI_FUNCTION("cleanSandboxAppConfig", CleanSandboxAppConfig),
        DECLARE_NAPI_FUNCTION("getSandboxAppConfig", GetSandboxAppConfig),
        DECLARE_NAPI_FUNCTION("isDLPFeatureProvided", IsDLPFeatureProvided),

        DECLARE_NAPI_FUNCTION("generateDlpFileForEnterprise", GenerateDlpFileForEnterprise),
        DECLARE_NAPI_FUNCTION("decryptDlpFile", DecryptDlpFile),
        DECLARE_NAPI_FUNCTION("queryDlpPolicy", QueryDlpPolicy),

        DECLARE_NAPI_FUNCTION("setEnterprisePolicy", SetEnterprisePolicy),

        DECLARE_NAPI_FUNCTION("closeOpenedEnterpriseDlpFiles", CloseOpenedEnterpriseDlpFiles),
        DECLARE_NAPI_FUNCTION("queryOpenedEnterpriseDlpFiles", QueryOpenedEnterpriseDlpFiles),
    };
    NAPI_CALL_RETURN_VOID(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[PARAM0]), desc));
}

napi_value NapiDlpPermission::Init(napi_env env, napi_value exports)
{
    InitFunction(env, exports);
    InitDlpConnectFunction(env, exports);
    InitDlpTransparentEncFunction(env, exports);
    napi_property_descriptor descriptor[] = {DECLARE_NAPI_FUNCTION("DLPFile", DlpFile)};
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addDLPLinkFile", AddDlpLinkFile),
        DECLARE_NAPI_FUNCTION("stopFuseLink", StopDlpLinkFile),
        DECLARE_NAPI_FUNCTION("resumeFuseLink", RestartDlpLinkFile),
        DECLARE_NAPI_FUNCTION("replaceDLPLinkFile", ReplaceDlpLinkFile),
        DECLARE_NAPI_FUNCTION("deleteDLPLinkFile", DeleteDlpLinkFile),
        DECLARE_NAPI_FUNCTION("recoverDLPFile", RecoverDlpFile),
        DECLARE_NAPI_FUNCTION("closeDLPFile", CloseDlpFile),
    };

    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, DLP_FILE_CLASS_NAME.c_str(), DLP_FILE_CLASS_NAME.size(), JsConstructor,
                       nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));

    NAPI_CALL(env, napi_create_reference(env, constructor, 1, &dlpFileRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, DLP_FILE_CLASS_NAME.c_str(), constructor));

    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("ActionFlagType", CreateEnumActionFlags(env)),
        DECLARE_NAPI_PROPERTY("DLPFileAccess", CreateEnumDLPFileAccess(env)),
        DECLARE_NAPI_PROPERTY("AccountType", CreateEnumAccountType(env)),
        DECLARE_NAPI_PROPERTY("GatheringPolicyType", CreateEnumGatheringPolicy(env)),
        DECLARE_NAPI_PROPERTY("ActionType", CreateEnumActionType(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);

    int32_t result = AccessToken::AccessTokenKit::VerifyAccessToken(GetSelfTokenID(),
        "ohos.permission.ACCESS_DLP_FILE", false);
    if (result == AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        DLP_LOG_INFO(LABEL, "Check dlp permission success, start init dlp link manager.");
        DlpPermission::DlpFuseHelper::GetDlpLinkManagerInstance();
    }
    return exports;
}

napi_value NapiDlpPermission::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr));
    int64_t nativeObjAddr;
    if (!GetInt64Value(env, argv[PARAM0], nativeObjAddr)) {
        return nullptr;
    }

    auto obj = reinterpret_cast<class DlpFile*>(nativeObjAddr);
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "obj is nullptr");
        return nullptr;
    }
    napi_status wrapStatus = napi_wrap(env, thisVar, obj,
        [](napi_env env, void* data, void* hint) {
            DLP_LOG_INFO(LABEL, "native obj destructed by js callback");
            return;
        },
        nullptr, nullptr);
    if (wrapStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Wrap js and native option failed");
    } else {
        DLP_LOG_INFO(LABEL, "native obj construct");
    }
    if (argc < PARAM_SIZE_TWO) {
        DLP_LOG_ERROR(LABEL, "property is null");
    }
    NAPI_CALL(env, napi_set_named_property(env, thisVar, "dlpProperty", argv[PARAM1]));
    return thisVar;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
