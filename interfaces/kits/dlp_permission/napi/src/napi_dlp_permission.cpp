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

#include "napi_dlp_permission.h"
#include <functional>
#include <string>
#include "accesstoken_kit.h"
#include "application_context.h"
#include "dlp_file_kits.h"
#include "dlp_link_manager.h"
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
#include "permission_policy.h"
#include "securec.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
std::mutex g_lockForOpenDlpFileSubscriber;
std::set<OpenDlpFileSubscriberContext*> g_openDlpFileSubscribers;
RegisterDlpSandboxChangeInfo *g_dlpSandboxChangeInfoRegister = nullptr;
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
}  // namespace

static bool CheckPermission(napi_env env, const std::string& permission)
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

static napi_value BindingJsWithNative(napi_env env, napi_value* argv, size_t argc)
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

napi_value NapiDlpPermission::GenerateDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GenerateDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
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
        NAPI_CALL_RETURN_VOID(
            env, napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()), &nativeObjJs));

        napi_value dlpPropertyJs = DlpPropertyToJs(env, asyncContext->property);
        napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
        napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO);
        if (instance == nullptr) {
            DLP_LOG_ERROR(LABEL, "native instance binding fail");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        } else {
            resJs = instance;
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::OpenDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
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

static void GetDlpProperty(std::shared_ptr<DlpFile>& dlpFileNative, DlpProperty& property)
{
    PermissionPolicy policy;
    dlpFileNative->GetPolicy(policy);
    std::string contactAccount;
    dlpFileNative->GetContactAccount(contactAccount);
    property = {
        .ownerAccount = policy.ownerAccount_,
        .ownerAccountId = policy.ownerAccountId_,
        .authUsers = policy.authUsers_,
        .contactAccount = contactAccount,
        .ownerAccountType = policy.ownerAccountType_,
        .offlineAccess = dlpFileNative->GetOfflineAccess(),
        .supportEveryone = policy.supportEveryone_,
        .everyonePerm = policy.everyonePerm_,
        .expireTime = policy.expireTime_,
    };
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
        napi_value nativeObjJs;
        if (asyncContext->dlpFileNative == nullptr) {
            DLP_LOG_ERROR(LABEL, "asyncContext dlpFileNative is nullptr");
            return;
        }
        NAPI_CALL_RETURN_VOID(
            env, napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()), &nativeObjJs));
        DlpProperty property;
        GetDlpProperty(asyncContext->dlpFileNative, property);
        napi_value dlpPropertyJs = DlpPropertyToJs(env, property);
        napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
        napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO);
        if (instance == nullptr) {
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        } else {
            resJs = instance;
        }
    } else {
        if (asyncContext->dlpFileNative != nullptr &&
            (asyncContext->errCode == DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR ||
            asyncContext->errCode == DLP_CREDENTIAL_ERROR_TIME_EXPIRED)) {
            std::string contactAccount = "";
            asyncContext->dlpFileNative->GetContactAccount(contactAccount);
            if (!contactAccount.empty()) {
                NAPI_CALL_RETURN_VOID(
                    env, napi_create_string_utf8(env, contactAccount.c_str(), NAPI_AUTO_LENGTH, &resJs));
            }
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::IsDlpFile(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
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
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->isDlpFile, &isDlpFileJs));
    }

    ProcessCallbackOrPromise(env, asyncContext, isDlpFileJs);
}

napi_value NapiDlpPermission::AddDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "AddDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AddDlpLinkFileExcute, AddDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::AddDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().AddDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::AddDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::StopDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetLinkFileStatusParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "StopDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, StopDlpLinkFileExcute, StopDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::StopDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpLinkManager::GetInstance().StopDlpLinkFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::StopDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RestartDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetLinkFileStatusParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "RestartDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, RestartDlpLinkFileExcute, RestartDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::RestartDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpLinkManager::GetInstance().RestartDlpLinkFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::RestartDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::ReplaceDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "ReplaceDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, ReplaceDlpLinkFileExcute, ReplaceDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::ReplaceDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().ReplaceDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::ReplaceDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, DeleteDlpLinkFileExcute, DeleteDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::DeleteDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpLinkManager::GetInstance().DeleteDlpLinkFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::DeleteDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RecoverDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) RecoverDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<RecoverDlpFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetRecoverDlpFileParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "RecoverDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, RecoverDlpFileExcute, RecoverDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::RecoverDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<RecoverDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpFileManager::GetInstance().RecoverDlpFile(asyncContext->dlpFileNative, asyncContext->plaintextFd);
}

void NapiDlpPermission::RecoverDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<RecoverDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<RecoverDlpFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CloseDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) CloseDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<CloseDlpFileAsyncContext> asyncContextPtr { asyncContext };

    if (!GetCloseDlpFileParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "CloseDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CloseDlpFileExcute, CloseDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::CloseDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<CloseDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpFileManager::GetInstance().CloseDlpFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::CloseDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<CloseDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<CloseDlpFileAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::InstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr { asyncContext };

    if (!GetInstallDlpSandboxParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "InstallDlpSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, InstallDlpSandboxExcute, InstallDlpSandboxComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::InstallDlpSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::InstallDlpSandbox(asyncContext->bundleName, asyncContext->dlpFileAccess,
        asyncContext->userId, asyncContext->sandboxInfo, asyncContext->uri);
}

void NapiDlpPermission::InstallDlpSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr { asyncContext };
    napi_value sandboxInfoJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        sandboxInfoJs = SandboxInfoToJs(env, asyncContext->sandboxInfo);
    }
    ProcessCallbackOrPromise(env, asyncContext, sandboxInfoJs);
}

napi_value NapiDlpPermission::UninstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr { asyncContext };

    if (!GetUninstallDlpSandboxParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "UninstallDlpSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, UninstallDlpSandboxExcute,
        UninstallDlpSandboxComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::UninstallDlpSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::UninstallDlpSandbox(
        asyncContext->bundleName, asyncContext->sandboxInfo.appIndex, asyncContext->userId);
}

void NapiDlpPermission::UninstallDlpSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetDLPPermissionInfo(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) GetPermInfoAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetPermInfoAsyncContext> asyncContextPtr { asyncContext };

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDLPPermissionInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetDLPPermissionInfoExcute,
        GetDLPPermissionInfoComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetDLPPermissionInfoExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetPermInfoAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::QueryDlpFileAccess(asyncContext->permInfo);
}

void NapiDlpPermission::GetDLPPermissionInfoComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetPermInfoAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GetPermInfoAsyncContext> asyncContextPtr { asyncContext };
    napi_value permInfoJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        permInfoJs = DlpPermissionInfoToJs(env, asyncContext->permInfo);
    }
    ProcessCallbackOrPromise(env, asyncContext, permInfoJs);
}

napi_value NapiDlpPermission::IsInSandbox(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) IsInSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<IsInSandboxAsyncContext> asyncContextPtr { asyncContext };

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "IsInSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, IsInSandboxExcute, IsInSandboxComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::IsInSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<IsInSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::IsInDlpSandbox(asyncContext->inSandbox);
}

void NapiDlpPermission::IsInSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<IsInSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<IsInSandboxAsyncContext> asyncContextPtr { asyncContext };
    napi_value inSandboxJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->inSandbox, &inSandboxJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, inSandboxJs);
}

napi_value NapiDlpPermission::GetDlpSupportFileType(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) GetDlpSupportFileTypeAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetDlpSupportFileTypeAsyncContext> asyncContextPtr { asyncContext };

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDlpSupportFileType", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetDlpSupportFileTypeExcute,
        GetDlpSupportFileTypeComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetDlpSupportFileTypeExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetDlpSupportFileTypeAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::GetDlpSupportFileType(asyncContext->supportFileType);
}

void NapiDlpPermission::GetDlpSupportFileTypeComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetDlpSupportFileTypeAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GetDlpSupportFileTypeAsyncContext> asyncContextPtr { asyncContext };
    napi_value supportFileTypeJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        supportFileTypeJs = VectorStringToJs(env, asyncContext->supportFileType);
    }
    ProcessCallbackOrPromise(env, asyncContext, supportFileTypeJs);
}

napi_value NapiDlpPermission::RegisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    RegisterDlpSandboxChangeInfo *registerDlpSandboxChangeInfo = new (std::nothrow) RegisterDlpSandboxChangeInfo();
    if (registerDlpSandboxChangeInfo == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<RegisterDlpSandboxChangeInfo> callbackPtr { registerDlpSandboxChangeInfo };
    if (!ParseInputToRegister(env, cbInfo, *registerDlpSandboxChangeInfo)) {
        return nullptr;
    }
    int32_t result = DlpPermissionKit::RegisterDlpSandboxChangeCallback(registerDlpSandboxChangeInfo->subscriber);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RegisterSandboxChangeCallback failed");
        DlpNapiThrow(env, result);
        return nullptr;
    }
    if (g_dlpSandboxChangeInfoRegister != nullptr) {
        delete g_dlpSandboxChangeInfoRegister;
        g_dlpSandboxChangeInfoRegister = nullptr;
    }
    g_dlpSandboxChangeInfoRegister = callbackPtr.release();
    return nullptr;
}

napi_value NapiDlpPermission::UnregisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    auto *asyncContext = new (std::nothrow) UnregisterSandboxChangeCallbackAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<UnregisterSandboxChangeCallbackAsyncContext> asyncContextPtr { asyncContext };
    if (!GetUnregisterSandboxParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    int32_t result = DlpPermissionKit::UnregisterDlpSandboxChangeCallback(asyncContext->result);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "UnregisterSandboxChangeCallback failed");
        DlpNapiThrow(env, result);
        return nullptr;
    }
    if (g_dlpSandboxChangeInfoRegister != nullptr) {
        delete g_dlpSandboxChangeInfoRegister;
        g_dlpSandboxChangeInfoRegister = nullptr;
    }
    return nullptr;
}

bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef)
{
    napi_value subscriberCallback;
    napi_get_reference_value(env, subscriberRef, &subscriberCallback);
    napi_value unsubscriberCallback;
    napi_get_reference_value(env, unsubscriberRef, &unsubscriberCallback);
    bool result = false;
    napi_strict_equals(env, subscriberCallback, unsubscriberCallback, &result);
    return result;
}

static bool IsSubscribeExist(napi_env env, OpenDlpFileSubscriberContext* subscribeCBInfo)
{
    return std::any_of(g_openDlpFileSubscribers.begin(), g_openDlpFileSubscribers.end(),
        [env, subscribeCBInfo](const auto& it) {
            return CompareOnAndOffRef(env, it->callbackRef, subscribeCBInfo->callbackRef);
        });
}

napi_value NapiDlpPermission::SubscribeOpenDlpFile(const napi_env env, const napi_value thisVar, napi_ref& callback)
{
    DLP_LOG_INFO(LABEL, "Subscribe open dlp file");
    OpenDlpFileSubscriberContext* syncContext = new (std::nothrow) OpenDlpFileSubscriberContext();
    if (syncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for syncContext!");
        return nullptr;
    }
    std::unique_ptr<OpenDlpFileSubscriberContext> syncContextPtr { syncContext };
    syncContextPtr->env = env;
    syncContextPtr->callbackRef = callback;
    syncContextPtr->subscriber = std::make_shared<OpenDlpFileSubscriberPtr>();
    syncContextPtr->subscriber->SetEnv(env);
    syncContextPtr->subscriber->SetCallbackRef(callback);
    std::shared_ptr<OpenDlpFileSubscriberPtr>* subscriber =
        new (std::nothrow) std::shared_ptr<OpenDlpFileSubscriberPtr>(syncContextPtr->subscriber);
    if (subscriber == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to create subscriber");
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_lockForOpenDlpFileSubscriber);
    if (IsSubscribeExist(env, syncContext)) {
        DLP_LOG_ERROR(LABEL, "Subscribe failed. The current subscriber has been existed");
        delete subscriber;
        return nullptr;
    }
    int32_t result = DlpPermissionKit::RegisterOpenDlpFileCallback(syncContextPtr->subscriber);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RegisterSandboxChangeCallback failed");
        delete subscriber;
        DlpNapiThrow(env, result);
        return nullptr;
    }
    napi_wrap(
        env, thisVar, reinterpret_cast<void*>(subscriber),
        [](napi_env nev, void* data, void* hint) {
            DLP_LOG_INFO(LABEL, "OpenDlpFileSubscriberPtr delete");
            std::shared_ptr<OpenDlpFileSubscriberPtr>* subscriber =
                static_cast<std::shared_ptr<OpenDlpFileSubscriberPtr>*>(data);
            if (subscriber != nullptr && *subscriber != nullptr) {
                (*subscriber)->SetValid(false);
                delete subscriber;
            }
        },
        nullptr, nullptr);
    g_openDlpFileSubscribers.emplace(syncContext);
    DLP_LOG_INFO(LABEL, "Subscribe open dlp file success");
    syncContextPtr.release();
    return nullptr;
}

napi_value NapiDlpPermission::Subscribe(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr));
    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO + 1)) {
        return nullptr;
    }
    std::string type;
    if (!GetStringValue(env, argv[PARAM0], type)) {
        DLP_LOG_ERROR(LABEL, "event type is invalid");
        ThrowParamError(env, "type", "string");
        return nullptr;
    }
    napi_ref callback = nullptr;
    if (!ParseCallback(env, argv[PARAM1], callback)) {
        DLP_LOG_ERROR(LABEL, "event listener is invalid");
        ThrowParamError(env, "listener", "function");
        return nullptr;
    }

    if (type == "openDLPFile") {
        return SubscribeOpenDlpFile(env, thisVar, callback);
    } else if (type == "uninstallDLPSandbox") {
        return RegisterSandboxChangeCallback(env, cbInfo);
    } else {
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, "event type is wrong")));
        return nullptr;
    }
}

napi_value NapiDlpPermission::UnSubscribeOpenDlpFile(const napi_env env, napi_ref& callback)
{
    OpenDlpFileUnSubscriberContext* syncContext = new (std::nothrow) OpenDlpFileUnSubscriberContext(env);
    if (syncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for syncContext!");
        return nullptr;
    }
    std::unique_ptr<OpenDlpFileUnSubscriberContext> syncContextPtr { syncContext };
    std::lock_guard<std::mutex> lock(g_lockForOpenDlpFileSubscriber);
    if (callback == nullptr) {
        auto iter = g_openDlpFileSubscribers.begin();
        while (iter != g_openDlpFileSubscribers.end()) {
            int32_t result = DlpPermissionKit::UnRegisterOpenDlpFileCallback((*iter)->subscriber);
            if (result != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "UnSubscribeOpenDlpFile failed");
                DlpNapiThrow(env, result);
                return nullptr;
            }
            delete *iter;
            iter = g_openDlpFileSubscribers.erase(iter);
        }
    } else {
        auto iter = g_openDlpFileSubscribers.begin();
        while (iter != g_openDlpFileSubscribers.end()) {
            if (!CompareOnAndOffRef(env, (*iter)->callbackRef, callback)) {
                iter++;
                continue;
            }
            int32_t result = DlpPermissionKit::UnRegisterOpenDlpFileCallback((*iter)->subscriber);
            if (result != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "UnSubscribeOpenDlpFile failed");
                DlpNapiThrow(env, result);
                return nullptr;
            }
            delete *iter;
            g_openDlpFileSubscribers.erase(iter);
            break;
        }
    }
    syncContextPtr.release();
    return nullptr;
}

napi_value NapiDlpPermission::UnSubscribe(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr));
    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return nullptr;
    }
    std::string type;
    if (!GetStringValue(env, argv[PARAM0], type)) {
        DLP_LOG_ERROR(LABEL, "event type is invalid");
        ThrowParamError(env, "type", "string");
        return nullptr;
    }
    napi_ref callback = nullptr;
    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], callback)) {
            DLP_LOG_ERROR(LABEL, "event listener is invalid");
            ThrowParamError(env, "listener", "function");
            return nullptr;
        }
    }

    if (type == "openDLPFile") {
        return UnSubscribeOpenDlpFile(env, callback);
    } else if (type == "uninstallDLPSandbox") {
        return UnregisterSandboxChangeCallback(env, cbInfo);
    } else {
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, "event type is wrong")));
        return nullptr;
    }
}

napi_value NapiDlpPermission::GetDlpGatheringPolicy(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) GetGatheringPolicyContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetGatheringPolicyContext> asyncContextPtr { asyncContext };

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDlpGatheringPolicy", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetDlpGatheringPolicyExcute,
        GetDlpGatheringPolicyComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetDlpGatheringPolicyExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetGatheringPolicyContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::GetDlpGatheringPolicy(asyncContext->isGathering);
}

void NapiDlpPermission::GetDlpGatheringPolicyComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetGatheringPolicyContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GetGatheringPolicyContext> asyncContextPtr { asyncContext };
    napi_value isGatheringJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GatheringPolicyType policy = asyncContext->isGathering ? GATHERING : NON_GATHERING;
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, policy, &isGatheringJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, isGatheringJs);
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

napi_value NapiDlpPermission::SetRetentionState(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) RetentionStateAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<RetentionStateAsyncContext> asyncContextPtr { asyncContext };

    if (!GetRetentionStateParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "SetRetentionState", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, SetRetentionStateExcute, SetRetentionStateComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::SetRetentionStateExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<RetentionStateAsyncContext*>(data);
    asyncContext->errCode = DlpPermissionKit::SetRetentionState(asyncContext->docUris);
}

void NapiDlpPermission::SetRetentionStateComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<RetentionStateAsyncContext*>(data);
    std::unique_ptr<RetentionStateAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CancelRetentionState(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) RetentionStateAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<RetentionStateAsyncContext> asyncContextPtr { asyncContext };

    if (!GetRetentionStateParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "CancelRetentionState", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CancelRetentionStateExcute,
        CancelRetentionStateComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::CancelRetentionStateExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<RetentionStateAsyncContext*>(data);
    asyncContext->errCode = DlpPermissionKit::CancelRetentionState(asyncContext->docUris);
}

void NapiDlpPermission::CancelRetentionStateComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<RetentionStateAsyncContext*>(data);
    std::unique_ptr<RetentionStateAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetRetentionSandboxList(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto* asyncContext = new (std::nothrow) GetRetentionSandboxListAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetRetentionSandboxListAsyncContext> asyncContextPtr { asyncContext };

    if (!GetRetentionSandboxListParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "GetRetentionSandboxList", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetRetentionSandboxListExcute,
        GetRetentionSandboxListComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetRetentionSandboxListExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetRetentionSandboxListAsyncContext*>(data);
    asyncContext->errCode =
        DlpPermissionKit::GetRetentionSandboxList(asyncContext->bundleName, asyncContext->retentionSandBoxInfoVec);
}

void NapiDlpPermission::GetRetentionSandboxListComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetRetentionSandboxListAsyncContext*>(data);
    std::unique_ptr<GetRetentionSandboxListAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        resJs = RetentionSandboxInfoToJs(env, asyncContext->retentionSandBoxInfoVec);
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetDLPFileVisitRecord(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto* asyncContext = new (std::nothrow) GetDLPFileVisitRecordAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetDLPFileVisitRecordAsyncContext> asyncContextPtr { asyncContext };

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDLPFileVisitRecord", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetDLPFileVisitRecordExcute,
        GetDLPFileVisitRecordComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetDLPFileVisitRecordExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetDLPFileVisitRecordAsyncContext*>(data);
    asyncContext->errCode = DlpPermissionKit::GetDLPFileVisitRecord(asyncContext->visitedDlpFileInfoVec);
}

void NapiDlpPermission::GetDLPFileVisitRecordComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetDLPFileVisitRecordAsyncContext*>(data);
    std::unique_ptr<GetDLPFileVisitRecordAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        resJs = VisitInfoToJs(env, asyncContext->visitedDlpFileInfoVec);
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::SetSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work SetSandboxAppConfig running");
    auto asyncContextPtr = std::make_unique<SandboxAppConfigAsyncContext>(env);
    if (!GetSandboxAppConfigParams(env, cbInfo, asyncContextPtr.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetSandboxAppConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, SetSandboxAppConfigExecute,
        SetSandboxAppConfigComplete, static_cast<void*>(asyncContextPtr.get()), &(asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextPtr->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::SetSandboxAppConfigExecute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work SetSandboxAppConfigExecute running");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::SetSandboxAppConfig(asyncContext->configInfo);
}

void NapiDlpPermission::SetSandboxAppConfigComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work SetSandboxAppConfig complete");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<SandboxAppConfigAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CleanSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContextPtr = std::make_unique<SandboxAppConfigAsyncContext>(env);
    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CleanSandboxAppConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CleanSandboxAppConfigExecute,
        CleanSandboxAppConfigComplete, static_cast<void*>(asyncContextPtr.get()), &(asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextPtr->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::CleanSandboxAppConfigExecute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work CleanSandboxAppConfigExecute running");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::CleanSandboxAppConfig();
}

void NapiDlpPermission::CleanSandboxAppConfigComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work CleanSandboxAppConfig complete");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<SandboxAppConfigAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContextPtr = std::make_unique<SandboxAppConfigAsyncContext>(env);
    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContextPtr.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetSandboxAppConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetSandboxAppConfigExecute,
        GetSandboxAppConfigComplete, static_cast<void*>(asyncContextPtr.get()), &(asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextPtr->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetSandboxAppConfigExecute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work GetSandboxAppConfigExecute running");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::GetSandboxAppConfig(asyncContext->configInfo);
}

void NapiDlpPermission::GetSandboxAppConfigComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work GetSandboxAppConfig complete");
    auto asyncContext = reinterpret_cast<SandboxAppConfigAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<SandboxAppConfigAsyncContext> asyncContextPtr { asyncContext };
    napi_value configInfoJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncContext->configInfo.c_str(),
            NAPI_AUTO_LENGTH, &configInfoJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, configInfoJs);
}


napi_value NapiDlpPermission::IsDLPFeatureProvided(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContextPtr = std::make_unique<IsDLPFeatureProvidedAsyncContext>(env);
    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContextPtr.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsDLPFeatureProvided", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, IsDLPFeatureProvidedExcute,
        IsDLPFeatureProvidedComplete, static_cast<void*>(asyncContextPtr.get()), &(asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextPtr->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::IsDLPFeatureProvidedExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "IsDLPFeatureProvidedExcute start run.");
    auto asyncContext = reinterpret_cast<IsDLPFeatureProvidedAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::IsDLPFeatureProvided(asyncContext->isProvideDLPFeature);
}

void NapiDlpPermission::IsDLPFeatureProvidedComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "IsDLPFeatureProvidedComplete start run.");
    auto asyncContext = reinterpret_cast<IsDLPFeatureProvidedAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    std::unique_ptr<IsDLPFeatureProvidedAsyncContext> asyncContextPtr { asyncContext };
    napi_value isProvideDLPFeatureJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->isProvideDLPFeature, &isProvideDLPFeatureJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, isProvideDLPFeatureJs);
}

napi_value NapiDlpPermission::GetDLPSuffix(napi_env env, napi_callback_info cbInfo)
{
    GetSuffixAsyncContext *asyncContext = new (std::nothrow) GetSuffixAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for GetSuffixAsyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetSuffixAsyncContext> callbackPtr { asyncContext };

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, DLP_FILE_SUFFIX.c_str(), NAPI_AUTO_LENGTH, &result));
    return result;
}

napi_value NapiDlpPermission::GetOriginalFileName(napi_env env, napi_callback_info cbInfo)
{
    GetOriginalFileAsyncContext *asyncContext = new (std::nothrow) GetOriginalFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for GetFileNameAsyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetOriginalFileAsyncContext> callbackPtr { asyncContext };
    if (!GetOriginalFilenameParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    std::string resultStr =
        asyncContext->dlpFilename.substr(0, asyncContext->dlpFilename.size() - DLP_FILE_SUFFIX.size());
    napi_value resultJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, resultStr.c_str(), NAPI_AUTO_LENGTH, &resultJs));
    return resultJs;
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

napi_value NapiDlpPermission::StartDLPManagerForResult(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_INFO(LABEL, "begin StartDLPManagerForResult");
    size_t argc = PARAM_SIZE_TWO;
    size_t maxArgcNum = PARAM_SIZE_TWO;
    size_t contextIndex = PARAM0;
    size_t requestIndex = PARAM1;

    napi_value argv[PARAM2] = {nullptr};
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr));
    if (argc != maxArgcNum) {
        DLP_LOG_ERROR(LABEL, "params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(maxArgcNum) +
            ", given " + std::to_string(argc);
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg);
        return result;
    }

    auto asyncContext = std::make_shared<UIExtensionRequestContext>(env);
    if (!ParseUIAbilityContextReq(env, argv[contextIndex], asyncContext->context)) {
        DLP_LOG_ERROR(LABEL, "ParseUIAbilityContextReq failed");
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "get context failed");
        return result;
    }
    if (!ParseWantReq(env, argv[requestIndex], asyncContext->requestWant)) {
        DLP_LOG_ERROR(LABEL, "ParseWantReq failed");
        return result;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    StartUIExtensionAbility(asyncContext);
    DLP_LOG_DEBUG(LABEL, "end StartDLPManagerForResult");
    return result;
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
    };
    NAPI_CALL_RETURN_VOID(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[PARAM0]), desc));
}

napi_value NapiDlpPermission::Init(napi_env env, napi_value exports)
{
    InitFunction(env, exports);
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
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);

    int32_t result = AccessToken::AccessTokenKit::VerifyAccessToken(GetSelfTokenID(),
        "ohos.permission.ACCESS_DLP_FILE", false);
    if (result == AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        DLP_LOG_INFO(LABEL, "Check dlp permission success, start init dlp link manager.");
        DlpPermission::DlpLinkManager::GetInstance();
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

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    DLP_LOG_DEBUG(OHOS::Security::DlpPermission::LABEL, "Register end, start init.");

    return OHOS::Security::DlpPermission::NapiDlpPermission::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "dlpPermission",
    .nm_priv = ((void*)0),
    .reserved = {0}};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void DlpPermissionModuleRegister(void)
{
    napi_module_register(&_module);
}
