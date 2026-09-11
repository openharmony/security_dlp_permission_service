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
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
}  // namespace

napi_value NapiDlpPermission::AddDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    DlpLinkManager* manager = DlpFuseHelper::GetDlpLinkManagerInstance();
    if (!manager) {
        DLP_LOG_ERROR(LABEL, "Get instance failed.");
        asyncContext->errCode = DLP_FUSE_ERROR_DLP_FILE_NULL;
        return;
    }
    asyncContext->errCode = manager->AddDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::StopDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    DlpLinkManager* manager = DlpFuseHelper::GetDlpLinkManagerInstance();
    if (!manager) {
        DLP_LOG_ERROR(LABEL, "Get instance failed.");
        asyncContext->errCode = DLP_FUSE_ERROR_DLP_FILE_NULL;
        return;
    }
    asyncContext->errCode = manager->StopDlpLinkFile(asyncContext->dlpFileNative);
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RestartDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    DlpLinkManager* manager = DlpFuseHelper::GetDlpLinkManagerInstance();
    if (!manager) {
        DLP_LOG_ERROR(LABEL, "Get instance failed.");
        asyncContext->errCode = DLP_FUSE_ERROR_DLP_FILE_NULL;
        return;
    }
    asyncContext->errCode = manager->RestartDlpLinkFile(asyncContext->dlpFileNative);
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::ReplaceDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    DlpLinkManager* manager = DlpFuseHelper::GetDlpLinkManagerInstance();
    if (!manager) {
        DLP_LOG_ERROR(LABEL, "Get instance failed.");
        asyncContext->errCode = DLP_FUSE_ERROR_DLP_FILE_NULL;
        return;
    }
    asyncContext->errCode = manager->ReplaceDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    DlpLinkManager* manager = DlpFuseHelper::GetDlpLinkManagerInstance();
    if (!manager) {
        DLP_LOG_ERROR(LABEL, "Get instance failed.");
        asyncContext->errCode = DLP_FUSE_ERROR_DLP_FILE_NULL;
        return;
    }
    asyncContext->errCode = manager->DeleteDlpLinkFile(asyncContext->dlpFileNative);
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RecoverDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) RecoverDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CloseDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) CloseDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
