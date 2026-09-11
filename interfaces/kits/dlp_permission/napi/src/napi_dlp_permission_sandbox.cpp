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
}  // namespace

napi_value NapiDlpPermission::InstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (sandboxInfoJs == nullptr) {
            DLP_LOG_ERROR(LABEL, "SandboxInfoToJs failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &sandboxInfoJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, sandboxInfoJs);
}

napi_value NapiDlpPermission::UninstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
    if (napi_get_undefined(env, &resJs) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
        asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::SetSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
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
        if (napi_get_undefined(env, &resJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CleanSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
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
        if (napi_get_undefined(env, &resJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetSandboxAppConfig(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
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
        if (napi_create_string_utf8(env, asyncContext->configInfo.c_str(),
            NAPI_AUTO_LENGTH, &configInfoJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_create_string_utf8 failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &configInfoJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, configInfoJs);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
