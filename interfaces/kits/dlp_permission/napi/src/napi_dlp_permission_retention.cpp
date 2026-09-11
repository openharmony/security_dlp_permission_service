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

napi_value NapiDlpPermission::SetRetentionState(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) RetentionStateAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
        if (napi_get_undefined(env, &resJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CancelRetentionState(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) RetentionStateAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
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
        if (napi_get_undefined(env, &resJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_undefined failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetRetentionSandboxList(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto* asyncContext = new (std::nothrow) GetRetentionSandboxListAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (resJs == nullptr) {
            DLP_LOG_ERROR(LABEL, "RetentionSandboxInfoToJs failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &resJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::GetDLPFileVisitRecord(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto* asyncContext = new (std::nothrow) GetDLPFileVisitRecordAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (resJs == nullptr) {
            DLP_LOG_ERROR(LABEL, "VisitInfoToJs failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &resJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
