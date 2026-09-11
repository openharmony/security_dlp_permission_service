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

napi_value NapiDlpPermission::GetDLPPermissionInfo(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GetPermInfoAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (permInfoJs == nullptr) {
            DLP_LOG_ERROR(LABEL, "DlpPermissionInfoToJs failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &permInfoJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, permInfoJs);
}

napi_value NapiDlpPermission::IsInSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) IsInSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (napi_get_boolean(env, asyncContext->inSandbox, &inSandboxJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_boolean failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &inSandboxJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, inSandboxJs);
}

napi_value NapiDlpPermission::GetDlpSupportFileType(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GetDlpSupportFileTypeAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (supportFileTypeJs == nullptr) {
            DLP_LOG_ERROR(LABEL, "VectorStringToJs failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &supportFileTypeJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, supportFileTypeJs);
}

napi_value NapiDlpPermission::GetDlpGatheringPolicy(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GetGatheringPolicyContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, DLP_SERVICE_ERROR_VALUE_INVALID);
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
        if (napi_create_uint32(env, policy, &isGatheringJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_create_uint32 failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &isGatheringJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, isGatheringJs);
}

napi_value NapiDlpPermission::IsDLPFeatureProvided(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
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
        if (napi_get_boolean(env, asyncContext->isProvideDLPFeature, &isProvideDLPFeatureJs) != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_get_boolean failed");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
            napi_get_undefined(env, &isProvideDLPFeatureJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, isProvideDLPFeatureJs);
}

napi_value NapiDlpPermission::GetDLPSuffix(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    GetSuffixAsyncContext *asyncContext = new (std::nothrow) GetSuffixAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for GetSuffixAsyncContext!");
        DlpNapiThrow(env, DLP_PARSE_ERROR_OPERATION_UNSUPPORTED);
        return nullptr;
    }
    std::unique_ptr<GetSuffixAsyncContext> callbackPtr { asyncContext };

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, DLP_FILE_SUFFIX.c_str(), NAPI_AUTO_LENGTH, &result));
    return result;
}

napi_value NapiDlpPermission::GetOriginalFileName(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    GetOriginalFileAsyncContext *asyncContext = new (std::nothrow) GetOriginalFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for GetFileNameAsyncContext!");
        DlpNapiThrow(env, DLP_PARSE_ERROR_OPERATION_UNSUPPORTED);
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

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
