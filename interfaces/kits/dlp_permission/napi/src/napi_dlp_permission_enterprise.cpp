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
#include "napi_dlp_permission_common.h"
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
static const std::string PERMISSION_ENTERPRISE_ACCESS_DLP_FILE = "ohos.permission.ENTERPRISE_ACCESS_DLP_FILE";
}  // namespace

#ifdef IS_EMULATOR
#define CheckEmulator(env)                                              \
    do {                                                                \
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR);   \
        return nullptr;                                                 \
    } while (0)
#else
#define CheckEmulator(env)
#endif

napi_value NapiDlpPermission::CloseOpenedEnterpriseDlpFiles(napi_env env, napi_callback_info cbInfo)
{
    CheckEmulator(env);
    if (!CheckPermission(env, PERMISSION_ENTERPRISE_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    DLP_LOG_INFO(LABEL, "Enter CloseOpenedEnterpriseDlpFiles.");
    auto* asyncContext = new (std::nothrow) CloseOpenedEnterpriseDlpFilesContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr.");
        return nullptr;
    }
    std::unique_ptr<CloseOpenedEnterpriseDlpFilesContext> asyncContextPtr { asyncContext };

    if (!GetDlpFileQueryOptionsParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "CloseOpenedEnterpriseDlpFiles", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CloseOpenedEnterpriseDlpFilesExcute,
        CloseOpenedEnterpriseDlpFilesComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::CloseOpenedEnterpriseDlpFilesExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "CloseOpenedEnterpriseDlpFilesExcute start.");
    auto asyncContext = reinterpret_cast<CloseOpenedEnterpriseDlpFilesContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::CloseOpenedEnterpriseDlpFiles(asyncContext->options.classificationLabel);
}

void NapiDlpPermission::CloseOpenedEnterpriseDlpFilesComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "CloseOpenedEnterpriseDlpFilesComplete start.");
    auto asyncContext = reinterpret_cast<CloseOpenedEnterpriseDlpFilesContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    std::unique_ptr<CloseOpenedEnterpriseDlpFilesContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::QueryOpenedEnterpriseDlpFiles(napi_env env, napi_callback_info cbInfo)
{
    CheckEmulator(env);
    if (!CheckPermission(env, PERMISSION_ENTERPRISE_ACCESS_DLP_FILE)) {
        return nullptr;
    }
    DLP_LOG_INFO(LABEL, "Enter QueryOpenedEnterpriseDlpFiles.");
    auto* asyncContext = new (std::nothrow) QueryOpenedEnterpriseDlpFilesContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr.");
        return nullptr;
    }
    std::unique_ptr<QueryOpenedEnterpriseDlpFilesContext> asyncContextPtr { asyncContext };

    if (!GetDlpFileQueryOptionsParams(env, cbInfo, *asyncContext)) {
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
    NAPI_CALL(env, napi_create_string_utf8(env, "QueryOpenedEnterpriseDlpFiles", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, QueryOpenedEnterpriseDlpFilesExcute,
        QueryOpenedEnterpriseDlpFilesComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::QueryOpenedEnterpriseDlpFilesExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "QueryOpenedEnterpriseDlpFilesExcute start.");
    auto asyncContext = reinterpret_cast<QueryOpenedEnterpriseDlpFilesContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DlpPermissionKit::QueryOpenedEnterpriseDlpFiles(
        asyncContext->options.classificationLabel, asyncContext->resultUris);
}

void NapiDlpPermission::QueryOpenedEnterpriseDlpFilesComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "QueryOpenedEnterpriseDlpFilesComplete start.");
    auto asyncContext = reinterpret_cast<QueryOpenedEnterpriseDlpFilesContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    std::unique_ptr<QueryOpenedEnterpriseDlpFilesContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        resJs = VectorStringToJs(env, asyncContext->resultUris);
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS