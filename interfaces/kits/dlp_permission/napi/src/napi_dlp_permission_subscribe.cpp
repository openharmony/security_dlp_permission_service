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
std::mutex g_lockForOpenDlpFileSubscriber;
std::set<OpenDlpFileSubscriberContext*> g_openDlpFileSubscribers;
RegisterDlpSandboxChangeInfo *g_dlpSandboxChangeInfoRegister = nullptr;
static constexpr size_t MAX_TYPE_LEN = 64;
}  // namespace

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

static bool IsSubscribeExist(napi_env env, OpenDlpFileSubscriberContext* subscribeCBInfo)
{
    return std::any_of(g_openDlpFileSubscribers.begin(), g_openDlpFileSubscribers.end(),
        [env, subscribeCBInfo](const auto& it) {
            return CompareOnAndOffRef(env, it->callbackRef, subscribeCBInfo->callbackRef);
        });
}

static void RemoveWrapFromThisVar(napi_env env, napi_value thisVar, OpenDlpFileSubscriberPtr* subscriber)
{
    if (thisVar == nullptr || subscriber == nullptr) {
        return;
    }
    void* nativeData = nullptr;
    napi_status status = napi_unwrap(env, thisVar, &nativeData);
    if (status != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_unwrap failed, status %{public}d", static_cast<int32_t>(status));
        return;
    }
    if (nativeData == reinterpret_cast<void*>(subscriber)) {
        napi_status removeStatus = napi_remove_wrap(env, thisVar, nullptr);
        if (removeStatus != napi_ok) {
            DLP_LOG_ERROR(LABEL, "napi_remove_wrap failed, status %{public}d", static_cast<int32_t>(removeStatus));
        }
    }
}

napi_value NapiDlpPermission::SubscribeOpenDlpFile(const napi_env env, const napi_value thisVar, napi_ref& callback)
{
    DLP_LOG_INFO(LABEL, "Subscribe open dlp file");
    OpenDlpFileSubscriberContext* syncContext = new (std::nothrow) OpenDlpFileSubscriberContext();
    if (syncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for syncContext!");
        DlpNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, "The system ability works abnormally.");
        return nullptr;
    }
    std::unique_ptr<OpenDlpFileSubscriberContext> syncContextPtr { syncContext };
    syncContextPtr->env = env;
    syncContextPtr->callbackRef = callback;
    syncContextPtr->subscriber = std::make_shared<OpenDlpFileSubscriberPtr>();
    syncContextPtr->subscriber->SetEnv(env);
    syncContextPtr->subscriber->SetCallbackRef(callback);

    std::lock_guard<std::mutex> lock(g_lockForOpenDlpFileSubscriber);
    if (IsSubscribeExist(env, syncContext)) {
        DLP_LOG_ERROR(LABEL, "Subscribe failed. The current subscriber has been existed");
        return nullptr;
    }
    int32_t result = DlpPermissionKit::RegisterOpenDlpFileCallback(syncContextPtr->subscriber);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RegisterSandboxChangeCallback failed");
        DlpNapiThrow(env, result);
        return nullptr;
    }
    napi_status wrapStatus = napi_wrap(
        env, thisVar, reinterpret_cast<void*>(syncContextPtr->subscriber.get()),
        [](napi_env nev, void* data, void* hint) {
            DLP_LOG_INFO(LABEL, "OpenDlpFileSubscriberPtr delete");
            OpenDlpFileSubscriberPtr* subscriber = static_cast<OpenDlpFileSubscriberPtr*>(data);
            if (subscriber != nullptr) {
                subscriber->SetValid(false);
            }
        },
        nullptr, nullptr);
    if (wrapStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Wrap js and native option failed");
        syncContextPtr->subscriber->SetValid(false);
        DlpPermissionKit::UnRegisterOpenDlpFileCallback(syncContextPtr->subscriber);
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "Wrap js and native option failed");
        return nullptr;
    }
    g_openDlpFileSubscribers.emplace(syncContext);
    DLP_LOG_INFO(LABEL, "Subscribe open dlp file success");
    syncContextPtr.release();
    return nullptr;
}

napi_value NapiDlpPermission::Subscribe(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr));
    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO + 1)) {
        return nullptr;
    }
    std::string type;
    if (!GetStringValue(env, argv[PARAM0], type) || !IsStringLengthValid(type, MAX_TYPE_LEN)) {
        DLP_LOG_ERROR(LABEL, "event type is invalid");
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, "event type is invalid");
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
        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        return RegisterSandboxChangeCallback(env, cbInfo);
    } else {
        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, "event type is wrong")));
        return nullptr;
    }
}

napi_value NapiDlpPermission::UnSubscribeOpenDlpFile(const napi_env env, const napi_value thisVar, napi_ref& callback)
{
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
            RemoveWrapFromThisVar(env, thisVar, (*iter)->subscriber.get());
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
            RemoveWrapFromThisVar(env, thisVar, (*iter)->subscriber.get());
            delete *iter;
            g_openDlpFileSubscribers.erase(iter);
            break;
        }
    }
    return nullptr;
}

napi_value NapiDlpPermission::UnSubscribe(napi_env env, napi_callback_info cbInfo)
{
    if (CheckDevice(env)) {
        return nullptr;
    }
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr));
    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return nullptr;
    }
    std::string type;
    if (!GetStringValue(env, argv[PARAM0], type) || !IsStringLengthValid(type, MAX_TYPE_LEN)) {
        DLP_LOG_ERROR(LABEL, "event type is invalid");
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, "event type length is invalid");
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
    if (callback == nullptr) {
        DLP_LOG_INFO(LABEL, "SubEvent op=off_all kit=DataProtectionKit event=%{public}s", type.c_str());
    }
    if (type == "openDLPFile") {
        napi_value ret = UnSubscribeOpenDlpFile(env, thisVar, callback);
        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        return ret;
    } else if (type == "uninstallDLPSandbox") {
        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        return UnregisterSandboxChangeCallback(env, cbInfo);
    } else {
        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, "event type is wrong")));
        return nullptr;
    }
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
