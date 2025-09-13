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

#include "napi_dlp_connection_plugin.h"

#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "securec.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_file_operator.h"

namespace OHOS {
namespace Security {
namespace DlpConnection {

using namespace OHOS::Security::DlpPermission;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "NapiConnectionPlugin"};
#ifdef SUPPORT_DLP_CREDENTIAL
static const size_t SIZE_64_BIT = 8;
static const std::string DLP_CREDENTIAL_STATIC_PLP_32_PATH = "/system/lib/libdlp_connection_static.z.so";
static const std::string DLP_CREDENTIAL_STATIC_PLP_64_PATH = "/system/lib64/libdlp_connection_static.z.so";
std::mutex g_lockDlpStatic;
static void *g_dlpStaticHandle;
#endif
}  // namespace

typedef int32_t (*Connection_Set)(void *plugin, uint64_t *pluginId);

NapiDlpConnectionPlugin::NapiDlpConnectionPlugin(napi_env env, const JsDlpConnPlugin &jsPlugin)
    : env_(env), jsPlugin_(jsPlugin)
{}

static void ReleaseNapiRefArray(napi_env env, const std::vector<napi_ref> &napiRefVec)
{
    if (env == nullptr) {
        return;
    }
    auto task = [env, napiRefVec]() {
        for (auto &napiRef : napiRefVec) {
            if (napiRef != nullptr) {
                napi_delete_reference(env, napiRef);
            }
        }
    };
    if (napi_ok != napi_send_event(env, task, napi_eprio_high)) {
        DLP_LOG_ERROR(LABEL, "napi_send_event is error.");
    }
}

static void ReleaseNapiRefAsync(napi_env env, napi_ref napiRef)
{
    ReleaseNapiRefArray(env, {napiRef});
}

NapiDlpConnectionPlugin::~NapiDlpConnectionPlugin()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    lockInfo_.condition.wait(lock, [this] { return this->lockInfo_.count == 0; });
    lockInfo_.count--;
    if (env_ == nullptr) {
        return;
    }
    ReleaseNapiRefAsync(env_, jsPlugin_.context);
    ReleaseNapiRefAsync(env_, jsPlugin_.funcRef);
    jsPlugin_.context = nullptr;
    jsPlugin_.funcRef = nullptr;
}

static napi_value CreatePluginAsyncCallback(napi_env env, napi_callback callback, JsDlpConnectionParam *param)
{
    napi_value napiCallback = nullptr;
    napi_status status = napi_create_function(env, "callback", NAPI_AUTO_LENGTH, callback, param, &napiCallback);
    if (status != napi_ok) {
        DLP_LOG_ERROR(LABEL, "status is not ok.");
        return nullptr;
    }
    status = napi_wrap(env, napiCallback, param,
        [](napi_env env, void *data, void *hint) {
            DLP_LOG_DEBUG(LABEL, "release JsDlpConnectionParam.");
            delete reinterpret_cast<JsDlpConnectionParam *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        DLP_LOG_ERROR(LABEL, "status is not ok.");
        return nullptr;
    }
    return napiCallback;
}

static bool GetPluginCallbackCommonParam(napi_env env, napi_callback_info cbInfo,
    JsDlpConnectionParam **param, BusinessError &error, napi_value *businessData)
{
    size_t argc = PARAM1;
    napi_value argv[PARAM1] = {nullptr};
    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, &data), false);
    if (argc != PARAM1) {
        DLP_LOG_ERROR(LABEL, "param size is error.");
        return false;
    }
    *param = reinterpret_cast<JsDlpConnectionParam *>(data);
    if ((*param == nullptr) || ((*param)->callback == nullptr)) {
        DLP_LOG_ERROR(LABEL, "param is error.");
        return false;
    }
    *businessData = argv[PARAM0];
    error.code = 0;
    return true;
}

static bool GetStringProperty(napi_env env, napi_value obj, std::string &property)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valuetype), false);
    if (valuetype != napi_string) {
        return false;
    }
    size_t propLen;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, nullptr, 0, &propLen), false);
    property.reserve(propLen + 1);
    property.resize(propLen);
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, property.data(), propLen + 1, &propLen), false);
    return true;
}

static napi_value ConnectServerCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDlpConnectionParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR);
        return nullptr;
    }
    std::string data;
    if ((error.code == 0) && (!GetStringProperty(env, businessData, data))) {
        DLP_LOG_ERROR(LABEL, "GetStringProperty is error.");
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR);
        return nullptr;
    }

    param->callback->OnResult(error.code, data);
    return nullptr;
}

static napi_value CreateString(const std::string &data, JsDlpConnectionParam *param)
{
    napi_value result = nullptr;
    NAPI_CALL(param->env,
        napi_create_string_utf8(param->env, data.c_str(), NAPI_AUTO_LENGTH, &result));
    return result;
}

void NapiCallVoidFunction(napi_env env, napi_value *argv, size_t argc, napi_ref funcRef, napi_ref contextRef)
{
    napi_value context = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, contextRef, &context));
    napi_value returnVal;
    napi_value func = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, funcRef, &func));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, context, func, argc, argv, &returnVal));
}

static void ConnectServerWork(JsDlpConnectionParam *param)
{
    napi_handle_scope scope = nullptr;
    int32_t res = 0;
    do {
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            DLP_LOG_ERROR(LABEL, "scope is error.");
            res = 1;
            break;
        }
        napi_value napiCallback = CreatePluginAsyncCallback(param->env, ConnectServerCallback, param);
        if (napiCallback == nullptr) {
            DLP_LOG_ERROR(LABEL, "napiCallback is error.");
            res = 1;
            break;
        }
        napi_value napiRequestId = CreateString(param->requestId, param);
        if (napiRequestId == nullptr) {
            DLP_LOG_ERROR(LABEL, "napiRequestId is error.");
            res = 1;
            break;
        }
        napi_value napiRequestData = CreateString(param->requestData, param);
        if (napiRequestData == nullptr) {
            DLP_LOG_ERROR(LABEL, "napiRequestData is error.");
            res = 1;
            break;
        }
        napi_value argv[] = {napiRequestId, napiRequestData, napiCallback};
        NapiCallVoidFunction(param->env, argv, PARAM3, param->func, param->context);
    } while (0);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    napi_close_handle_scope(param->env, scope);
    if (res != 0) {
        delete param;
    }
}

void NapiDlpConnectionPlugin::ConnectServer(const std::string requestId, const std::string requestData,
    const std::shared_ptr<DlpConnectionCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        DLP_LOG_ERROR(LABEL, "the plugin has been released");
        return;
    }
    if (jsPlugin_.funcRef == nullptr) {
        DLP_LOG_ERROR(LABEL, "funcRef released");
        return;
    }
    JsDlpConnectionParam *param = new (std::nothrow) JsDlpConnectionParam(env_);
    if (param == nullptr) {
        DLP_LOG_ERROR(LABEL, "JsDlpConnectionParam error");
        return;
    }
    param->callback = callback;
    param->func = jsPlugin_.funcRef;
    param->context = jsPlugin_.context;
    param->requestId = requestId;
    param->requestData = requestData;
    param->lockInfo = &lockInfo_;
    auto task = [param]() {
        ConnectServerWork(param);
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_high)) {
        DLP_LOG_ERROR(LABEL, "napi_send_event error");
        delete param;
        return;
    }
    lockInfo_.count++;
}

static napi_value CreateUint64(napi_env env, uint64_t data)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_bigint_uint64(env, data, &result));
    return result;
}

static bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        return true;
    } else if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, obj, argNum, &property), false);
        return true;
    }
    return false;
}

static bool GetNamedJsFunction(napi_env env, napi_value object, const std::string &name, napi_ref &callback)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, object, &valueType), false);
    if (valueType != napi_object) {
        return false;
    }
    napi_value result = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, object, name.c_str(), &result), false);
    return GetCallbackProperty(env, result, callback, 1);
}

static bool ParseContextForRegisterPlugin(napi_env env, napi_callback_info cbInfo, JsDlpConnPlugin &jsPlugin)
{
    size_t argc = PARAM1;
    napi_value argv[PARAM1];
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc != PARAM1) {
        DLP_LOG_ERROR(LABEL, "param size is error.");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valueType), false);
    if (valueType != napi_object) {
        DLP_LOG_ERROR(LABEL, "valueType is error.");
        return false;
    }

    NAPI_CALL_BASE(env, napi_create_reference(env, argv[PARAM0], PARAM1, &jsPlugin.context), false);
    if (!GetNamedJsFunction(env, argv[PARAM0], "connectServer", jsPlugin.funcRef)) {
        DLP_LOG_ERROR(LABEL, "get connectServer is error.");
        return false;
    }
    return true;
}

static napi_value RegisterPlugin(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_INFO(LABEL, "Enter RegisterPlugin.");
    JsDlpConnPlugin jsPlugin;
    if (!ParseContextForRegisterPlugin(env, cbInfo, jsPlugin)) {
        std::string errMsg = "Parameter error of plugin";
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg);
        return nullptr;
    }
    uint64_t pluginId = 0;
    auto plugin = new (std::nothrow) NapiDlpConnectionPlugin(env, jsPlugin);
    if (plugin == nullptr) {
        DLP_LOG_ERROR(LABEL, "malloc is error.");
        return nullptr;
    }
    int32_t res = 0;
#ifdef SUPPORT_DLP_CREDENTIAL
    std::lock_guard<std::mutex> lock(g_lockDlpStatic);
    if (g_dlpStaticHandle == nullptr) {
        if (sizeof(void *) == SIZE_64_BIT) {
            g_dlpStaticHandle = dlopen(DLP_CREDENTIAL_STATIC_PLP_64_PATH.c_str(), RTLD_LAZY);
        } else {
            g_dlpStaticHandle = dlopen(DLP_CREDENTIAL_STATIC_PLP_32_PATH.c_str(), RTLD_LAZY);
        }
        if (g_dlpStaticHandle == nullptr) {
            return nullptr;
        }
    }
    void *func = dlsym(g_dlpStaticHandle, "Connection_Set");
    if (func == nullptr) {
        DLP_LOG_ERROR(LABEL, "get func is error.");
        return nullptr;
    }
    Connection_Set dlpFunc = reinterpret_cast<Connection_Set>(func);
    if (dlpFunc == nullptr) {
        DLP_LOG_ERROR(LABEL, "get dlpFunc is error.");
        return nullptr;
    }
    res = (*dlpFunc)(reinterpret_cast<void *>(plugin), &pluginId);
#else
    res = DlpConnectionClient::GetInstance().RegisterPlugin(plugin, &pluginId);
#endif
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "res is %{public}d.", res);
        delete plugin;
        DlpNapiThrow(env, res);
    }
    napi_value result = CreateUint64(env, pluginId);
    return result;
}

static napi_value UnregisterPlugin(napi_env env, napi_callback_info cbInfo)
{
    DLP_LOG_INFO(LABEL, "Enter UnregisterPlugin.");
    (void)cbInfo;
#ifdef SUPPORT_DLP_CREDENTIAL
    std::lock_guard<std::mutex> lock(g_lockDlpStatic);
    if (g_dlpStaticHandle != nullptr) {
        dlclose(g_dlpStaticHandle);
        g_dlpStaticHandle = nullptr;
    }
#endif
    return nullptr;
}

static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

void GenerateDlpFileForEnterpriseExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpFileForEnterprise start run.");
    auto asyncContext = reinterpret_cast<GenerateDlpFileForEnterpriseAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }

    asyncContext->errCode = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(
        asyncContext->property, asyncContext->customProperty, asyncContext->plaintextFd, asyncContext->dlpFd);
}

void GenerateDlpFileForEnterpriseComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpFileForEnterprise start run.");
    auto asyncContext = reinterpret_cast<GenerateDlpFileForEnterpriseAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "AsyncContext is nullptr.");
        return;
    }
    std::unique_ptr<GenerateDlpFileForEnterpriseAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value ProcessEnterpriseAccount(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContextPtr = std::make_unique<GenerateDlpFileForEnterpriseAsyncContext>(env);
    if (!GetGenerateDlpFileForEnterpriseParam(env, cbInfo, *asyncContextPtr)) {
        return nullptr;
    }
    napi_value result = nullptr;
    if (asyncContextPtr->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "ProcessEnterpriseAccount", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GenerateDlpFileForEnterpriseExcute,
        GenerateDlpFileForEnterpriseComplete, static_cast<void*>(asyncContextPtr.get()), &(asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContextPtr->work, napi_qos_user_initiated));
    asyncContextPtr.release();
    return result;
}

napi_value InitDlpConnectFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_STATIC_FUNCTION("unregisterPlugin", UnregisterPlugin),
    };

    std::string className = "DlpConnManager";
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.size(), JsConstructor,
                       nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class DlpConnManager failed.");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to exports failed.");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed.");
    status = napi_set_named_property(env, global, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to global failed.");
    return exports;
}
}  // namespace DlpConnection
}  // namespace Security
}  // namespace OHOS

