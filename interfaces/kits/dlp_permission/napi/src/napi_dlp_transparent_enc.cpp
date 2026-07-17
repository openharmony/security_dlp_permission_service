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

#include "napi_dlp_transparent_enc.h"

#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "dlp_transparent_enc_manager.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "parameters.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                      "DlpTransparentEncNapi"};
static constexpr int32_t THE_PARAM_TWO = 2;
static constexpr int32_t THE_PARAM_ONE = 1;
static constexpr int32_t THE_PARAM_ZERO = 0;
static constexpr int32_t DEFAULT_USER_ID = 0;
static constexpr int32_t MAX_MESSAGE_LEN = 4096;
static std::string VERSION_FOR_2B = "1";
static const std::string PERMISSION_DLP_POLICY_MANAGER = "ohos.permission.DLP_POLICY_MANAGER";
enum PluginCmd {
    CMD_BASE_INSTALL_PLUGIN = 0x1001,
    CMD_BASE_INSTALL_CONFIG_FILE = 0x1002,
    CMD_BASE_INSTALL_SUFFIX_FILTER_FILE = 0x1003,
    CMD_BASE_UNINSTALL_PLUGIN = 0x1004,
    CMD_BASE_QUERY_TRANSPARENT_CRYPTO_STATUS = 0x1005,
    CMD_EVENT_REPORT_COMMON = 0x2001
};
}  // namespace

static bool CheckEmulator()
{
#ifdef IS_EMULATOR
    return true;
#endif
    return false;
}

static bool CheckEnterprisePlatform()
{
    std::string value = OHOS::system::GetParameter("const.dlp.functiontypes", "0");
    if (value == VERSION_FOR_2B) {
        return true;
    }
    return false;
}

int32_t ConvertCredentialError(int32_t errorCode)
{
    if (errorCode == DLP_SUCCESS) {
        return DLP_OK;
    }
    if (errorCode == DLP_ERR_CHECK_PERFMISSION) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    if (errorCode == DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED) {
        return DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED;
    }
    if (errorCode == DLP_ERR_INVALID_PARAMS) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (errorCode == DLP_ERR_NOT_ENTERPRISE_WORKSPACE) {
        return DLP_ERROR_NOT_ENTERPRISE_WORKSPACE;
    }
    if (errorCode == DLP_ERR_USERID_INCONSISTENT) {
        return DLP_ERROR_USERID_INCONSISTENT;
    }
    if (errorCode == DLP_ERR_FILE_INVALID) {
        return DLP_ERROR_FILE_INVALID;
    }
    return DLP_TRANSPARENT_ENC_ERROR;
}

struct SetControlledAppListsAsyncContext : public CommonAsyncContext {
    explicit SetControlledAppListsAsyncContext(napi_env env) : CommonAsyncContext(env){};
    std::vector<std::string> appLists;
    int32_t userId = DEFAULT_USER_ID;
    bool userIdSet = false;
};

struct GetControlledAppListsAsyncContext : public CommonAsyncContext {
    explicit GetControlledAppListsAsyncContext(napi_env env) : CommonAsyncContext(env){};
    std::vector<std::string> appLists;
};

struct ProcessPluginCommandAsyncContext : public CommonAsyncContext {
    explicit ProcessPluginCommandAsyncContext(napi_env env) : CommonAsyncContext(env){};
    int32_t code = 0;
    std::string message;
    std::string result;
};

bool GetStringArrayValue(napi_env env, napi_value jsObject, std::vector<std::string> &resultVec)
{
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, jsObject, &isArray), false);
    if (!isArray) {
        DLP_LOG_ERROR(LABEL, "value is not array");
        return false;
    }
    uint32_t size = 0;
    if (napi_get_array_length(env, jsObject, &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "js get array size fail");
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        napi_value obj;
        NAPI_CALL_BASE(env, napi_get_element(env, jsObject, i, &obj), false);
        std::string app;
        if (!GetStringValue(env, obj, app)) {
            DLP_LOG_ERROR(LABEL, "js get app string fail");
            return false;
        }
        resultVec.push_back(app);
    }
    return true;
}

bool GetSetControlledAppListsParams(const napi_env env, const napi_callback_info info,
                                    SetControlledAppListsAsyncContext &asyncContext)
{
    size_t argc = THE_PARAM_TWO;
    napi_value argv[THE_PARAM_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (!NapiCheckArgc(env, argc, THE_PARAM_ONE)) {
        return false;
    }
    if (!GetStringArrayValue(env, argv[THE_PARAM_ZERO], asyncContext.appLists)) {
        DLP_LOG_ERROR(LABEL, "js get appLists fail");
        ThrowParamError(env, "appLists", "string array");
        return false;
    }
    if (argc < THE_PARAM_TWO) {
        return true;
    }
    if (!GetInt32Value(env, argv[THE_PARAM_ONE], asyncContext.userId)) {
        DLP_LOG_DEBUG(LABEL, "js get userId fail");
    } else {
        asyncContext.userIdSet = true;
    }
    return true;
}

void SetControlledAppListsExecute(napi_env env, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<SetControlledAppListsAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    int32_t res = DlpTransparentEncManager::GetInstance().SetControlledAppLists(
        asyncContext->appLists, asyncContext->userId, asyncContext->userIdSet);
    asyncContext->errCode = ConvertCredentialError(res);
}

void SetControlledAppListsComplete(napi_env env, napi_status status, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<SetControlledAppListsAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<SetControlledAppListsAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value SetControlledAppLists(napi_env env, napi_callback_info cbInfo)
{
    if (!CheckEnterprisePlatform()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED);
        return nullptr;
    }
    if (CheckEmulator()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR);
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_DLP_POLICY_MANAGER)) {
        return nullptr;
    }
    auto *asyncContext = new (std::nothrow) SetControlledAppListsAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_OUT_OF_MEMORY);
        return nullptr;
    }
    std::unique_ptr<SetControlledAppListsAsyncContext> asyncContextPtr{asyncContext};

    if (!GetSetControlledAppListsParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetControlledAppLists", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(
        env, napi_create_async_work(env, nullptr, resource, SetControlledAppListsExecute, SetControlledAppListsComplete,
                                    static_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

bool GetProcessPluginCommandParams(const napi_env env, const napi_callback_info info,
                                   ProcessPluginCommandAsyncContext &asyncContext)
{
    size_t argc = THE_PARAM_TWO;
    napi_value argv[THE_PARAM_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (!NapiCheckArgc(env, argc, THE_PARAM_TWO)) {
        return false;
    }
    if (!GetInt32Value(env, argv[THE_PARAM_ZERO], asyncContext.code)) {
        DLP_LOG_ERROR(LABEL, "js get code fail");
        ThrowParamError(env, "code", "PluginCmd");
        return false;
    }
    if (!GetStringValue(env, argv[THE_PARAM_ONE], asyncContext.message)) {
        DLP_LOG_ERROR(LABEL, "js get message fail");
        ThrowParamError(env, "message", "string");
        return false;
    }
    if (asyncContext.message.size() > MAX_MESSAGE_LEN) {
        DLP_LOG_ERROR(LABEL, "message length exceeds max limit");
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER);
        return false;
    }
    return true;
}

void ProcessPluginCommandExecute(napi_env env, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<ProcessPluginCommandAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    int32_t res = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(
        asyncContext->code, asyncContext->message, asyncContext->result);
    asyncContext->errCode = ConvertCredentialError(res);
}

void ProcessPluginCommandComplete(napi_env env, napi_status status, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<ProcessPluginCommandAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<ProcessPluginCommandAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env,
                              napi_create_string_utf8(env, asyncContext->result.c_str(), NAPI_AUTO_LENGTH, &resJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value ProcessPluginCommand(napi_env env, napi_callback_info cbInfo)
{
    if (!CheckEnterprisePlatform()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED);
        return nullptr;
    }
    if (CheckEmulator()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR);
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_DLP_POLICY_MANAGER)) {
        return nullptr;
    }
    auto *asyncContext = new (std::nothrow) ProcessPluginCommandAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_OUT_OF_MEMORY);
        return nullptr;
    }
    std::unique_ptr<ProcessPluginCommandAsyncContext> asyncContextPtr{asyncContext};

    if (!GetProcessPluginCommandParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "ProcessPluginCommand", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
              napi_create_async_work(env, nullptr, resource, ProcessPluginCommandExecute, ProcessPluginCommandComplete,
                                     static_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void GetControlledAppListsExecute(napi_env env, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetControlledAppListsAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    int32_t res = DlpTransparentEncManager::GetInstance().GetControlledAppLists(asyncContext->appLists);
    asyncContext->errCode = ConvertCredentialError(res);
}

void GetControlledAppListsComplete(napi_env env, napi_status status, void *data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetControlledAppListsAsyncContext *>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GetControlledAppListsAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &resJs));
        for (size_t i = 0; i < asyncContext->appLists.size(); i++) {
            napi_value app = nullptr;
            NAPI_CALL_RETURN_VOID(
                env, napi_create_string_utf8(env, asyncContext->appLists[i].c_str(), NAPI_AUTO_LENGTH, &app));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, resJs, i, app));
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value GetControlledAppLists(napi_env env, napi_callback_info cbInfo)
{
    if (!CheckEnterprisePlatform()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED);
        return nullptr;
    }
    if (CheckEmulator()) {
        DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR);
        return nullptr;
    }
    if (!CheckPermission(env, PERMISSION_DLP_POLICY_MANAGER)) {
        return nullptr;
    }
    auto *asyncContext = new (std::nothrow) GetControlledAppListsAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_OUT_OF_MEMORY);
        return nullptr;
    }
    std::unique_ptr<GetControlledAppListsAsyncContext> asyncContextPtr{asyncContext};

    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetControlledAppLists", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(
        env, napi_create_async_work(env, nullptr, resource, GetControlledAppListsExecute, GetControlledAppListsComplete,
                                    static_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

napi_value CreateEnumPluginCmd(napi_env env)
{
    napi_value pluginCmds = nullptr;
    NAPI_CALL(env, napi_create_object(env, &pluginCmds));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_BASE_INSTALL_PLUGIN), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_BASE_INSTALL_PLUGIN", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_BASE_INSTALL_CONFIG_FILE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_BASE_INSTALL_CONFIG_FILE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_BASE_INSTALL_SUFFIX_FILTER_FILE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_BASE_INSTALL_SUFFIX_FILTER_FILE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_BASE_UNINSTALL_PLUGIN), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_BASE_UNINSTALL_PLUGIN", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_BASE_QUERY_TRANSPARENT_CRYPTO_STATUS), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_BASE_QUERY_TRANSPARENT_CRYPTO_STATUS", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CMD_EVENT_REPORT_COMMON), &prop));
    NAPI_CALL(env, napi_set_named_property(env, pluginCmds, "CMD_EVENT_REPORT_COMMON", prop));

    return pluginCmds;
}

napi_value InitDlpTransparentEncFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("setControlledAppLists", SetControlledAppLists),
        DECLARE_NAPI_FUNCTION("getControlledAppLists", GetControlledAppLists),
        DECLARE_NAPI_FUNCTION("processPluginCommand", ProcessPluginCommand),
    };
    NAPI_CALL(env,
              napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));
    
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("PluginCmd", CreateEnumPluginCmd(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);
    return exports;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS