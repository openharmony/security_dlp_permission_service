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

#include "napi_dlp_feature.h"

#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFeatureNapi"};
const std::string PARAM_STATUS = "status";
const std::string PARAM_DLPFEATURESTATUS = "dlpFeatureStatus";
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
const std::string PERMISSION_ENTERPRISE_ACCESS_DLP_FILE = "ohos.permission.ENTERPRISE_ACCESS_DLP_FILE";

static constexpr int32_t THE_PARAM_ONE = 1;
static constexpr int32_t THE_PARAM_ZERO = 0;
}  // namespace

typedef struct StatusSetInfo {
    bool isSuccess = false;
} StatusSetInfo;

enum DlpFeatureStatus : uint32_t {
    NOT_ENABLED_FEATURE = 0,
    ENABLED_FEATURE = 1,
};

typedef struct DlpFeatureInfo {
    DlpFeatureStatus status = NOT_ENABLED_FEATURE;
} DlpFeatureInfo;

struct SetDlpFeatureAsyncContext : public CommonAsyncContext {
    explicit SetDlpFeatureAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    DlpFeatureInfo dlpFeatureInfo;
    StatusSetInfo statusSetInfo;
};

bool GetDlpFeatureParams(
    const napi_env env, const napi_callback_info info, SetDlpFeatureAsyncContext& asyncContext)
{
    size_t argc = THE_PARAM_ONE;
    napi_value argv[THE_PARAM_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, THE_PARAM_ONE)) {
        return false;
    }

    int64_t res;
    if (!GetInt64Value(env, argv[THE_PARAM_ZERO], res)) {
        DLP_LOG_ERROR(LABEL, "js get dlpFeatureInfo fail");
        ThrowParamError(env, "dlpFeatureInfo", "number");
        return false;
    }
    asyncContext.dlpFeatureInfo.status = static_cast<DlpFeatureStatus>(res);
    return true;
}

napi_value NapiDlpFeature::SetDlpFeature(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) SetDlpFeatureAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        DlpNapiThrow(env, ERR_JS_OUT_OF_MEMORY);
        return nullptr;
    }
    std::unique_ptr<SetDlpFeatureAsyncContext> asyncContextPtr { asyncContext };

    if (!GetDlpFeatureParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    DLP_LOG_DEBUG(LABEL, "Create promise");
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetDlpFeature", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, SetDlpFeatureExecute, SetDlpFeatureComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpFeature::SetDlpFeatureExecute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<SetDlpFeatureAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpPermissionKit::SetDlpFeature(asyncContext->dlpFeatureInfo.status, asyncContext->statusSetInfo.isSuccess);
}

void NapiDlpFeature::SetDlpFeatureComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<SetDlpFeatureAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<SetDlpFeatureAsyncContext> asyncContextPtr { asyncContext };
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContextPtr->statusSetInfo.isSuccess, &resJs));
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value CreateEnumDlpFeatureStatus(napi_env env)
{
    napi_value status = nullptr;
    NAPI_CALL(env, napi_create_object(env, &status));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DlpFeatureStatus::NOT_ENABLED_FEATURE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, status, "NOT_ENABLED_FEATURE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DlpFeatureStatus::ENABLED_FEATURE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, status, "ENABLED_FEATURE", prop));

    return status;
}

napi_value NapiDlpFeature::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {DECLARE_NAPI_FUNCTION("setDlpFeature", SetDlpFeature)};
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("DlpFeatureStatus", CreateEnumDlpFeatureStatus(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);

    return exports;
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
    DLP_LOG_DEBUG(OHOS::Security::DlpPermission::LABEL, "dlpFeature start init.");

    return OHOS::Security::DlpPermission::NapiDlpFeature::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "dlpSetDlpFeature",
    .nm_priv = ((void*)0),
    .reserved = {0}};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void DlpFeatureModuleRegister(void)
{
    napi_module_register(&_module);
}