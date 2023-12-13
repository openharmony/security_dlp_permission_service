/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "napi_common.h"
#include <algorithm>
#include <unistd.h>
#include "dlp_file_kits.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "napi_error_msg.h"
#include "securec.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionCommon"};
static const int MAX_FILE_NAME_LEN = 256;
const std::string PARAM_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string SYS_COMMON_UI = "sys/commonUI";
const std::string DLP_MANAGER_BUNDLENAME = "com.ohos.dlpmanager";
const std::string DLP_MANAGER_ABILITYNAME = "MainAbilityEx";

static bool ConvertDlpSandboxChangeInfo(napi_env env, napi_value value, const DlpSandboxCallbackInfo &result)
{
    napi_value element;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.appIndex, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "appIndex", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, result.bundleName.c_str(), NAPI_AUTO_LENGTH, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "bundleName", element), false);
    return true;
};

static void UvQueueWorkDlpSandboxChanged(uv_work_t *work, int status)
{
    DLP_LOG_INFO(LABEL, "enter UvQueueWorkDlpSandboxChanged");
    if ((work == nullptr) || (work->data == nullptr)) {
        DLP_LOG_ERROR(LABEL, "work == nullptr || work->data == nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    RegisterDlpSandboxChangeWorker *registerSandboxChangeData =
        reinterpret_cast<RegisterDlpSandboxChangeWorker *>(work->data);
    std::unique_ptr<RegisterDlpSandboxChangeWorker> workPtr { registerSandboxChangeData };
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(registerSandboxChangeData->env, &scope);
    if (scope == nullptr) {
        DLP_LOG_ERROR(LABEL, "scope is nullptr");
        return;
    }
    napi_value result = { nullptr };
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(registerSandboxChangeData->env,
        napi_create_array(registerSandboxChangeData->env, &result), scope);
    if (!ConvertDlpSandboxChangeInfo(registerSandboxChangeData->env, result, registerSandboxChangeData->result)) {
        napi_close_handle_scope(registerSandboxChangeData->env, scope);
        DLP_LOG_ERROR(LABEL, "ConvertDlpSandboxChangeInfo failed");
        return;
    }

    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(registerSandboxChangeData->env,
        napi_get_undefined(registerSandboxChangeData->env, &undefined), scope);
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(registerSandboxChangeData->env,
        napi_get_reference_value(registerSandboxChangeData->env, registerSandboxChangeData->ref, &callback), scope);
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(registerSandboxChangeData->env,
        napi_call_function(registerSandboxChangeData->env, undefined, callback, 1, &result, &resultout), scope);
    napi_close_handle_scope(registerSandboxChangeData->env, scope);
    DLP_LOG_DEBUG(LABEL, "UvQueueWorkDlpSandboxChanged end");
};

static bool ConvertOpenDlpFileCallbackInfo(napi_env env, napi_value value, const OpenDlpFileCallbackInfo &result)
{
    napi_value element = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, result.uri.c_str(), NAPI_AUTO_LENGTH, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "uri", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_bigint_uint64(env, result.timeStamp, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "lastOpenTime", element), false);
    return true;
};

static void UvQueueWorkOpenDlpFile(uv_work_t *work, int status)
{
    DLP_LOG_INFO(LABEL, "enter UvQueueWorkOpenDlpFile");
    if ((work == nullptr) || (work->data == nullptr)) {
        DLP_LOG_ERROR(LABEL, "work == nullptr || work->data == nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    OpenDlpFileSubscriberWorker *oepnDlpFileDate =
        reinterpret_cast<OpenDlpFileSubscriberWorker *>(work->data);
    std::unique_ptr<OpenDlpFileSubscriberWorker> workPtr { oepnDlpFileDate };
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(oepnDlpFileDate->env, &scope);
    if (scope == nullptr) {
        DLP_LOG_ERROR(LABEL, "scope is nullptr");
        return;
    }
    napi_value result = { nullptr };
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(oepnDlpFileDate->env,
        napi_create_array(oepnDlpFileDate->env, &result), scope);
    if (!ConvertOpenDlpFileCallbackInfo(oepnDlpFileDate->env, result, oepnDlpFileDate->result)) {
        napi_close_handle_scope(oepnDlpFileDate->env, scope);
        DLP_LOG_ERROR(LABEL, "ConvertOpenDlpFileCallbackInfo failed");
        return;
    }

    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(oepnDlpFileDate->env,
        napi_get_undefined(oepnDlpFileDate->env, &undefined), scope);
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(oepnDlpFileDate->env,
        napi_get_reference_value(oepnDlpFileDate->env, oepnDlpFileDate->ref, &callback), scope);
    NAPI_CALL_RETURN_VOID_WITH_SCOPE(oepnDlpFileDate->env,
        napi_call_function(oepnDlpFileDate->env, undefined, callback, 1, &result, &resultout), scope);
    napi_close_handle_scope(oepnDlpFileDate->env, scope);
    DLP_LOG_INFO(LABEL, "UvQueueWorkOpenDlpFile end");
};
} // namespace

RegisterDlpSandboxChangeScopePtr::RegisterDlpSandboxChangeScopePtr() {}

RegisterDlpSandboxChangeScopePtr::~RegisterDlpSandboxChangeScopePtr() {}

void RegisterDlpSandboxChangeScopePtr::DlpSandboxChangeCallback(DlpSandboxCallbackInfo &result)
{
    DLP_LOG_INFO(LABEL, "enter DlpSandboxChangeCallback");
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        DLP_LOG_ERROR(LABEL, "object is invalid.");
        return;
    }
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_get_uv_event_loop(env_, &loop));
    if (loop == nullptr) {
        DLP_LOG_ERROR(LABEL, "loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    RegisterDlpSandboxChangeWorker *registerSandboxChangeWorker = new (std::nothrow) RegisterDlpSandboxChangeWorker();
    if (registerSandboxChangeWorker == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for RegisterDlpSandboxChangeWorker!");
        return;
    }
    std::unique_ptr<RegisterDlpSandboxChangeWorker> workPtr { registerSandboxChangeWorker };
    registerSandboxChangeWorker->env = env_;
    registerSandboxChangeWorker->ref = ref_;
    registerSandboxChangeWorker->result = result;
    DLP_LOG_DEBUG(LABEL, "result appIndex = %{public}d, bundleName = %{public}s", result.appIndex,
        result.bundleName.c_str());
    registerSandboxChangeWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(registerSandboxChangeWorker);
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(
        loop, work, [](uv_work_t *work) {}, UvQueueWorkDlpSandboxChanged));
    uvWorkPtr.release();
    workPtr.release();
}

void RegisterDlpSandboxChangeScopePtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void RegisterDlpSandboxChangeScopePtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

void RegisterDlpSandboxChangeScopePtr::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
}

DlpSandboxChangeContext::~DlpSandboxChangeContext()
{
    if (callbackRef == nullptr) {
        return;
    }
    DeleteNapiRef();
}

void DlpSandboxChangeContext::DeleteNapiRef()
{
    DLP_LOG_INFO(LABEL, "enter DeleteNapiRef");
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_uv_event_loop(env, &loop));
    if (loop == nullptr) {
        DLP_LOG_ERROR(LABEL, "loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }

    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    RegisterDlpSandboxChangeWorker *registerSandboxChangeWorker = new (std::nothrow) RegisterDlpSandboxChangeWorker();
    if (registerSandboxChangeWorker == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for registerSandboxChangeWorker!");
        return;
    }
    std::unique_ptr<RegisterDlpSandboxChangeWorker> workPtr { registerSandboxChangeWorker };
    registerSandboxChangeWorker->env = env;
    registerSandboxChangeWorker->ref = callbackRef;

    work->data = reinterpret_cast<void *>(registerSandboxChangeWorker);
    NAPI_CALL_RETURN_VOID(env, uv_queue_work(
        loop, work, [](uv_work_t *work) {}, UvQueueWorkDeleteRef));
    DLP_LOG_DEBUG(LABEL, "DeleteNapiRef");
    uvWorkPtr.release();
    workPtr.release();
}

void UvQueueWorkDeleteRef(uv_work_t *work, int32_t status)
{
    DLP_LOG_INFO(LABEL, "enter UvQueueWorkDeleteRef");
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "work == nullptr : %{public}d", work == nullptr);
        return;
    } else if (work->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "work->data == nullptr : %{public}d", work->data == nullptr);
        return;
    }
    RegisterDlpSandboxChangeWorker *registerSandboxChangeWorker =
        reinterpret_cast<RegisterDlpSandboxChangeWorker *>(work->data);
    if (registerSandboxChangeWorker == nullptr) {
        delete work;
        return;
    }
    napi_delete_reference(registerSandboxChangeWorker->env, registerSandboxChangeWorker->ref);
    delete registerSandboxChangeWorker;
    registerSandboxChangeWorker = nullptr;
    delete work;
    DLP_LOG_DEBUG(LABEL, "UvQueueWorkDeleteRef end");
}

OpenDlpFileSubscriberPtr::OpenDlpFileSubscriberPtr() {}

OpenDlpFileSubscriberPtr::~OpenDlpFileSubscriberPtr() {}

void OpenDlpFileSubscriberPtr::OnOpenDlpFile(OpenDlpFileCallbackInfo &result)
{
    DLP_LOG_INFO(LABEL, "enter OnOpenDlpFile");
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        DLP_LOG_ERROR(LABEL, "object is invalid.");
        return;
    }
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_get_uv_event_loop(env_, &loop));
    if (loop == nullptr) {
        DLP_LOG_ERROR(LABEL, "loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    OpenDlpFileSubscriberWorker *openDlpFileWorker = new (std::nothrow) OpenDlpFileSubscriberWorker();
    if (openDlpFileWorker == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for OpenDlpFileSubscriberWorker!");
        return;
    }
    std::unique_ptr<OpenDlpFileSubscriberWorker> workPtr { openDlpFileWorker };
    openDlpFileWorker->env = env_;
    openDlpFileWorker->ref = ref_;
    openDlpFileWorker->result = result;
    DLP_LOG_DEBUG(LABEL, "result uri = %{public}s, openTime = %{public}" PRIu64, result.uri.c_str(),
        result.timeStamp);
    openDlpFileWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(openDlpFileWorker);
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(
        loop, work, [](uv_work_t *work) {}, UvQueueWorkOpenDlpFile));
    uvWorkPtr.release();
    workPtr.release();
}

void OpenDlpFileSubscriberPtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void OpenDlpFileSubscriberPtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

void OpenDlpFileSubscriberPtr::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
}

OpenDlpFileSubscriberContext::~OpenDlpFileSubscriberContext()
{
    if (callbackRef == nullptr) {
        return;
    }
    DeleteNapiRef();
}

void OpenDlpFileUvQueueWorkDeleteRef(uv_work_t *work, int32_t status)
{
    DLP_LOG_INFO(LABEL, "enter OpenDlpFileUvQueueWorkDeleteRef");
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "work == nullptr : %{public}d", work == nullptr);
        return;
    } else if (work->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "work->data == nullptr : %{public}d", work->data == nullptr);
        return;
    }
    OpenDlpFileSubscriberWorker *openDlpFileWorker =
        reinterpret_cast<OpenDlpFileSubscriberWorker *>(work->data);
    if (openDlpFileWorker == nullptr) {
        delete work;
        return;
    }
    napi_delete_reference(openDlpFileWorker->env, openDlpFileWorker->ref);
    delete openDlpFileWorker;
    openDlpFileWorker = nullptr;
    delete work;
    DLP_LOG_INFO(LABEL, "OpenDlpFileUvQueueWorkDeleteRef end");
}

void OpenDlpFileSubscriberContext::DeleteNapiRef()
{
    DLP_LOG_INFO(LABEL, "enter DeleteNapiRef");
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_uv_event_loop(env, &loop));
    if (loop == nullptr) {
        DLP_LOG_ERROR(LABEL, "loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }

    std::unique_ptr<uv_work_t> uvWorkPtr { work };
    OpenDlpFileSubscriberWorker *openDlpFileWorker = new (std::nothrow) OpenDlpFileSubscriberWorker();
    if (openDlpFileWorker == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for openDlpFileWorker!");
        return;
    }
    std::unique_ptr<OpenDlpFileSubscriberWorker> workPtr { openDlpFileWorker };
    openDlpFileWorker->env = env;
    openDlpFileWorker->ref = callbackRef;

    work->data = reinterpret_cast<void *>(openDlpFileWorker);
    NAPI_CALL_RETURN_VOID(env, uv_queue_work(
        loop, work, [](uv_work_t *work) {}, OpenDlpFileUvQueueWorkDeleteRef));
    DLP_LOG_DEBUG(LABEL, "DeleteNapiRef");
    uvWorkPtr.release();
    workPtr.release();
}

napi_value GenerateBusinessError(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    napi_value errCodeJs = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, jsErrCode, &errCodeJs));

    napi_value errMsgJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, jsErrMsg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs));

    napi_value errJs = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, errMsgJs, &errJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "code", errCodeJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "message", errMsgJs));
    return errJs;
}

void DlpNapiThrow(napi_env env, int32_t nativeErrCode)
{
    int32_t jsErrCode = NativeCodeToJsCode(nativeErrCode);
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode))));
}

void DlpNapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, jsErrMsg)));
}

void ThrowParamError(const napi_env env, const std::string& param, const std::string& type)
{
    std::string msg = "Parameter Error. The type of \"" + param + "\" must be " + type + ".";
    DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, msg);
}

CommonAsyncContext::CommonAsyncContext(napi_env napiEnv)
{
    env = napiEnv;
}

CommonAsyncContext::~CommonAsyncContext()
{
    if (callbackRef) {
        DLP_LOG_DEBUG(LABEL, "~CommonAsyncContext delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (work) {
        DLP_LOG_DEBUG(LABEL, "~CommonAsyncContext delete work");
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

napi_value CreateEnumDLPFileAccess(napi_env env)
{
    napi_value authPerm = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authPerm));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(NO_PERMISSION), &prop));
    NAPI_CALL(env, napi_set_named_property(env, authPerm, "NO_PERMISSION", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(READ_ONLY), &prop));
    NAPI_CALL(env, napi_set_named_property(env, authPerm, "READ_ONLY", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CONTENT_EDIT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, authPerm, "CONTENT_EDIT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(FULL_CONTROL), &prop));
    NAPI_CALL(env, napi_set_named_property(env, authPerm, "FULL_CONTROL", prop));

    return authPerm;
}

napi_value CreateEnumAccountType(napi_env env)
{
    napi_value accountType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &accountType));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CLOUD_ACCOUNT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, accountType, "CLOUD_ACCOUNT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DOMAIN_ACCOUNT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, accountType, "DOMAIN_ACCOUNT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(APPLICATION_ACCOUNT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, accountType, "APPLICATION_ACCOUNT", prop));

    return accountType;
}

napi_value CreateEnumActionFlags(napi_env env)
{
    napi_value actionFlags = nullptr;
    NAPI_CALL(env, napi_create_object(env, &actionFlags));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_INVALID), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_INVALID", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_VIEW), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_VIEW", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_SAVE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_SAVE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_SAVE_AS), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_SAVE_AS", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_EDIT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_EDIT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_SCREEN_CAPTURE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_SCREEN_CAPTURE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_SCREEN_SHARE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_SCREEN_SHARE", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_SCREEN_RECORD), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_SCREEN_RECORD", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_COPY), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_COPY", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_PRINT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_PRINT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_EXPORT), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_EXPORT", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(ACTION_PERMISSION_CHANGE), &prop));
    NAPI_CALL(env, napi_set_named_property(env, actionFlags, "ACTION_PERMISSION_CHANGE", prop));
    return actionFlags;
}

napi_value CreateEnumGatheringPolicy(napi_env env)
{
    napi_value gatheringPolicy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &gatheringPolicy));

    napi_value prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(GATHERING), &prop));
    NAPI_CALL(env, napi_set_named_property(env, gatheringPolicy, "GATHERING", prop));

    prop = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(NON_GATHERING), &prop));
    NAPI_CALL(env, napi_set_named_property(env, gatheringPolicy, "NON_GATHERING", prop));

    return gatheringPolicy;
}

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext* asyncContext, napi_value data)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value args[PARAM_SIZE_TWO] = {nullptr};

    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[PARAM0]));
        args[PARAM1] = data;
    } else {
        int32_t jsErrCode = NativeCodeToJsCode(asyncContext->errCode);
        napi_value errObj = GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode));
        if (data != nullptr && (asyncContext->errCode == DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR ||
            asyncContext->errCode == DLP_CREDENTIAL_ERROR_TIME_EXPIRED)) {
            std::string errContacter;
            if (!GetStringValue(env, data, errContacter)) {
                DLP_LOG_ERROR(LABEL, "js get contacter data fail");
                ThrowParamError(env, "contacter data", "string");
                return ;
            }
            std::string errMessage = GetJsErrMsg(jsErrCode) + ", contact:" + errContacter;
            napi_value jsMessageStr;
            napi_value jsErrMessage;
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "message", NAPI_AUTO_LENGTH, &jsMessageStr));
            NAPI_CALL_RETURN_VOID(env,
                napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &jsErrMessage));
            NAPI_CALL_RETURN_VOID(env, napi_delete_property(env, errObj, jsMessageStr, nullptr));
            NAPI_CALL_RETURN_VOID(env, napi_set_property(env, errObj, jsMessageStr, jsErrMessage));
        }
        args[PARAM0] = errObj;
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[PARAM1]));
    }

    if (asyncContext->deferred) {
        DLP_LOG_DEBUG(LABEL, "Promise");
        if (asyncContext->errCode == DLP_OK) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args[PARAM1]));
        } else {
            DLP_LOG_ERROR(LABEL, "Promise reject, errCode=%{public}d", asyncContext->errCode);
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, args[PARAM0]));
        }
    } else {
        DLP_LOG_DEBUG(LABEL, "Callback");
        napi_value callback = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        napi_value returnVal = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback, argc, &args[PARAM0], &returnVal));
    }
}

bool NapiCheckArgc(const napi_env env, int32_t argc, int32_t reqSize)
{
    if (argc < (reqSize - 1)) {
        DLP_LOG_ERROR(LABEL, "params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need at least " + std::to_string(reqSize - 1) +
            ", given " + std::to_string(argc);
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg);
        return false;
    }
    return true;
}

bool GetGenerateDlpFileParams(
    const napi_env env, const napi_callback_info info, GenerateDlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plaintextFd)) {
        DLP_LOG_ERROR(LABEL, "js get plain fd fail");
        ThrowParamError(env, "plaintextFd", "number");
        return false;
    }
    if (!GetInt64Value(env, argv[PARAM1], asyncContext.ciphertextFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "ciphertextFd", "number");
        return false;
    }

    if (!GetDlpProperty(env, argv[PARAM2], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail");
        ThrowParamError(env, "property", "DlpProperty");
        return false;
    }

    if (argc == PARAM_SIZE_FOUR) {
        if (!ParseCallback(env, argv[PARAM3], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL,
        "Fd: %{private}" PRId64 ",ownerAccount:%{private}s,ownerAccountId: %{private}s, ownerAccountType: %{private}d,"
        "contactAccount: %{private}s, size: %{private}zu, expireTime: %{public}" PRId64,
        asyncContext.plaintextFd, asyncContext.property.ownerAccount.c_str(),
        asyncContext.property.ownerAccountId.c_str(), asyncContext.property.ownerAccountType,
        asyncContext.property.contactAccount.c_str(), asyncContext.property.authUsers.size(),
        asyncContext.property.expireTime);
    return true;
}

bool GetOpenDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_THREE;
    napi_value argv[PARAM_SIZE_THREE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_THREE)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.ciphertextFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "ciphertextFd", "number");
        return false;
    }

    if (!GetStringValue(env, argv[PARAM1], asyncContext.appId)) {
        DLP_LOG_ERROR(LABEL, "js get appId fail");
        ThrowParamError(env, "appId", "string");
        return false;
    }

    if (argc == PARAM_SIZE_THREE) {
        if (!ParseCallback(env, argv[PARAM2], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}" PRId64, asyncContext.ciphertextFd);
    return true;
}

bool GetIsDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.ciphertextFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "fd", "number");
        return false;
    }

    if (asyncContext.ciphertextFd < 0) {
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, GetJsErrMsg(ERR_JS_INVALID_PARAMETER));
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}" PRId64, asyncContext.ciphertextFd);
    return true;
}

bool GetDlpLinkFileParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.linkFileName)) {
        DLP_LOG_ERROR(LABEL, "linkFileName is invalid");
        ThrowParamError(env, "linkFileName", "string");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "linkFileName: %{private}s", asyncContext.linkFileName.c_str());
    return true;
}

bool GetLinkFileStatusParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_ONE)) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (argc == PARAM_SIZE_ONE) {
        if (!ParseCallback(env, argv[PARAM0], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    return true;
}

bool GetRecoverDlpFileParams(
    const napi_env env, const napi_callback_info info, RecoverDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plaintextFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "plaintextFd", "number");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "plaintextFd: %{private}" PRId64, asyncContext.plaintextFd);
    return true;
}

bool GetCloseDlpFileParams(const napi_env env, const napi_callback_info info, CloseDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (argc == PARAM_SIZE_ONE) {
        if (!ParseCallback(env, argv[PARAM0], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    return true;
}

bool GetInstallDlpSandboxParams(const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FIVE;
    napi_value argv[PARAM_SIZE_FIVE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FIVE)) {
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        ThrowParamError(env, "bundleName", "string");
        return false;
    }
    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get perm fail");
        ThrowParamError(env, "access", "number");
        return false;
    }
    asyncContext.dlpFileAccess = static_cast<DLPFileAccess>(res);
    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        ThrowParamError(env, "userId", "number");
        return false;
    }
    asyncContext.userId = static_cast<int32_t>(res);
    if (!GetStringValue(env, argv[PARAM3], asyncContext.uri)) {
        DLP_LOG_ERROR(LABEL, "js get uri fail");
        ThrowParamError(env, "uri", "string");
        return false;
    }

    if (argc == PARAM_SIZE_FIVE) {
        if (!ParseCallback(env, argv[PARAM4], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, dlpFileAccess: %{private}d, userId: %{private}d,uri: %{private}s",
        asyncContext.bundleName.c_str(), asyncContext.dlpFileAccess, asyncContext.userId, asyncContext.uri.c_str());
    return true;
}

bool GetUninstallDlpSandboxParams(
    const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        ThrowParamError(env, "bundleName", "string");
        return false;
    }

    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        ThrowParamError(env, "userId", "number");
        return false;
    }
    asyncContext.userId = static_cast<int32_t>(res);

    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get app index fail");
        ThrowParamError(env, "appIndex", "number");
        return false;
    }
    asyncContext.sandboxInfo.appIndex = static_cast<int32_t>(res);

    if (argc == PARAM_SIZE_FOUR) {
        if (!ParseCallback(env, argv[PARAM3], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, userId: %{private}d, appIndex: %{private}d",
        asyncContext.bundleName.c_str(), asyncContext.userId, asyncContext.sandboxInfo.appIndex);
    return true;
}

bool ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterDlpSandboxChangeInfo &registerSandboxChangeInfo)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc < PARAM_SIZE_TWO) {
        ThrowParamError(env, "params", " missing.");
        return false;
    }
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "thisVar is nullptr");
        return false;
    }
    napi_valuetype valueTypeOfThis = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, thisVar, &valueTypeOfThis), false);
    if (valueTypeOfThis == napi_undefined) {
        DLP_LOG_ERROR(LABEL, "thisVar is undefined");
        return false;
    }
    // 0: the first parameter of argv
    std::string type;
    if (!GetStringValue(env, argv[0], type)) {
        ThrowParamError(env, "type", "string");
        return false;
    }

    if (type.compare(ON_OFF_SANDBOX) != 0) {
        ThrowParamError(env, "type", "uninstallsandbox");
        return false;
    }

    if (!FillDlpSandboxChangeInfo(env, argv, type, thisVar, registerSandboxChangeInfo)) {
        return false;
    }

    return true;
}

bool FillDlpSandboxChangeInfo(const napi_env env, const napi_value *argv, const std::string &type,
    const napi_value thisVar, RegisterDlpSandboxChangeInfo &registerSandboxChangeInfo)
{
    std::string errMsg;
    napi_ref callback = nullptr;

    // 1: the second parameter of argv
    if (!ParseCallback(env, argv[1], callback)) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, "callback is wrong"));
        return false;
    }

    registerSandboxChangeInfo.env = env;
    registerSandboxChangeInfo.callbackRef = callback;
    registerSandboxChangeInfo.changeType = type;
    registerSandboxChangeInfo.subscriber = std::make_shared<RegisterDlpSandboxChangeScopePtr>();
    registerSandboxChangeInfo.subscriber->SetEnv(env);
    registerSandboxChangeInfo.subscriber->SetCallbackRef(callback);
    std::shared_ptr<RegisterDlpSandboxChangeScopePtr> *subscriber =
        new (std::nothrow) std::shared_ptr<RegisterDlpSandboxChangeScopePtr>(registerSandboxChangeInfo.subscriber);
    if (subscriber == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to create subscriber");
        return false;
    }
    napi_wrap(
        env, thisVar, reinterpret_cast<void *>(subscriber),
        [](napi_env nev, void *data, void *hint) {
            DLP_LOG_DEBUG(LABEL, "RegisterDlpSandboxChangeScopePtr delete");
            std::shared_ptr<RegisterDlpSandboxChangeScopePtr> *subscriber =
                static_cast<std::shared_ptr<RegisterDlpSandboxChangeScopePtr> *>(data);
            if (subscriber != nullptr && *subscriber != nullptr) {
                (*subscriber)->SetValid(false);
                delete subscriber;
            }
        },
        nullptr, nullptr);
    return true;
}

bool GetUnregisterSandboxParams(const napi_env env, const napi_callback_info info,
    UnregisterSandboxChangeCallbackAsyncContext &asyncContext)
{
    DLP_LOG_INFO(LABEL, "enter GetUnregisterSandboxParams");
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.changeType)) {
        DLP_LOG_ERROR(LABEL, "js get changeType fail");
        ThrowParamError(env, "changeType", "string");
        return false;
    }

    if (asyncContext.changeType.compare(ON_OFF_SANDBOX) != 0) {
        ThrowParamError(env, "type", "uninstallsandbox");
        return false;
    }

    DLP_LOG_DEBUG(LABEL, "changeType: %{private}s", asyncContext.changeType.c_str());
    return true;
}

bool GetRetentionStateParams(const napi_env env, const napi_callback_info info,
    RetentionStateAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    if (!GetVectorDocUriByKey(env, argv[PARAM0], "docUris", asyncContext.docUris)) {
        DLP_LOG_ERROR(LABEL, "js get auth users fail");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "docUriVec size: %{private}zu", asyncContext.docUris.size());
    return true;
}

bool GetRetentionSandboxListParams(const napi_env env, const napi_callback_info info,
    GetRetentionSandboxListAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc == PARAM_SIZE_TWO) {
        if (!ParseCallback(env, argv[PARAM1], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
        if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
            DLP_LOG_ERROR(LABEL, "js get bundle name fail");
            ThrowParamError(env, "bundleName", "string");
            return false;
        }
    }
    if (argc == PARAM_SIZE_ONE) {
        if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName) &&
            !ParseCallback(env, argv[PARAM0], asyncContext.callbackRef)) {
            DLP_LOG_ERROR(LABEL, "js get bundle name or callback fail");
            ThrowParamError(env, "bundleName or callback", "string or function");
            return false;
        }
    }
    return true;
}

bool GetOriginalFilenameParams(const napi_env env, const napi_callback_info info,
    GetOriginalFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc == PARAM_SIZE_ONE) {
        if (!GetStringValue(env, argv[PARAM0], asyncContext.dlpFilename)) {
            ThrowParamError(env, "fileName", "string");
            return false;
        }
    }

    std::string filename = asyncContext.dlpFilename;
    size_t size = filename.size();
    if ((size <= DLP_FILE_SUFFIX.size()) || (size > MAX_FILE_NAME_LEN)) {
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, GetJsErrMsg(ERR_JS_INVALID_PARAMETER));
        return false;
    }

    if (filename.substr(filename.size() - DLP_FILE_SUFFIX.size()) != DLP_FILE_SUFFIX) {
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, GetJsErrMsg(ERR_JS_INVALID_PARAMETER));
        return false;
    }
    return true;
}

bool GetSandboxAppConfigParams(const napi_env env, const napi_callback_info info,
    SandboxAppConfigAsyncContext* asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (!NapiCheckArgc(env, argc, PARAM_SIZE_ONE)) {
        return false;
    }
    if (!GetStringValue(env, argv[PARAM0], asyncContext->configInfo)) {
        ThrowParamError(env, "config", "string");
        return false;
    }
    if (asyncContext->configInfo.empty()) {
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, GetJsErrMsg(ERR_JS_INVALID_PARAMETER));
        return false;
    }

    return true;
}

bool GetThirdInterfaceParams(
    const napi_env env, const napi_callback_info info, CommonAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc == PARAM_SIZE_ONE) {
        if (!ParseCallback(env, argv[PARAM0], asyncContext.callbackRef)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }
    return true;
}

void GetDlpPropertyExpireTime(napi_env env, napi_value jsObject, DlpProperty& property)
{
    int64_t jsExpireTime = 0;
    if (!GetInt64ValueByKey(env, jsObject, "expireTime", jsExpireTime)) {
        DLP_LOG_INFO(LABEL, "js get expity time fail, set zero");
    }
    property.expireTime = static_cast<uint64_t>(jsExpireTime);
}

bool GetDlpProperty(napi_env env, napi_value jsObject, DlpProperty& property)
{
    if (!GetStringValueByKey(env, jsObject, "ownerAccount", property.ownerAccount)) {
        DLP_LOG_ERROR(LABEL, "js get owner account fail");
        return false;
    }
    if (!GetStringValueByKey(env, jsObject, "ownerAccountID", property.ownerAccountId)) {
        DLP_LOG_ERROR(LABEL, "js get owner accountId fail");
        return false;
    }
    int64_t type;
    if (!GetInt64ValueByKey(env, jsObject, "ownerAccountType", type)) {
        DLP_LOG_ERROR(LABEL, "js get owner account type fail");
        return false;
    }
    property.ownerAccountType = static_cast<DlpAccountType>(type);
    napi_value authUserListObj = GetNapiValue(env, jsObject, "authUserList");
    if (authUserListObj != nullptr) {
        if (!GetVectorAuthUser(env, authUserListObj, property.authUsers)) {
            DLP_LOG_ERROR(LABEL, "js get auth users fail");
            return false;
        }
    }
    if (!GetStringValueByKey(env, jsObject, "contactAccount", property.contactAccount)) {
        DLP_LOG_ERROR(LABEL, "js get contact account fail");
        return false;
    }
    if (!GetBoolValueByKey(env, jsObject, "offlineAccess", property.offlineAccess)) {
        DLP_LOG_ERROR(LABEL, "js get offline access flag fail");
        return false;
    }
    GetDlpPropertyExpireTime(env, jsObject, property);

    napi_value everyoneAccessListObj = GetNapiValue(env, jsObject, "everyoneAccessList");
    if (everyoneAccessListObj != nullptr) {
        std::vector<uint32_t> permList = {};
        if (!GetVectorUint32(env, everyoneAccessListObj, permList)) {
            DLP_LOG_ERROR(LABEL, "js get everyoneAccessList fail");
            return false;
        }
        if (permList.size() > 0) {
            uint32_t perm = *(std::max_element(permList.begin(), permList.end()));
            property.everyonePerm = static_cast<DLPFileAccess>(perm);
            property.supportEveryone = true;
        }
    }
    return true;
}

napi_value RetentionSandboxInfoToJs(napi_env env, const std::vector<RetentionSandBoxInfo>& infoVec)
{
    napi_value vectorJs = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &vectorJs));
    for (auto item : infoVec) {
        napi_value objInfo = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objInfo));

        napi_value appIndexJs;
        NAPI_CALL(env, napi_create_int32(env, item.appIndex_, &appIndexJs));
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "appIndex", appIndexJs));
        DLP_LOG_INFO(LABEL, "GetAppIndex %{public}d", item.appIndex_);
        napi_value bundleNameJs;
        NAPI_CALL(env, napi_create_string_utf8(env, item.bundleName_.c_str(), NAPI_AUTO_LENGTH, &bundleNameJs));
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "bundleName", bundleNameJs));

        napi_value docUriVecJs = SetStringToJs(env, item.docUriSet_);
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "docUris", docUriVecJs));

        NAPI_CALL(env, napi_set_element(env, vectorJs, index, objInfo));
        index++;
    }
    return vectorJs;
}

napi_value VisitInfoToJs(napi_env env, const std::vector<VisitedDLPFileInfo>& infoVec)
{
    napi_value vectorJs = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &vectorJs));
    for (auto& item : infoVec) {
        napi_value objInfo = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objInfo));

        napi_value timestampJs;
        NAPI_CALL(env, napi_create_int64(env, item.visitTimestamp, &timestampJs));
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "lastOpenTime", timestampJs));
        DLP_LOG_DEBUG(LABEL, "Get visitTimestamp %{public}" PRId64, item.visitTimestamp);
        napi_value uriJs;
        NAPI_CALL(env, napi_create_string_utf8(env, item.docUri.c_str(), NAPI_AUTO_LENGTH, &uriJs));
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "uri", uriJs));

        NAPI_CALL(env, napi_set_element(env, vectorJs, index, objInfo));
        index++;
    }
    return vectorJs;
}

napi_value DlpPropertyToJs(napi_env env, const DlpProperty& property)
{
    napi_value dlpPropertyJs = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dlpPropertyJs));

    napi_value everyoneAccessListJs = nullptr;
    if (property.supportEveryone) {
        everyoneAccessListJs = VectorUint32ToJs(env, {property.everyonePerm});
    } else {
        everyoneAccessListJs = VectorUint32ToJs(env, {});
    }
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "everyoneAccessList", everyoneAccessListJs));

    napi_value offlineAccessJs;
    napi_get_boolean(env, property.offlineAccess, &offlineAccessJs);
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "offlineAccess", offlineAccessJs));

    napi_value expireTimeJs;
    napi_create_int64(env, property.expireTime, &expireTimeJs);
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "expireTime", expireTimeJs));

    napi_value ownerAccountJs;
    NAPI_CALL(env, napi_create_string_utf8(env, property.ownerAccount.c_str(), NAPI_AUTO_LENGTH, &ownerAccountJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "ownerAccount", ownerAccountJs));

    napi_value ownerAccountIdJs;
    NAPI_CALL(env, napi_create_string_utf8(env, property.ownerAccountId.c_str(), NAPI_AUTO_LENGTH, &ownerAccountIdJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "ownerAccountID", ownerAccountIdJs));

    napi_value vectorAuthUserJs = VectorAuthUserToJs(env, property.authUsers);
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "authUserList", vectorAuthUserJs));

    napi_value contractAccountJs;
    NAPI_CALL(
        env, napi_create_string_utf8(env, property.contactAccount.c_str(), NAPI_AUTO_LENGTH, &contractAccountJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "contactAccount", contractAccountJs));

    napi_value ownerAccountTypeJs;
    NAPI_CALL(env, napi_create_int64(env, property.ownerAccountType, &ownerAccountTypeJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "ownerAccountType", ownerAccountTypeJs));

    return dlpPropertyJs;
}

napi_value DlpPermissionInfoToJs(napi_env env, const DLPPermissionInfo& permInfo)
{
    napi_value dlpPermInfoJs = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dlpPermInfoJs));

    napi_value accessJs;
    NAPI_CALL(env, napi_create_uint32(env, permInfo.dlpFileAccess, &accessJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPermInfoJs, "dlpFileAccess", accessJs));

    napi_value flagsJs;
    NAPI_CALL(env, napi_create_uint32(env, permInfo.flags, &flagsJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPermInfoJs, "flags", flagsJs));

    return dlpPermInfoJs;
}

napi_value SandboxInfoToJs(napi_env env, const SandboxInfo& sandboxInfo)
{
    napi_value sandboxInfoJs = nullptr;
    NAPI_CALL(env, napi_create_object(env, &sandboxInfoJs));

    napi_value appIndexJs;
    NAPI_CALL(env, napi_create_int64(env, sandboxInfo.appIndex, &appIndexJs));
    NAPI_CALL(env, napi_set_named_property(env, sandboxInfoJs, "appIndex", appIndexJs));

    napi_value tokenIdJs;
    NAPI_CALL(env, napi_create_int64(env, sandboxInfo.tokenId, &tokenIdJs));
    NAPI_CALL(env, napi_set_named_property(env, sandboxInfoJs, "tokenID", tokenIdJs));

    return sandboxInfoJs;
}

napi_value VectorAuthUserToJs(napi_env env, const std::vector<AuthUserInfo>& users)
{
    napi_value vectorAuthUserJs = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &vectorAuthUserJs));
    for (auto item : users) {
        napi_value objAuthUserInfo = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objAuthUserInfo));

        napi_value authAccountJs;
        NAPI_CALL(env, napi_create_string_utf8(env, item.authAccount.c_str(), NAPI_AUTO_LENGTH, &authAccountJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "authAccount", authAccountJs));

        napi_value authPermJs;
        NAPI_CALL(env, napi_create_int64(env, item.authPerm, &authPermJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "dlpFileAccess", authPermJs));

        napi_value permExpiryTimeJs;
        NAPI_CALL(env, napi_create_int64(env, item.permExpiryTime, &permExpiryTimeJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "permExpiryTime", permExpiryTimeJs));

        napi_value authAccountTypeJs;
        NAPI_CALL(env, napi_create_int64(env, item.authAccountType, &authAccountTypeJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "authAccountType", authAccountTypeJs));

        NAPI_CALL(env, napi_set_element(env, vectorAuthUserJs, index, objAuthUserInfo));
        index++;
    }
    return vectorAuthUserJs;
}

napi_value VectorStringToJs(napi_env env, const std::vector<std::string>& value)
{
    napi_value jsArray = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &jsArray));
    for (const auto& iter : value) {
        napi_value jsValue = nullptr;
        if (napi_create_string_utf8(env, iter.c_str(), NAPI_AUTO_LENGTH, &jsValue) == napi_ok) {
            if (napi_set_element(env, jsArray, index, jsValue) == napi_ok) {
                index++;
            }
        }
    }
    return jsArray;
}

napi_value VectorUint32ToJs(napi_env env, const std::vector<uint32_t>& value)
{
    napi_value jsArray = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &jsArray));
    for (const auto& iter : value) {
        napi_value jsValue = nullptr;
        if (napi_create_int64(env, iter, &jsValue) == napi_ok) {
            if (napi_set_element(env, jsArray, index, jsValue) == napi_ok) {
                index++;
            }
        }
    }
    return jsArray;
}

napi_value SetStringToJs(napi_env env, const std::set<std::string>& value)
{
    napi_value jsArray = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &jsArray));
    for (const auto& iter : value) {
        napi_value jsValue = nullptr;
        if (napi_create_string_utf8(env, iter.c_str(), NAPI_AUTO_LENGTH, &jsValue) == napi_ok) {
            if (napi_set_element(env, jsArray, index, jsValue) == napi_ok) {
                index++;
            } else {
                DLP_LOG_ERROR(LABEL, "napi_set_element error index:%{public}d,value:%{private}s", index, iter.c_str());
            }
        } else {
            DLP_LOG_ERROR(LABEL, "napi_create_string_utf8 error index:%{public}d,value:%{private}s", index,
                iter.c_str());
        }
    }
    return jsArray;
}

bool ParseCallback(const napi_env& env, const napi_value& value, napi_ref& callbackRef)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);

    if (valuetype == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, value, 1, &callbackRef), false);
        return true;
    }
    if (valuetype == napi_null || valuetype == napi_undefined) {
        return true;
    }
    return false;
}

napi_value GetNapiValue(napi_env env, napi_value jsObject, const std::string& key)
{
    if (jsObject == nullptr) {
        DLP_LOG_ERROR(LABEL, "Js object is nullptr");
        return nullptr;
    }
    napi_value keyValue;
    NAPI_CALL(env, napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &keyValue));
    bool result = false;
    NAPI_CALL(env, napi_has_property(env, jsObject, keyValue, &result));
    if (result) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_property(env, jsObject, keyValue, &value));
        return value;
    }
    DLP_LOG_ERROR(LABEL, "get napi value fail");
    return nullptr;
}

bool GetStringValue(napi_env env, napi_value jsObject, std::string& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_string) {
        DLP_LOG_ERROR(LABEL, "object is no a string");
        return false;
    }

    size_t size = 0;
    if (napi_get_value_string_utf8(env, jsObject, nullptr, 0, &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get string size");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, jsObject, result.data(), (size + 1), &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get string value");
        return false;
    }
    return true;
}

bool GetStringValueByKey(napi_env env, napi_value jsObject, const std::string& key, std::string& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetStringValue(env, value, result);
}

bool GetBoolValue(napi_env env, napi_value jsObject, bool& result)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, jsObject, &valuetype) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }

    if (valuetype != napi_boolean) {
        DLP_LOG_ERROR(LABEL, "Wrong argument type. Boolean expected.");
        return false;
    }

    napi_get_value_bool(env, jsObject, &result);
    return true;
}

bool GetBoolValueByKey(napi_env env, napi_value jsObject, const std::string& key, bool& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetBoolValue(env, value, result);
}

bool GetInt64Value(napi_env env, napi_value jsObject, int64_t& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_number) {
        DLP_LOG_ERROR(LABEL, "object is no a number");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int64(env, jsObject, &result), false);
    return true;
}

bool GetInt64ValueByKey(napi_env env, napi_value jsObject, const std::string& key, int64_t& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetInt64Value(env, value, result);
}

bool GetUint32Value(napi_env env, napi_value jsObject, uint32_t& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_number) {
        DLP_LOG_ERROR(LABEL, "object is no a number");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_uint32(env, jsObject, &result), false);
    return true;
}

bool GetUint32ValueByKey(napi_env env, napi_value jsObject, const std::string& key, uint32_t& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetUint32Value(env, value, result);
}

napi_value GetArrayValueByKey(napi_env env, napi_value jsObject, const std::string& key)
{
    napi_value array = GetNapiValue(env, jsObject, key);
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, array, &isArray));
    if (!isArray) {
        DLP_LOG_ERROR(LABEL, "value is not array");
        return nullptr;
    }
    return array;
}

bool GetVectorAuthUser(napi_env env, napi_value jsObject, std::vector<AuthUserInfo>& resultVec)
{
    uint32_t size = 0;
    if (napi_get_array_length(env, jsObject, &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "js get array size fail");
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        napi_value obj;
        NAPI_CALL_BASE(env, napi_get_element(env, jsObject, i, &obj), false);
        AuthUserInfo userInfo;
        if (!GetStringValueByKey(env, obj, "authAccount", userInfo.authAccount)) {
            DLP_LOG_ERROR(LABEL, "js get auth account fail");
            resultVec.clear();
            return false;
        }
        int64_t perm;
        if (!GetInt64ValueByKey(env, obj, "dlpFileAccess", perm)) {
            DLP_LOG_ERROR(LABEL, "js get auth perm fail");
            resultVec.clear();
            return false;
        }
        userInfo.authPerm = static_cast<DLPFileAccess>(perm);
        int64_t time;
        if (!GetInt64ValueByKey(env, obj, "permExpiryTime", time)) {
            DLP_LOG_ERROR(LABEL, "js get time fail");
            resultVec.clear();
            return false;
        }
        userInfo.permExpiryTime = static_cast<uint64_t>(time);
        int64_t type;
        if (!GetInt64ValueByKey(env, obj, "authAccountType", type)) {
            DLP_LOG_ERROR(LABEL, "js get type fail");
            resultVec.clear();
            return false;
        }
        userInfo.authAccountType = static_cast<DlpAccountType>(type);
        resultVec.push_back(userInfo);
    }
    return true;
}

bool GetVectorAuthUserByKey(
    napi_env env, napi_value jsObject, const std::string& key, std::vector<AuthUserInfo>& resultVec)
{
    napi_value userArray = GetArrayValueByKey(env, jsObject, key);
    if (userArray == nullptr) {
        DLP_LOG_ERROR(LABEL, "User array is null");
        return false;
    }
    return GetVectorAuthUser(env, userArray, resultVec);
}

bool GetVectorDocUriByKey(napi_env env, napi_value jsObject, const std::string& key,
    std::vector<std::string>& docUriVec)
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
        std::string docUri;
        if (!GetStringValue(env, obj, docUri)) {
            DLP_LOG_ERROR(LABEL, "js get docUri fail");
            ThrowParamError(env, "docUri", "string");
            return false;
        }
        docUriVec.push_back(docUri);
    }
    return true;
}

bool GetVectorUint32(napi_env env, napi_value jsObject, std::vector<uint32_t>& resultVec)
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
        uint32_t num;
        if (!GetUint32Value(env, obj, num)) {
            DLP_LOG_ERROR(LABEL, "js get num fail");
            return false;
        }
        resultVec.emplace_back(num);
    }
    return true;
}

bool ParseUIAbilityContextReq(
    napi_env env, const napi_value& obj, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, obj, stageMode);
    if (status != napi_ok || !stageMode) {
        DLP_LOG_ERROR(LABEL, "not stage mode");
        return false;
    }

    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, obj);
    if (context == nullptr) {
        DLP_LOG_ERROR(LABEL, "get context failed");
        return false;
    }

    abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "get abilityContext failed");
        return false;
    }
    DLP_LOG_DEBUG(LABEL, "end ParseUIAbilityContextReq");
    return true;
}

bool ParseWantReq(napi_env env, const napi_value& obj, OHOS::AAFwk::Want& requestWant)
{
    requestWant.SetElementName(DLP_MANAGER_BUNDLENAME, DLP_MANAGER_ABILITYNAME);
    std::string uri;
    bool ret = GetStringValueByKey(env, obj, "uri", uri);
    if (!ret || uri.empty()) {
        DLP_LOG_ERROR(LABEL, "get uri failed");
        DlpNapiThrow(env, ERR_JS_URI_NOT_EXIST, "uri not exist in want");
        return false;
    }
    requestWant.SetUri(uri);

    napi_value wantParameters = GetNapiValue(env, obj, "parameters");
    if (wantParameters == nullptr) {
        DLP_LOG_ERROR(LABEL, "get wantParameters failed");
        DlpNapiThrow(env, ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST, "parameters not exist in want");
        return false;
    }
    std::string displayName;
    ret = GetStringValueByKey(env, wantParameters, "displayName", displayName);
    if (!ret || displayName.empty()) {
        DLP_LOG_ERROR(LABEL, "get displayName failed");
        DlpNapiThrow(env, ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST, "displayName not exist in want parameters");
        return false;
    }
    AAFwk::WantParams requestWantParam;
    requestWantParam.SetParam("displayName", AAFwk::String::Box(displayName));
    AAFwk::WantParams fileNameObj;
    fileNameObj.SetParam("name", AAFwk::String::Box(displayName));
    requestWantParam.SetParam("fileName", AAFwk::WantParamWrapper::Box(fileNameObj));

    napi_status result = napi_has_named_property(env, wantParameters, "linkFileName", &ret);
    if (result == napi_ok && ret) {
        napi_value linkFileName = GetNapiValue(env, wantParameters, "linkFileName");
        std::string linkFileNameStr;
        ret = GetStringValueByKey(env, linkFileName, "name", linkFileNameStr);
        if (ret && !linkFileNameStr.empty()) {
            AAFwk::WantParams linkFileNameObj;
            linkFileNameObj.SetParam("name", AAFwk::String::Box(linkFileNameStr));
            requestWantParam.SetParam("linkFileName", AAFwk::WantParamWrapper::Box(linkFileNameObj));
            DLP_LOG_DEBUG(LABEL, "set linkFileName");
        }
    }

    requestWant.SetParams(requestWantParam);
    requestWant.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    DLP_LOG_DEBUG(LABEL, "end ParseWantReq");
    return true;
}

void StartUIExtensionAbility(std::shared_ptr<UIExtensionRequestContext> asyncContext)
{
    DLP_LOG_DEBUG(LABEL, "begin StartUIExtensionAbility");
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is null");
        return;
    }
    auto abilityContext = asyncContext->context;
    if (abilityContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "abilityContext is null");
        DlpNapiThrow(asyncContext->env, ERR_JS_INVALID_PARAMETER, "abilityContext is null");
        return;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        DLP_LOG_ERROR(LABEL, "uiContent is null");
        DlpNapiThrow(asyncContext->env, ERR_JS_INVALID_PARAMETER, "uiContent is null");
        return;
    }

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        std::bind(&UIExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnResult, uiExtCallback, std::placeholders::_1, std::placeholders::_2),
        std::bind(&UIExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnError, uiExtCallback, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3),
        std::bind(&UIExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnDestroy, uiExtCallback)
    };

    OHOS::Ace::ModalUIExtensionConfig uiExtConfig;
    uiExtConfig.isProhibitBack = false;
    int32_t sessionId = uiContent->CreateModalUIExtension(asyncContext->requestWant, extensionCallbacks, uiExtConfig);
    DLP_LOG_INFO(LABEL, "end CreateModalUIExtension sessionId = %{public}d", sessionId);
    if (sessionId == 0) {
        DLP_LOG_ERROR(LABEL, "CreateModalUIExtension failed, sessionId is %{public}d", sessionId);
    }
    uiExtCallback->SetSessionId(sessionId);
    return;
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<UIExtensionRequestContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

bool UIExtensionCallback::SetErrorCode(int32_t code)
{
    if (this->reqContext_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "OnError reqContext is nullptr");
        return false;
    }
    if (this->alreadyCallback_) {
        DLP_LOG_DEBUG(LABEL, "alreadyCallback");
        return false;
    }
    this->alreadyCallback_ = true;
    this->reqContext_->errCode = code;
    return true;
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    DLP_LOG_DEBUG(LABEL, "UIExtensionComponent OnRelease(), releaseCode = %{public}d", releaseCode);
    if (SetErrorCode(releaseCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    DLP_LOG_DEBUG(LABEL, "UIExtensionComponent OnResult(), resultCode = %{public}d", resultCode);
    this->resultCode_ = resultCode;
    this->resultWant_ = result;
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    DLP_LOG_DEBUG(LABEL, "UIExtensionComponent OnReceive()");
}

void UIExtensionCallback::OnError(int32_t errorCode, const std::string& name, const std::string& message)
{
    DLP_LOG_ERROR(LABEL,
        "UIExtensionComponent OnError(), errorCode = %{public}d, name = %{public}s, message = %{public}s",
        errorCode, name.c_str(), message.c_str());
    if (SetErrorCode(errorCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    DLP_LOG_DEBUG(LABEL, "UIExtensionComponent OnRemoteReady()");
}

void UIExtensionCallback::OnDestroy()
{
    DLP_LOG_DEBUG(LABEL, "UIExtensionComponent OnDestroy()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::SendMessageBack()
{
    DLP_LOG_INFO(LABEL, "start SendMessageBack");
    if (this->reqContext_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "reqContext is nullptr");
        return;
    }

    auto abilityContext = this->reqContext_->context;
    if (abilityContext != nullptr) {
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent != nullptr) {
            DLP_LOG_DEBUG(LABEL, "CloseModalUIExtension");
            uiContent->CloseModalUIExtension(this->sessionId_);
        }
    }

    napi_value nativeObjJs = nullptr;
    NAPI_CALL_RETURN_VOID(this->reqContext_->env, napi_create_object(this->reqContext_->env, &nativeObjJs));
    napi_value resultCode = nullptr;
    NAPI_CALL_RETURN_VOID(this->reqContext_->env,
        napi_create_int32(this->reqContext_->env, this->resultCode_, &resultCode));
    NAPI_CALL_RETURN_VOID(this->reqContext_->env,
        napi_set_named_property(this->reqContext_->env, nativeObjJs, "resultCode", resultCode));
    napi_value resultWant = nullptr;
    resultWant = OHOS::AppExecFwk::WrapWant(this->reqContext_->env, this->resultWant_);
    NAPI_CALL_RETURN_VOID(this->reqContext_->env,
        napi_set_named_property(this->reqContext_->env, nativeObjJs, "want", resultWant));

    DLP_LOG_DEBUG(LABEL, "ProcessCallbackOrPromise");
    ProcessCallbackOrPromise(this->reqContext_->env, this->reqContext_.get(), nativeObjJs);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
