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

#include "napi_common.h"
#include "dlp_permission_log.h"
#include "napi_error_msg.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionCommon"};
const std::string PARAM_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string SYS_COMMON_UI = "sys/commonUI";
const std::string DLP_MANAGER_BUNDLENAME = "com.ohos.dlpmanager";
const std::string DLP_MANAGER_ABILITYNAME = "MainAbilityEx";
static constexpr size_t MAX_FILE_NAME_LEN = 255;
static constexpr size_t MAX_URI_LEN = 4095;

static bool ParseWantUri(napi_env env, const napi_value& obj, OHOS::AAFwk::Want& requestWant, std::string& uri)
{
    if (!GetStringValueByKey(env, obj, "uri", uri)) {
        DLP_LOG_ERROR(LABEL, "get uri failed");
        DlpNapiThrow(env, ERR_JS_URI_NOT_EXIST, "uri not exist in want");
        return false;
    }
    if (!IsStringLengthValid(uri, MAX_URI_LEN) || uri.empty()) {
        DLP_LOG_ERROR(LABEL, "uri length is invalid");
        DlpNapiThrow(env, ERR_JS_URI_NOT_EXIST, "uri length is invalid");
        return false;
    }
    requestWant.SetUri(uri);
    return true;
}

static bool ParseWantParameters(napi_env env, const napi_value& obj, napi_value& wantParameters)
{
    wantParameters = GetNapiValue(env, obj, "parameters");
    if (wantParameters == nullptr) {
        DLP_LOG_ERROR(LABEL, "get wantParameters failed");
        DlpNapiThrow(env, ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST, "parameters not exist in want");
        return false;
    }
    return true;
}

static bool ParseDisplayName(napi_env env, napi_value wantParameters, std::string& displayName)
{
    if (!GetStringValueByKey(env, wantParameters, "displayName", displayName)) {
        DLP_LOG_ERROR(LABEL, "get displayName failed");
        DlpNapiThrow(env, ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST, "displayName not exist in want parameters");
        return false;
    }
    if (!IsStringLengthValid(displayName, MAX_FILE_NAME_LEN) || displayName.empty()) {
        DLP_LOG_ERROR(LABEL, "displayName length is invalid");
        DlpNapiThrow(env, ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST, "displayName length is invalid");
        return false;
    }
    return true;
}

static void BuildWantParams(AAFwk::WantParams& requestWantParam, const std::string& displayName)
{
    requestWantParam.SetParam("displayName", AAFwk::String::Box(displayName));
    AAFwk::WantParams fileNameObj;
    fileNameObj.SetParam("name", AAFwk::String::Box(displayName));
    requestWantParam.SetParam("fileName", AAFwk::WantParamWrapper::Box(fileNameObj));
}

static void ParseLinkFileName(napi_env env, napi_value wantParameters, AAFwk::WantParams& requestWantParam)
{
    bool ret = false;
    napi_status result = napi_has_named_property(env, wantParameters, "linkFileName", &ret);
    if (result == napi_ok && ret) {
        napi_value linkFileName = GetNapiValue(env, wantParameters, "linkFileName");
        std::string linkFileNameStr;
        if (!GetStringValueByKey(env, linkFileName, "name", linkFileNameStr)) {
            DLP_LOG_ERROR(LABEL, "linkFileName.name is not a valid string");
            return;
        }
        if (!IsStringLengthValid(linkFileNameStr, MAX_FILE_NAME_LEN)) {
            DLP_LOG_ERROR(LABEL, "linkFileName.name length exceeds limit, len=%{public}zu",
                linkFileNameStr.length());
            return;
        }
        if (!linkFileNameStr.empty()) {
            AAFwk::WantParams linkFileNameObj;
            linkFileNameObj.SetParam("name", AAFwk::String::Box(linkFileNameStr));
            requestWantParam.SetParam("linkFileName", AAFwk::WantParamWrapper::Box(linkFileNameObj));
            DLP_LOG_DEBUG(LABEL, "set linkFileName");
        }
    }
}

static bool GetWindowProperties(napi_env env, napi_value windowObj, napi_value& properties)
{
    napi_value getPropertiesFunc = nullptr;
    napi_status getStatus = napi_get_named_property(env, windowObj, "getWindowProperties", &getPropertiesFunc);
    if (getStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_named_property getWindowProperties failed");
        return false;
    }
    napi_valuetype funcType = napi_undefined;
    napi_status typeofStatus = napi_typeof(env, getPropertiesFunc, &funcType);
    if (typeofStatus != napi_ok || funcType != napi_function) {
        DLP_LOG_ERROR(LABEL, "getWindowProperties is not a function");
        return false;
    }
    napi_status callStatus = napi_call_function(env, windowObj, getPropertiesFunc, 0, nullptr, &properties);
    if (callStatus != napi_ok || properties == nullptr) {
        DLP_LOG_ERROR(LABEL, "getPropertiesFunc call failed or returned null");
        return false;
    }
    return true;
}

static bool GetWindowNameFromProperties(napi_env env, napi_value properties, std::string& windowName)
{
    napi_value nameValue = nullptr;
    napi_status getStatus = napi_get_named_property(env, properties, "name", &nameValue);
    if (getStatus != napi_ok || nameValue == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get window name");
        return false;
    }
    napi_valuetype nameType = napi_undefined;
    napi_status typeofStatus = napi_typeof(env, nameValue, &nameType);
    if (typeofStatus != napi_ok || nameType != napi_string) {
        DLP_LOG_ERROR(LABEL, "Window name is not a string");
        return false;
    }
    size_t nameLen = 0;
    napi_status strStatus = napi_get_value_string_utf8(env, nameValue, nullptr, 0, &nameLen);
    if (strStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_value_string_utf8 get length failed for window name");
        return false;
    }
    if (nameLen == 0 || nameLen > MAX_FILE_NAME_LEN) {
        DLP_LOG_ERROR(LABEL, "Window name length is invalid, len=%{public}zu", nameLen);
        return false;
    }
    windowName.reserve(nameLen + 1);
    windowName.resize(nameLen);
    strStatus = napi_get_value_string_utf8(env, nameValue, windowName.data(), nameLen + 1, &nameLen);
    if (strStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "napi_get_value_string_utf8 failed for window name");
        return false;
    }
    DLP_LOG_INFO(LABEL, "Got window name: %{public}s", windowName.c_str());
    return true;
}

static bool GetWindowNameFromObj(napi_env env, napi_value windowObj, std::string& windowName)
{
    DLP_LOG_DEBUG(LABEL, "begin GetWindowNameFromObj");
    napi_value properties = nullptr;
    if (!GetWindowProperties(env, windowObj, properties)) {
        DLP_LOG_ERROR(LABEL, "GetWindowProperties failed");
        return false;
    }
    return GetWindowNameFromProperties(env, properties, windowName);
}
} // namespace

bool ParseWantReq(napi_env env, const napi_value& obj, OHOS::AAFwk::Want& requestWant)
{
    requestWant.SetElementName(DLP_MANAGER_BUNDLENAME, DLP_MANAGER_ABILITYNAME);
    std::string uri;
    if (!ParseWantUri(env, obj, requestWant, uri)) {
        return false;
    }
    napi_value wantParameters;
    if (!ParseWantParameters(env, obj, wantParameters)) {
        return false;
    }
    std::string displayName;
    if (!ParseDisplayName(env, wantParameters, displayName)) {
        return false;
    }
    AAFwk::WantParams requestWantParam;
    BuildWantParams(requestWantParam, displayName);
    ParseLinkFileName(env, wantParameters, requestWantParam);
    requestWant.SetParams(requestWantParam);
    requestWant.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    DLP_LOG_DEBUG(LABEL, "end ParseWantReq");
    return true;
}

OHOS::Ace::ModalUIExtensionCallbacks CreateExtensionCallbacks(
    std::shared_ptr<UIExtensionCallback>& uiExtCallback)
{
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string& name, const std::string& message) {
            uiExtCallback->OnError(errorCode, name, message); },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }
    };
    return extensionCallbacks;
}

void StartUIExtensionAbility(std::shared_ptr<UIExtensionRequestContext> asyncContext)
{
    DLP_LOG_DEBUG(LABEL, "begin StartUIExtensionAbility");
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is null");
        return;
    }
    int32_t errCode = ERR_JS_INVALID_PARAMETER;
    const char* errMsg = "StartUIExtensionAbility failed";
    do {
        auto abilityContext = asyncContext->context;
        if (abilityContext == nullptr) {
            DLP_LOG_ERROR(LABEL, "abilityContext is null");
            errMsg = "abilityContext is null";
            break;
        }
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent == nullptr) {
            DLP_LOG_ERROR(LABEL, "uiContent is null");
            errMsg = "uiContent is null";
            break;
        }

        auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
        auto extensionCallbacks = CreateExtensionCallbacks(uiExtCallback);

        OHOS::Ace::ModalUIExtensionConfig uiExtConfig;
        uiExtConfig.isProhibitBack = false;
        int32_t sessionId =
            uiContent->CreateModalUIExtension(asyncContext->requestWant, extensionCallbacks, uiExtConfig);
        DLP_LOG_INFO(LABEL, "end CreateModalUIExtension sessionId = %{public}d", sessionId);
        if (sessionId == 0) {
            DLP_LOG_ERROR(LABEL, "CreateModalUIExtension failed, sessionId is %{public}d", sessionId);
            errCode = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            errMsg = "CreateModalUIExtension failed";
            break;
        }
        uiExtCallback->SetSessionId(sessionId);
        return;
    } while (0);

    napi_value error = GenerateBusinessError(asyncContext->env, errCode, errMsg);
    napi_reject_deferred(asyncContext->env, asyncContext->deferred, error);
    asyncContext->deferred = nullptr;
}

bool GetCustomShowingWindow(napi_env env, napi_value windowObj, sptr<Rosen::Window>& window)
{
    DLP_LOG_DEBUG(LABEL, "begin GetCustomShowingWindow");
    if (windowObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "window argument is null");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_status typeofStatus = napi_typeof(env, windowObj, &valueType);
    if (typeofStatus != napi_ok || valueType != napi_object) {
        DLP_LOG_ERROR(LABEL, "Window argument is not an object");
        return false;
    }
    std::string windowName;
    if (!GetWindowNameFromObj(env, windowObj, windowName)) {
        DLP_LOG_ERROR(LABEL, "GetWindowNameFromObj failed");
        return false;
    }
    auto foundWindow = Rosen::Window::Find(windowName);
    if (foundWindow == nullptr) {
        DLP_LOG_ERROR(LABEL, "Window not found by name: %{public}s", windowName.c_str());
        return false;
    }
    window = foundWindow;
    DLP_LOG_INFO(LABEL, "GetCustomShowingWindow success");
    return true;
}

void StartUIExtensionAbilityWithWindow(std::shared_ptr<UIExtensionRequestContext> asyncContext)
{
    DLP_LOG_DEBUG(LABEL, "begin StartUIExtensionAbilityWithWindow");
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is null");
        return;
    }
    int32_t errCode = ERR_JS_INVALID_PARAMETER;
    const char* errMsg = "StartUIExtensionAbilityWithWindow failed";
    do {
        auto window = asyncContext->window;
        if (window == nullptr) {
            DLP_LOG_ERROR(LABEL, "window is null");
            errMsg = "window is null";
            break;
        }
        auto uiContent = window->GetUIContent();
        if (uiContent == nullptr) {
            DLP_LOG_ERROR(LABEL, "uiContent is null");
            errMsg = "uiContent is null";
            break;
        }
        asyncContext->uiContent = uiContent;

        auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
        auto extensionCallbacks = CreateExtensionCallbacks(uiExtCallback);

        OHOS::Ace::ModalUIExtensionConfig uiExtConfig;
        uiExtConfig.isProhibitBack = false;
        int32_t sessionId =
            uiContent->CreateModalUIExtension(asyncContext->requestWant, extensionCallbacks, uiExtConfig);
        DLP_LOG_INFO(LABEL, "end CreateModalUIExtension sessionId = %{public}d", sessionId);
        if (sessionId == 0) {
            DLP_LOG_ERROR(LABEL, "CreateModalUIExtension failed, sessionId is %{public}d", sessionId);
            errCode = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            errMsg = "CreateModalUIExtension failed";
            break;
        }
        uiExtCallback->SetSessionId(sessionId);
        return;
    } while (0);

    napi_value error = GenerateBusinessError(asyncContext->env, errCode, errMsg);
    napi_reject_deferred(asyncContext->env, asyncContext->deferred, error);
    asyncContext->deferred = nullptr;
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

    if (this->reqContext_->uiContent != nullptr) {
        DLP_LOG_DEBUG(LABEL, "CloseModalUIExtension via window uiContent");
        this->reqContext_->uiContent->CloseModalUIExtension(this->sessionId_);
    } else {
        auto abilityContext = this->reqContext_->context;
        if (abilityContext != nullptr) {
            auto uiContent = abilityContext->GetUIContent();
            if (uiContent != nullptr) {
                DLP_LOG_DEBUG(LABEL, "CloseModalUIExtension");
                uiContent->CloseModalUIExtension(this->sessionId_);
            }
        }
    }

    if (this->reqContext_->window != nullptr) {
        DLP_LOG_WARN(LABEL,
            "SendMessageBack: caller-provided window is still alive after modal closed. "
            "Caller MUST call window.destroyWindow() to release it, otherwise the window will leak.");
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