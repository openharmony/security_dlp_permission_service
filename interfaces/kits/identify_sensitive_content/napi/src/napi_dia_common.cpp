/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "napi_dia_common.h"
#include "napi_dia_error_msg.h"
#include "napi_dia_log_adapter.h"

namespace OHOS::Security::DIA {

CommonAsyncContext::CommonAsyncContext(napi_env napiEnv)
{
    env = napiEnv;
}

CommonAsyncContext::~CommonAsyncContext()
{
    if (callbackRef) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (work) {
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

napi_value GenerateBusinessError(napi_env env, int32_t diaErrCode, const std::string &diaErrMsg)
{
    napi_value errCodeJs = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, diaErrCode, &errCodeJs));

    napi_value errMsgJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, diaErrMsg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs));

    napi_value errJs = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, errMsgJs, &errJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "code", errCodeJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "message", errMsgJs));
    return errJs;
}

bool IsArrayFromNapiValue(napi_env env, napi_value args, uint32_t &length)
{
    bool isArray = false;
    if (napi_is_array(env, args, &isArray) != napi_ok || !isArray) {
        LOG_ERROR("can not get array");
        return false;
    }
    if (napi_get_array_length(env, args, &length) != napi_ok) {
        LOG_ERROR("can not get array length");
        return false;
    }
    return true;
}

bool GetStringFromNAPI(napi_env env, napi_value value, std::string &resultStr)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        LOG_ERROR("can not get string size");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        LOG_ERROR("can not get string value");
        return false;
    }
    resultStr = result;
    return true;
}

bool NapiParseString(napi_env env, std::string &param, napi_value args)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, args, &valuetype) != napi_ok || valuetype != napi_string ||
        !GetStringFromNAPI(env, args, param)) {
        LOG_ERROR("can not get napi type or type is not string");
        return false;
    }
    return true;
}

napi_value GetNapiValue(napi_env env, napi_value element, const std::string &key)
{
    if (element == nullptr) {
        LOG_ERROR("element is nullptr");
        return nullptr;
    }
    napi_value keyValue;
    NAPI_CALL(env, napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &keyValue));
    bool result = false;
    NAPI_CALL(env, napi_has_property(env, element, keyValue, &result));
    if (result) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_property(env, element, keyValue, &value));
        return value;
    }
    LOG_ERROR("get napi value fail");
    return nullptr;
}

bool GetStringValueByKey(napi_env env, napi_value jsObject, const std::string &key, std::string &result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return NapiParseString(env, result, value);
}

bool GetStringArrayValueByKey(
    napi_env env, napi_value jsObject, const std::string &key, std::vector<std::string> &result)
{
    napi_value arrayValue = GetNapiValue(env, jsObject, key);
    uint32_t length = 0;
    if (!IsArrayFromNapiValue(env, arrayValue, length)) {
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        NAPI_CALL_BASE(env, napi_get_element(env, arrayValue, i, &element), false);
        std::string keywords;
        if (!NapiParseString(env, keywords, element)) {
            LOG_ERROR("get the value of keywords failed");
            return false;
        }
        result.emplace_back(keywords);
    }
    return true;
}

#ifdef FILE_IDENTIFY_ENABLE
bool NapiParsePolicy(napi_env env, napi_value jsObject, Policy &policy)
{
    if (!GetStringValueByKey(env, jsObject, "sensitiveLabel", policy.sensitiveLabel)) {
        LOG_ERROR("get napi sensitiveLabel value fail");
        return false;
    }
    if (!GetStringArrayValueByKey(env, jsObject, "keywords", policy.keywords)) {
        LOG_ERROR("get napi keywords value fail");
        return false;
    }
    if (!GetStringValueByKey(env, jsObject, "regex", policy.regex)) {
        LOG_ERROR("get napi regex value fail");
        return false;
    }
    return true;
}

bool NapiParsePolicyArray(napi_env env, std::vector<Policy> &policies, napi_value args)
{
    uint32_t length = 0;
    if (!IsArrayFromNapiValue(env, args, length)) {
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        NAPI_CALL_BASE(env, napi_get_element(env, args, i, &element), false);
        Policy policy;
        if (!NapiParsePolicy(env, element, policy)) {
            LOG_ERROR("get the value of policy failed");
            return false;
        }
        policies.emplace_back(policy);
    }
    return true;
}

napi_value NapiComposeMatchResultArray(napi_env env, const std::vector<MatchResult> &matchResultList)
{
    napi_value result;
    NAPI_CALL(env, napi_create_array_with_length(env, matchResultList.size(), &result));
    for (uint32_t i = 0; i < matchResultList.size(); ++i) {
        napi_value matchResult;
        NAPI_CALL(env, napi_create_object(env, &matchResult));

        napi_value sensitiveLabel;
        NAPI_CALL(env,
            napi_create_string_utf8(env, matchResultList[i].sensitiveLabel.c_str(), NAPI_AUTO_LENGTH, &sensitiveLabel));
        NAPI_CALL(env, napi_set_named_property(env, matchResult, "sensitiveLabel", sensitiveLabel));
        napi_value matchContent;
        NAPI_CALL(env,
            napi_create_string_utf8(env, matchResultList[i].matchContent.c_str(), NAPI_AUTO_LENGTH, &matchContent));
        NAPI_CALL(env, napi_set_named_property(env, matchResult, "matchContent", matchContent));
        napi_value matchNumber;
        NAPI_CALL(env, napi_create_uint32(env, matchResultList[i].matchNumber, &matchNumber));
        NAPI_CALL(env, napi_set_named_property(env, matchResult, "matchNumber", matchNumber));

        NAPI_CALL(env, napi_set_element(env, result, i, matchResult));
    }
    return result;
}

void DIANapiThrow(napi_env env, int32_t nativeErrCode)
{
    int32_t jsErrCode = NativeCodeToDIAJsCode(nativeErrCode);
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetDIAJsErrMsg(jsErrCode))));
}
#endif

void DIANapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, jsErrMsg)));
}

} // namespace OHOS::Security::DIA