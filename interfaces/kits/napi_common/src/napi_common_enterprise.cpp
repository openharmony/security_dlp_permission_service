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
#include <algorithm>
#include <unistd.h>
#include "dlp_file_kits.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "napi_error_msg.h"
#include "securec.h"
#include "string_wrapper.h"
#include "permission_policy.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionCommon"};
static constexpr size_t MAX_ENTERPRISEPOLICY_SIZE = 1024 * 1024 * 4;
static constexpr size_t MAX_ACCOUNT_LEN = 255;
}

bool GetAccountTypeInEnterpriseParam(
    const napi_env env, const napi_callback_info info, GenerateDlpFileForEnterpriseAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }
    if (!GetAccountTypeInDlpProperty(env, argv[PARAM2], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail.");
        ThrowParamError(env, "property", "DlpProperty");
        return false;
    }
    return true;
}

bool GetGenerateDlpFileForDomainParam(
    const napi_env env, const napi_callback_info info, GenerateDlpFileForEnterpriseAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plaintextFd)) {
        DLP_LOG_ERROR(LABEL, "js get plaintext fd fail");
        ThrowParamError(env, "plaintextFd", "number");
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM1], asyncContext.dlpFd)) {
        DLP_LOG_ERROR(LABEL, "js get dlp file fd fail");
        ThrowParamError(env, "dlpFd", "number");
        return false;
    }

    if (!GetDlpProperty(env, argv[PARAM2], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail");
        ThrowParamError(env, "property", "DlpProperty");
        return false;
    }

    if (!GetCustomProperty(env, argv[PARAM3], asyncContext.customProperty)) {
        DLP_LOG_ERROR(LABEL, "js get customProperty fail");
        ThrowParamError(env, "customProperty", "CustomProperty");
        return false;
    }

    return true;
}

static bool GetEnterpriseDlpPropertyAccount(napi_env env, napi_value jsObject, DlpProperty& property)
{
    if (!GetStringValueByKey(env, jsObject, "ownerAccount", property.ownerAccount) ||
        !IsStringLengthValid(property.ownerAccount, MAX_ACCOUNT_LEN)) {
        DLP_LOG_ERROR(LABEL, "js get owner account fail");
        return false;
    }
    if (!GetStringValueByKey(env, jsObject, "ownerAccountID", property.ownerAccountId) ||
        !IsStringLengthValid(property.ownerAccountId, MAX_ACCOUNT_LEN)) {
        DLP_LOG_ERROR(LABEL, "js get owner accountId fail");
        return false;
    }
    int64_t type;
    if (!GetInt64ValueByKey(env, jsObject, "ownerAccountType", type)) {
        DLP_LOG_ERROR(LABEL, "js get owner account type fail");
        return false;
    }
    property.ownerAccountType = static_cast<DlpAccountType>(type);
    return true;
}

bool GetEnterpriseDlpProperty(napi_env env, napi_value jsObject, DlpProperty& property)
{
    if (!GetEnterpriseDlpPropertyAccount(env, jsObject, property)) {
        return false;
    }
    napi_value authUserListObj = GetNapiValue(env, jsObject, "authUserList");
    if (authUserListObj != nullptr) {
        if (!GetVectorAuthUser(env, authUserListObj, property.authUsers)) {
            DLP_LOG_ERROR(LABEL, "js get auth users fail");
            return false;
        }
    }
    if (!GetStringValueByKey(env, jsObject, "contactAccount", property.contactAccount) ||
        !IsStringLengthValid(property.contactAccount, MAX_ACCOUNT_LEN)) {
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

    if (!GetStringValueByKey(env, jsObject, "fileId", property.fileId) ||
        !IsStringLengthValid(property.fileId, MAX_ACCOUNT_LEN)) {
        DLP_LOG_ERROR(LABEL, "js get fileId fail");
        return false;
    }
    return true;
}

bool GetGenerateDlpFileForEnterpriseParam(
    const napi_env env, const napi_callback_info info, GenerateDlpFileForEnterpriseAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plaintextFd)) {
        DLP_LOG_ERROR(LABEL, "js get plaintext fd fail");
        ThrowParamError(env, "plaintextFd", "number");
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM1], asyncContext.dlpFd)) {
        DLP_LOG_ERROR(LABEL, "js get dlp file fd fail");
        ThrowParamError(env, "dlpFd", "number");
        return false;
    }

    if (!GetEnterpriseDlpProperty(env, argv[PARAM2], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail");
        ThrowParamError(env, "property", "DlpProperty");
        return false;
    }

    if (!GetCustomProperty(env, argv[PARAM3], asyncContext.customProperty)) {
        DLP_LOG_ERROR(LABEL, "js get customProperty fail");
        ThrowParamError(env, "customProperty", "CustomProperty");
        return false;
    }

    return true;
}

bool GetCustomProperty(napi_env env, napi_value jsObject, CustomProperty& customProperty)
{
    if (!GetStringValueByKey(env, jsObject, "enterprise", customProperty.enterprise)) {
        DLP_LOG_ERROR(LABEL, "js get enterprise fail");
        return false;
    }
    // Get optional options field (DlpFileQueryOptions)
    napi_value optionsValue = GetNapiValue(env, jsObject, "options");
    napi_valuetype valueType;
    if (optionsValue != nullptr && napi_typeof(env, optionsValue, &valueType) == napi_ok && valueType == napi_object) {
        if (!GetDlpFileQueryOptions(env, optionsValue, customProperty.options)) {
            DLP_LOG_WARN(LABEL, "js get option fail, use default");
        }
    }
    return true;
}

bool GetSetEnterprisePolicyParams(
    const napi_env env, const napi_callback_info info, SetEnterprisePolicyContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_ONE)) {
        return false;
    }

    if (!GetStringValueByKey(env, argv[PARAM0], "policyString", asyncContext.policy.policyString) ||
        !IsStringLengthValid(asyncContext.policy.policyString, MAX_ENTERPRISEPOLICY_SIZE)) {
        DLP_LOG_ERROR(LABEL, "js get enterprise policy fail");
        DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "Invalid parameter value.");
        return false;
    }
    return true;
}
bool GetDlpFileQueryOptions(napi_env env, napi_value jsObject, DlpFileQueryOptions& queryOptions)
{
    if (jsObject == nullptr) {
        return true;
    }
    napi_valuetype valueType;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        return false;
    }
    if (valueType != napi_object) {
        return false;
    }
    // Get optional classificationLabel field
    bool hasProperty = false;
    napi_status status = napi_has_named_property(env, jsObject, "classificationLabel", &hasProperty);
    if (status == napi_ok && hasProperty) {
        if (!GetStringValueByKey(env, jsObject, "classificationLabel", queryOptions.classificationLabel)) {
            DLP_LOG_WARN(LABEL, "get classificationLabel fail, use default");
        }
    }
    return true;
}

bool GetDlpFileQueryOptionsParams(
    const napi_env env, const napi_callback_info info, DlpFileQueryOptionsAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc > PARAM0 && argv[PARAM0] != nullptr) {
        napi_valuetype valueType;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valueType), false);
        if (valueType == napi_object) {
            if (!GetDlpFileQueryOptions(env, argv[PARAM0], asyncContext.queryOptions)) {
                DLP_LOG_ERROR(LABEL, "js get DlpFileQueryOptions fail");
                DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "Invalid parameter value.");
                return false;
            }
        }
    }
    return true;
}

bool GetDlpFileQueryOptionsParams(
    const napi_env env, const napi_callback_info info, CloseOpenedEnterpriseDlpFilesContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc > PARAM0 && argv[PARAM0] != nullptr) {
        napi_valuetype valueType;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valueType), false);
        if (valueType == napi_object) {
            if (!GetDlpFileQueryOptions(env, argv[PARAM0], asyncContext.options)) {
                DLP_LOG_ERROR(LABEL, "js get DlpFileQueryOptions fail");
                DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "Invalid parameter value.");
                return false;
            }
        }
    }
    return true;
}

bool GetDlpFileQueryOptionsParams(
    const napi_env env, const napi_callback_info info, QueryOpenedEnterpriseDlpFilesContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc > PARAM0 && argv[PARAM0] != nullptr) {
        napi_valuetype valueType;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valueType), false);
        if (valueType == napi_object) {
            if (!GetDlpFileQueryOptions(env, argv[PARAM0], asyncContext.options)) {
                DLP_LOG_ERROR(LABEL, "js get DlpFileQueryOptions fail");
                DlpNapiThrow(env, ERR_JS_INVALID_PARAMETER, "Invalid parameter value.");
                return false;
            }
        }
    }
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS