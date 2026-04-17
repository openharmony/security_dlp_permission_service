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
static constexpr size_t MAX_ACCOUNT_LEN = 255;
static constexpr size_t MAX_FILE_NAME_LEN = 255;
}  // namespace
void GetDlpPropertyExpireTime(napi_env env, napi_value jsObject, DlpProperty& property)
{
    int64_t jsExpireTime = 0;
    if (!GetInt64ValueByKey(env, jsObject, "expireTime", jsExpireTime)) {
        DLP_LOG_INFO(LABEL, "js get expity time fail, set zero");
    }
    property.expireTime = static_cast<uint64_t>(jsExpireTime);
    int64_t jsActionUponExpiry = 0;
    if (!GetInt64ValueByKey(env, jsObject, "actionUponExpiry", jsActionUponExpiry)) {
        DLP_LOG_ERROR(LABEL, "js get action upon expiry fail");
    }
    property.actionUponExpiry = static_cast<ActionType>(jsActionUponExpiry);
}

bool GetAllowedOpenCount(napi_env env, napi_value jsObject, DlpProperty& property)
{
    if (!GetInt32ValueByKey(env, jsObject, "allowedOpenCount", property.allowedOpenCount)) {
        DLP_LOG_DEBUG(LABEL, "js get allowed open count fail, will set zero");
        property.allowedOpenCount = 0;
    }
    if (!GetStringValueByKey(env, jsObject, "fileId", property.fileId) ||
        !IsStringLengthValid(property.fileId, MAX_ACCOUNT_LEN)) {
        DLP_LOG_DEBUG(LABEL, "js get fileId fail, will set empty");
        property.fileId = "";
    }
    if (!GetInt32ValueByKey(env, jsObject, "countdown", property.countdown)) {
        DLP_LOG_DEBUG(LABEL, "js get countdown fail, will set zero");
        property.countdown = 0;
    }
    return true;
}

void GetWaterMarkConfig(napi_env env, napi_value jsObject, DlpProperty& property)
{
    bool jsWaterMarkConfig = false;
    if (!GetBoolValueByKey(env, jsObject, "waterMarkConfig", property.waterMarkConfig)) {
        DLP_LOG_ERROR(LABEL, "js get waterMarkConfig fail, will set false");
        property.waterMarkConfig = jsWaterMarkConfig;
    }
}

void GetExtensionFields(napi_env env, napi_value jsObject, DlpProperty& property)
{
    std::string nickNameMask = "";
    napi_value extensionFields = GetNapiValue(env, jsObject, "extensionFields");
    if (extensionFields == nullptr) {
        DLP_LOG_INFO(LABEL, "get extensionFields null");
        return;
    }
    bool ret = GetStringValueByKey(env, extensionFields, "nickNameMask", nickNameMask) &&
        IsStringLengthValid(nickNameMask, MAX_FILE_NAME_LEN);
    if (!ret || nickNameMask.empty()) {
        DLP_LOG_INFO(LABEL, "get nickNameMask empty");
        return;
    }
    property.nickNameMask = nickNameMask;
}

bool GetEveryoneAccessList(napi_env env, napi_value jsObject, DlpProperty& property)
{
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


bool GetDlpProperty(napi_env env, napi_value jsObject, DlpProperty& property)
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
    GetWaterMarkConfig(env, jsObject, property);
    GetDlpPropertyExpireTime(env, jsObject, property);
    GetExtensionFields(env, jsObject, property);
    if (!GetAllowedOpenCount(env, jsObject, property)) {
        DLP_LOG_ERROR(LABEL, "get allowed open count fail");
        return false;
    }
    if (!GetEveryoneAccessList(env, jsObject, property)) {
        DLP_LOG_ERROR(LABEL, "get GetEveryoneAccessList fail");
        return false;
    }
    return true;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS