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

#include "dlp_credential.h"
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include "account_adapt.h"
#include "bundle_manager_adapter.h"
#include "dlp_credential_client.h"
#include "dlp_policy_mgr_client.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "permission_policy.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS::AppExecFwk;
namespace {
const std::string LOCAL_ENCRYPTED_CERT = "encryptedPolicy";
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCredential"};
static const size_t MAX_REQUEST_NUM = 100;
static const uint32_t MAX_APPID_LIST_NUM = 250;
static const uint32_t MAX_APPID_LENGTH = 200;
static const std::string POLICY_CERT = "policyCert";
static const std::string DLP_MANAGER_BUNDLE_NAME = "com.ohos.dlpmanager";
static std::unordered_map<uint64_t, sptr<IDlpPermissionCallback>> g_requestMap;
static std::unordered_map<uint64_t, DlpAccountType> g_requestAccountTypeMap;
std::mutex g_lockRequest;
}  // namespace

static bool IsDlpCredentialHuksError(int errorCode)
{
    return ((errorCode >= DLP_ERR_GENERATE_KEY_FAILED) && (errorCode < DLP_ERR_IPC_INTERNAL_FAILED));
}

static bool IsDlpCredentialIpcError(int errorCode)
{
    return ((errorCode >= DLP_ERR_IPC_INTERNAL_FAILED) && (errorCode < DLP_ERR_CONNECTION_TIME_OUT));
}

static bool IsDlpCredentialServerError(int errorCode)
{
    return ((errorCode >= DLP_ERR_CONNECTION_TIME_OUT) && (errorCode < DLP_ERR_FILE_PATH));
}

static bool IsNoPermissionError(int errorCode)
{
    return ((errorCode == DLP_ERR_CONNECTION_VIP_RIGHT_EXPIRED) || (errorCode == DLP_ERR_CONNECTION_NO_PERMISSION));
}

static bool IsNoInternetError(int errorCode)
{
    return ((errorCode == DLP_ERR_CONNECTION_TIME_OUT) || (errorCode == DLP_ERR_TOKEN_CONNECTION_TIME_OUT) ||
        (errorCode == DLP_ERR_TOKEN_CONNECTION_FAIL));
}

static int32_t ConvertCredentialError(int errorCode)
{
    if (errorCode == DLP_SUCCESS) {
        return DLP_OK;
    }
    if (errorCode == DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED) {
        return DLP_CREDENTIAL_ERROR_TIME_EXPIRED;
    }
    if (errorCode == DLP_ERR_APPID_NOT_AUTHORIZED) {
        return DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED;
    }
    if (errorCode == DLP_ERR_CALLBACK_TIME_OUT) {
        return DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR;
    }
    if (errorCode == DLP_ERR_ACCOUNT_NOT_LOG_IN) {
        return DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR;
    }
    if (IsNoInternetError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_NO_INTERNET;
    }
    if (IsNoPermissionError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR;
    }
    if (IsDlpCredentialHuksError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_HUKS_ERROR;
    }
    if (IsDlpCredentialIpcError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_IPC_ERROR;
    }
    if (IsDlpCredentialServerError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_SERVER_ERROR;
    }
    return DLP_CREDENTIAL_ERROR_COMMON_ERROR;
}

static sptr<IDlpPermissionCallback> GetCallbackFromRequestMap(uint64_t requestId)
{
    DLP_LOG_INFO(LABEL, "Get callback, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    sptr<IDlpPermissionCallback> callback = nullptr;
    std::lock_guard<std::mutex> lock(g_lockRequest);
    auto iter = g_requestMap.find(requestId);
    if (iter != g_requestMap.end()) {
        callback = iter->second;
        g_requestMap.erase(requestId);
        return callback;
    }
    DLP_LOG_ERROR(LABEL, "Callback not found");
    return nullptr;
}

static int32_t InsertCallbackToRequestMap(uint64_t requestId, const sptr<IDlpPermissionCallback>& callback)
{
    DLP_LOG_DEBUG(LABEL, "insert request, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    if (g_requestMap.count(requestId) > 0) {
        DLP_LOG_ERROR(LABEL, "Duplicate task, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE;
    }
    g_requestMap[requestId] = callback;
    return DLP_OK;
}

static DlpAccountType GetAccountTypeFromRequestMap(uint64_t requestId)
{
    DLP_LOG_INFO(LABEL, "Get callback, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    DlpAccountType accountType = INVALID_ACCOUNT;
    std::lock_guard<std::mutex> lock(g_lockRequest);
    auto iter = g_requestAccountTypeMap.find(requestId);
    if (iter != g_requestAccountTypeMap.end()) {
        accountType = iter->second;
        g_requestAccountTypeMap.erase(requestId);
        return accountType;
    }
    DLP_LOG_ERROR(LABEL, "Callback not found");
    return INVALID_ACCOUNT;
}

static int32_t InsertAccountTypeToRequestMap(uint64_t requestId, const DlpAccountType& accountType)
{
    DLP_LOG_DEBUG(LABEL, "insert request, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    if (g_requestAccountTypeMap.count(requestId) > 0) {
        DLP_LOG_ERROR(LABEL, "Duplicate task, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE;
    }
    g_requestAccountTypeMap[requestId] = accountType;
    return DLP_OK;
}

static int32_t QueryRequestIdle()
{
    DLP_LOG_DEBUG(LABEL, "Total tasks: %{public}zu", g_requestMap.size());
    if (g_requestMap.size() > MAX_REQUEST_NUM) {
        DLP_LOG_ERROR(LABEL, "Task busy");
        return DLP_SERVICE_ERROR_CREDENTIAL_BUSY;
    }
    return DLP_OK;
}

static void DlpPackPolicyCallback(uint64_t requestId, int errorCode, DLP_EncPolicyData* outParams)
{
    DLP_LOG_INFO(LABEL, "Called, requestId: %{public}llu", static_cast<unsigned long long>(requestId));

    auto callback = GetCallbackFromRequestMap(requestId);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "callback is null");
        return;
    }

    if (errorCode != 0) {
        DLP_LOG_ERROR(LABEL, "Pack Policy error, errorCode: %{public}d", errorCode);

        // split DLP_CREDENTIAL error code by different situations
        errorCode = (errorCode == DLP_ERR_TOKEN_CONNECTION_FAIL) ?
            DLP_CREDENTIAL_ERROR_SERVER_ERROR : ConvertCredentialError(errorCode);
        callback->OnGenerateDlpCertificate(errorCode, std::vector<uint8_t>());
        return;
    }

    if (outParams == nullptr || outParams->data == nullptr || outParams->featureName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->OnGenerateDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, std::vector<uint8_t>());
        return;
    }
    unordered_json encDataJson;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(*outParams, encDataJson);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Serialize fail");
        return;
    }
    std::string encData = encDataJson.dump();
    std::vector<uint8_t> cert(encData.begin(), encData.end());
    callback->OnGenerateDlpCertificate(errorCode, cert);
}

static int32_t GetNewCert(const unordered_json& plainPolicyJson, std::vector<uint8_t>& cert,
    DlpAccountType ownerAccountType)
{
#ifdef SUPPORT_DLP_CREDENTIAL
    unordered_json json;
    if (plainPolicyJson.find(POLICY_CERT) == plainPolicyJson.end() || !plainPolicyJson.at(POLICY_CERT).is_object()) {
        DLP_LOG_ERROR(LABEL, "can not found policyCert");
        return DLP_CREDENTIAL_ERROR_SERVER_ERROR;
    }
    plainPolicyJson.at(POLICY_CERT).get_to(json);
    std::string encData = json.dump();
    DLP_EncPolicyData params;
    params.data = reinterpret_cast<uint8_t*>(strdup(encData.c_str()));
    params.dataLen = encData.length();
    params.accountType = static_cast<AccountType>(ownerAccountType);
    unordered_json encDataJson;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(params, encDataJson);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Serialize fail");
        free(params.data);
        params.data = nullptr;
        return res;
    }
    free(params.data);
    params.data = nullptr;
    std::string encDataStr = encDataJson.dump();
    cert.assign(encDataStr.begin(), encDataStr.end());
#endif
    return DLP_OK;
}

static int32_t DlpRestorePolicyCallbackCheck(sptr<IDlpPermissionCallback> callback, DlpAccountType accountType,
    int errorCode, DLP_RestorePolicyData* outParams, PermissionPolicy policyInfo)
{
    if (callback == nullptr || accountType == INVALID_ACCOUNT) {
        DLP_LOG_ERROR(LABEL, "callback is null or accountType is 0");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (errorCode != 0) {
        DLP_LOG_ERROR(LABEL, "Restore Policy error, errorCode: %{public}d", errorCode);
        callback->OnParseDlpCertificate(ConvertCredentialError(errorCode), policyInfo, {});
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (outParams == nullptr || outParams->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, policyInfo, {});
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

static void DlpRestorePolicyCallback(uint64_t requestId, int errorCode, DLP_RestorePolicyData* outParams)
{
    DLP_LOG_INFO(LABEL, "Called, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    auto callback = GetCallbackFromRequestMap(requestId);
    auto accountType = GetAccountTypeFromRequestMap(requestId);
    PermissionPolicy policyInfo;
    int32_t res = DlpRestorePolicyCallbackCheck(callback, accountType, errorCode, outParams, policyInfo);
    if (res != DLP_OK) {
        return;
    }
    auto policyStr = new (std::nothrow) char[outParams->dataLen + 1];
    if (policyStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo, {});
        return;
    }
    if (memcpy_s(policyStr, outParams->dataLen + 1, outParams->data, outParams->dataLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
        delete[] policyStr;
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo, {});
        return;
    }
    policyStr[outParams->dataLen] = '\0';
    auto jsonObj = unordered_json::parse(policyStr, policyStr + outParams->dataLen + 1, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        delete[] policyStr;
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, policyInfo, {});
        return;
    }
    delete[] policyStr;
    policyStr = nullptr;
    res = DlpPermissionSerializer::GetInstance().DeserializeDlpPermission(jsonObj, policyInfo);
    if (res != DLP_OK) {
        callback->OnParseDlpCertificate(res, policyInfo, {});
        return;
    }
    policyInfo.ownerAccountType_ = accountType;
    std::vector<uint8_t> cert;
    res = GetNewCert(jsonObj, cert, accountType);
    if (res != DLP_OK) {
        callback->OnParseDlpCertificate(res, policyInfo, {});
        return;
    }
    callback->OnParseDlpCertificate(errorCode, policyInfo, cert);
}

DlpCredential& DlpCredential::GetInstance()
{
    static DlpCredential instance;
    return instance;
}

static void FreeDlpPackPolicyParams(DLP_PackPolicyParams& packPolicy)
{
    if (packPolicy.featureName != nullptr) {
        free(packPolicy.featureName);
        packPolicy.featureName = nullptr;
    }
    if (packPolicy.data != nullptr) {
        free(packPolicy.data);
        packPolicy.data = nullptr;
    }
    if (packPolicy.senderAccountInfo.accountId != nullptr) {
        free(packPolicy.senderAccountInfo.accountId);
        packPolicy.senderAccountInfo.accountId = nullptr;
    }
}

DlpCredential::DlpCredential()
{}

int32_t DlpCredential::GenerateDlpCertificate(
    const std::string& policy, const std::string& accountInfo,
    DlpAccountType accountType, sptr<IDlpPermissionCallback>& callback)
{
    EncAndDecOptions encAndDecOptions = {
        .opt = RECEIVER_DECRYPT_MUST_USE_CLOUD,
        .extraInfo = nullptr,
        .extraInfoLen = 0
    };

    AccountInfo accountCfg = {
        .accountId = reinterpret_cast<uint8_t*>(strdup(accountInfo.c_str())),
        .accountIdLen = accountInfo.size(),
    };

    DLP_PackPolicyParams packPolicy = {
        .featureName = strdup("dlp_permission_service"),
        .data = reinterpret_cast<uint8_t*>(strdup(policy.c_str())),
        .dataLen = policy.size(),
        .options = encAndDecOptions,
        .accountType = static_cast<AccountType>(accountType),
        .senderAccountInfo = accountCfg,
    };
    int res = 0;
    {
        std::lock_guard<std::mutex> lock(g_lockRequest);
        int32_t status = QueryRequestIdle();
        if (status != DLP_OK) {
            FreeDlpPackPolicyParams(packPolicy);
            return status;
        }

        uint64_t requestId;
        res = DLP_PackPolicy(GetCallingUserId(), &packPolicy, DlpPackPolicyCallback, &requestId);
        if (res == 0) {
            DLP_LOG_INFO(
                LABEL, "Start request success, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
            res = InsertCallbackToRequestMap(requestId, callback);
            if (res != DLP_OK) {
                FreeDlpPackPolicyParams(packPolicy);
                return res;
            }
            res = InsertAccountTypeToRequestMap(requestId, accountType);
            if (res != DLP_OK) {
                FreeDlpPackPolicyParams(packPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDlpPackPolicyParams(packPolicy);
    return ConvertCredentialError(res);
}

static void FreeDLPEncPolicyData(DLP_EncPolicyData& encPolicy)
{
    if (encPolicy.featureName != nullptr) {
        free(encPolicy.featureName);
        encPolicy.featureName = nullptr;
    }
    if (encPolicy.data != nullptr) {
        delete[] encPolicy.data;
        encPolicy.data = nullptr;
    }
    if (encPolicy.options.extraInfo != nullptr) {
        delete[] encPolicy.options.extraInfo;
        encPolicy.options.extraInfo = nullptr;
    }
    if (encPolicy.receiverAccountInfo.accountId != nullptr) {
        free(encPolicy.receiverAccountInfo.accountId);
        encPolicy.receiverAccountInfo.accountId = nullptr;
    }
}

static int32_t GetLocalAccountName(std::string& account, const std::string& contactAccount, bool* isOwner)
{
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (accountInfo.first) {
        account = accountInfo.second.uid_;
        if (contactAccount.compare("") != 0 && contactAccount.compare(accountInfo.second.name_) == 0) {
            *isOwner = true;
        }
        return DLP_OK;
    }
    return DLP_PARSE_ERROR_ACCOUNT_INVALID;
}

static int32_t GetDomainAccountName(std::string& account, const std::string& contactAccount, bool* isOwner)
{
    std::vector<int32_t> ids;
    if (OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids) != 0) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    if (ids.size() != 1) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds size not 1");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    int32_t userId = ids[0];
    AccountSA::OsAccountInfo osAccountInfo;
    if (OHOS::AccountSA::OsAccountManager::QueryOsAccountById(userId, osAccountInfo) != 0) {
        DLP_LOG_ERROR(LABEL, "GetOsAccountLocalIdFromDomain return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    AccountSA::DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        DLP_LOG_ERROR(LABEL, "accountName_ empty");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    if (contactAccount.compare("") != 0 && contactAccount.compare(domainInfo.accountName_) == 0) {
        *isOwner = true;
    }
    account = domainInfo.accountId_;
    return DLP_OK;
}

static void GetAccoutInfo(DlpAccountType accountType, AccountInfo& accountCfg,
    const std::string& contactAccount, bool* isOwner)
{
    std::string account;
    if (accountType == DOMAIN_ACCOUNT) {
        if (GetDomainAccountName(account, contactAccount, isOwner) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "query GetDomainAccountName failed");
            return;
        }
    } else {
        if (GetLocalAccountName(account, contactAccount, isOwner) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "query GetLocalAccountName failed");
            return;
        }
    }

    accountCfg = {
        .accountId = reinterpret_cast<uint8_t*>(strdup(account.c_str())),
        .accountIdLen = account.size(),
    };
}

static int32_t AdapterData(const std::vector<uint8_t>& offlineCert, bool isOwner, unordered_json jsonObj,
    DLP_EncPolicyData& encPolicy)
{
    DLP_LOG_DEBUG(LABEL, "enter");
    unordered_json offlineJsonObj;
    if (!offlineCert.empty()) {
        std::string offlineEncDataJsonStr(offlineCert.begin(), offlineCert.end());
        offlineJsonObj = unordered_json::parse(offlineEncDataJsonStr, nullptr, false);
        if (offlineJsonObj.is_discarded()) {
            DLP_LOG_ERROR(LABEL, "offlineJsonObj is discarded");
            return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
        }
    }
    std::string ownerAccountId = "";
    if (isOwner) {
        std::string temp(reinterpret_cast<const char*>(encPolicy.receiverAccountInfo.accountId));
        ownerAccountId = temp;
    }
    int32_t result = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(jsonObj,
        offlineJsonObj, encPolicy, ownerAccountId);
    if (result != DLP_OK) {
        FreeDLPEncPolicyData(encPolicy);
        return result;
    }
    return DLP_OK;
}

int32_t DlpCredential::ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
    const std::string& appId, const bool& offlineAccess)
{
    std::string encDataJsonStr(certParcel->cert.begin(), certParcel->cert.end());
    auto jsonObj = unordered_json::parse(encDataJsonStr, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    EncAndDecOptions options = {.opt = CloudEncOption::RECEIVER_DECRYPT_MUST_USE_CLOUD, .extraInfo = nullptr};
    if (offlineAccess) {
        options.opt = CloudEncOption::RECEIVER_DECRYPT_MUST_USE_CLOUD_AND_RETURN_ENCRYPTION_VALUE;
    }
    DLP_EncPolicyData encPolicy = {.featureName = strdup(const_cast<char *>(appId.c_str())), .options = options};
    int32_t result =
        DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(jsonObj, encPolicy, certParcel->isNeedAdapter);
    auto accountType = static_cast<DlpAccountType>(encPolicy.accountType);
    if (result != DLP_OK) {
        FreeDLPEncPolicyData(encPolicy);
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    bool isOwner = false;
    GetAccoutInfo(accountType, encPolicy.receiverAccountInfo, certParcel->contactAccount, &isOwner);
    if (certParcel->isNeedAdapter) {
        AdapterData(certParcel->offlineCert, isOwner, jsonObj, encPolicy);
    }
    int res = 0;
    {
        std::lock_guard<std::mutex> lock(g_lockRequest);
        int32_t status = QueryRequestIdle();
        if (status != DLP_OK) {
            FreeDLPEncPolicyData(encPolicy);
            return status;
        }
        uint64_t requestId;
        res = DLP_RestorePolicy(GetCallingUserId(), &encPolicy, DlpRestorePolicyCallback, &requestId);
        if (res == 0) {
            res = InsertCallbackToRequestMap(requestId, callback);
            int accountTypeRes = InsertAccountTypeToRequestMap(requestId, accountType);
            if (res != DLP_OK || accountTypeRes != DLP_OK) {
                FreeDLPEncPolicyData(encPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDLPEncPolicyData(encPolicy);
    return ConvertCredentialError(res);
}

int32_t ParseStringVectorToUint8TypedArray(const std::vector<std::string>& appIdList, uint8_t *policy,
    uint32_t policySize)
{
    uint32_t count = static_cast<uint32_t>(appIdList.size());
    if (memcpy_s(policy, policySize, &count, sizeof(uint32_t)) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy policy fail");
        return DLP_CREDENTIAL_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t offset = sizeof(uint32_t);
    for (int32_t i = 0; i < static_cast<int32_t>(appIdList.size()); i++) {
        if (appIdList[i].empty()) {
            DLP_LOG_ERROR(LABEL, "Empty appId");
            return DLP_SERVICE_ERROR_VALUE_INVALID;
        }
        char *appId = const_cast<char *>(appIdList[i].c_str());
        uint32_t length = static_cast<uint32_t>(strlen(appId));
        if (length > MAX_APPID_LENGTH) {
            DLP_LOG_ERROR(LABEL, "AppId longer than limit");
            return DLP_SERVICE_ERROR_VALUE_INVALID;
        }
        if (memcpy_s(policy + offset, policySize - offset, &length, sizeof(uint32_t)) != EOK) {
            DLP_LOG_ERROR(LABEL, "Memcpy policy fail");
            return DLP_CREDENTIAL_ERROR_MEMORY_OPERATE_FAIL;
        }
        offset += sizeof(uint32_t);
        if (memcpy_s(policy + offset, policySize - offset, appId, strlen(appId)) != EOK) {
            DLP_LOG_ERROR(LABEL, "Memcpy policy fail");
            return DLP_CREDENTIAL_ERROR_MEMORY_OPERATE_FAIL;
        }
        offset += strlen(appId);
    }
    return offset;
}

int32_t ParseUint8TypedArrayToStringVector(uint8_t *policy, uint32_t *policyLen, std::vector<std::string>& appIdList)
{
    uint32_t count = reinterpret_cast<uint32_t *>(policy)[0];
    if (count < 0 || count > MAX_APPID_LIST_NUM) {
        DLP_LOG_ERROR(LABEL, "get appId List too large");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t offset = sizeof(uint32_t);
    for (uint32_t i = 0; i < count; i++) {
        int32_t length = reinterpret_cast<int32_t *>(policy + offset)[0];
        offset += sizeof(uint32_t);
        appIdList.push_back(std::string(reinterpret_cast<char *>(policy + offset), length));
        offset += length;
    }
    return DLP_OK;
}

int32_t PresetDLPPolicy(const std::vector<std::string>& srcList, std::vector<std::string>& dstList)
{
    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId;
    bool result = GetUserIdByActiveAccount(&userId);
    if (!result) {
        DLP_LOG_ERROR(LABEL, "get userId error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!BundleManagerAdapter::GetInstance().GetBundleInfo(DLP_MANAGER_BUNDLE_NAME,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId)) {
        DLP_LOG_ERROR(LABEL, "get appId error");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }
    std::string appId = bundleInfo.appId;
    dstList.assign(srcList.begin(), srcList.end());
    dstList.push_back(appId);
    return DLP_OK;
}

int32_t RemovePresetDLPPolicy(std::vector<std::string>& appIdList)
{
    if (appIdList.size() > 0) {
        appIdList.pop_back();
    }
    return DLP_OK;
}

int32_t DlpCredential::SetMDMPolicy(const std::vector<std::string>& appIdList)
{
    if (size(appIdList) > MAX_APPID_LENGTH) {
        DLP_LOG_ERROR(LABEL, "appId List too large");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint32_t policySize = (size(appIdList) + 1) * MAX_APPID_LENGTH;
    uint8_t *policy = new (std::nothrow)uint8_t[policySize];
    if (policy == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc policy failed.");
        delete[] policy;
        return DLP_CREDENTIAL_ERROR_MEMORY_OPERATE_FAIL;
    }
    std::vector<std::string> presetAppIdList;
    int32_t res = PresetDLPPolicy(appIdList, presetAppIdList);
    if (res != DLP_OK) {
        delete[] policy;
        return res;
    }
    int32_t policyLen = ParseStringVectorToUint8TypedArray(presetAppIdList, policy, policySize);
    if (policyLen <= 0) {
        delete[] policy;
        return policyLen;
    }
    res = DLP_AddPolicy(PolicyType::AUTHORIZED_APPLICATION_LIST, policy, policyLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SetMDMPolicy request fail, error: %{public}d", res);
    }
    delete[] policy;
    return res;
}

int32_t DlpCredential::GetMDMPolicy(std::vector<std::string>& appIdList)
{
    uint32_t policyLen = MAX_APPID_LIST_NUM * MAX_APPID_LENGTH;
    uint8_t *policy = new (std::nothrow)uint8_t[policyLen];
    if (policy == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc policy failed.");
        return DLP_CREDENTIAL_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t res = DLP_GetPolicy(PolicyType::AUTHORIZED_APPLICATION_LIST, policy, &policyLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetMDMPolicy request fail, error: %{public}d", res);
        delete[] policy;
        return res;
    }
    if (policyLen == 0) {
        DLP_LOG_WARN(LABEL, "appIdList is empty.");
        delete[] policy;
        return DLP_OK;
    }
    res = ParseUint8TypedArrayToStringVector(policy, &policyLen, appIdList);
    delete[] policy;
    if (res == DLP_OK) {
        res = RemovePresetDLPPolicy(appIdList);
    }
    return res;
}

int32_t DlpCredential::RemoveMDMPolicy()
{
    int32_t res = DLP_RemovePolicy(PolicyType::AUTHORIZED_APPLICATION_LIST);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RemoveMDMPolicy request fail, error: %{public}d", res);
    }
    return res;
}

int32_t DlpCredential::CheckMdmPermission(const std::string& bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    bool result = BundleManagerAdapter::GetInstance().GetBundleInfo(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId);
    if (!result) {
        DLP_LOG_ERROR(LABEL, "get appId error");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }
    std::string appId = bundleInfo.appId;
    DLP_LOG_DEBUG(LABEL, "appId:%{public}s", appId.c_str());
    PolicyHandle handle = {.id = strdup(const_cast<char *>(bundleInfo.appId.c_str()))};
    int32_t res = DLP_CheckPermission(PolicyType::AUTHORIZED_APPLICATION_LIST, handle);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_CheckPermission error:%{public}d", res);
        res = DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED;
    }
    if (handle.id != nullptr) {
        free(handle.id);
        handle.id = nullptr;
    }
    return res;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
