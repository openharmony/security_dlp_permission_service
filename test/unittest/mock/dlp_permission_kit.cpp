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

#include "dlp_permission_kit.h"
#include <string>
#include <thread>
#include <vector>
#include "nlohmann/json.hpp"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
using unordered_json = nlohmann::ordered_json;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKit"};
int32_t g_mockGetAbilityInfosRet = DLP_OK;
std::vector<AppExecFwk::AbilityInfo> g_mockAbilityInfos;
static const std::string ACCOUNT_INDEX = "account";
static const std::string ACCOUNT_TYPE = "accountType";
static const std::string READ_INDEX = "read";
static const std::string EDIT_INDEX = "edit";
static const std::string FC_INDEX = "fullCtrl";
static const std::string RIGHT_INDEX = "right";
static const std::string USER_PERM_EXPIRY = "permExpiryTime";
static const std::string OWNER_ACCOUNT = "ownerAccount";
static const std::string OWNER_ACCOUNT_NAME = "ownerAccountName";
static const std::string OWNER_ACCOUNT_ID = "ownerAccountId";
static const std::string OWNER_ACCOUNT_TYPE = "ownerAccountType";
static const std::string PERM_EXPIRY_TIME = "expireTime";
static const std::string ACTION_UPON_EXPIRY = "actionUponExpiry";
static const std::string NEED_ONLINE = "needOnline";
static const std::string CUSTOM_PROPERTY = "customProperty";
static const std::string EVERYONE_INDEX = "everyone";
static const std::string FILEID = "fileId";
static const std::string ALLOWED_OPEN_COUNT = "allowedOpenCount";
static const std::string WATERMARK_CONFIG = "waterMarkConfig";
static const std::string COUNTDOWN = "countdown";
static const std::string NICK_NAME_MASK = "nickNameMask";
static const std::string AES_KEY = "aesKey";
static const std::string IV_KEY = "ivKey";
static const std::string HMAC_KEY = "hmacKey";
static constexpr uint32_t TWO = 2;
static constexpr uint32_t FOUR = 4;

static std::string ToHex(const uint8_t* data, uint32_t len)
{
    if (data == nullptr || len == 0) {
        return "";
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<size_t>(len) * TWO);
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        out.push_back(hex[(byte >> FOUR) & 0x0F]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

static bool FromHex(const std::string& hexStr, std::vector<uint8_t>& out)
{
    auto hexValue = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }
        return -1;
    };

    if ((hexStr.size() % TWO) != 0) {
        return false;
    }
    out.clear();
    out.reserve(hexStr.size() / TWO);
    for (size_t i = 0; i < hexStr.size(); i += TWO) {
        int hi = hexValue(hexStr[i]);
        int lo = hexValue(hexStr[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out.emplace_back(static_cast<uint8_t>((hi << FOUR) | lo));
    }
    return true;
}

static void SerializePermInfo(DLPFileAccess perm, unordered_json& rightInfoJson)
{
    bool read = false;
    bool edit = false;
    bool fullCtrl = false;
    switch (perm) {
        case DLPFileAccess::READ_ONLY:
            read = true;
            break;
        case DLPFileAccess::CONTENT_EDIT:
            edit = true;
            break;
        case DLPFileAccess::FULL_CONTROL:
            read = true;
            edit = true;
            fullCtrl = true;
            break;
        default:
            break;
    }
    rightInfoJson[READ_INDEX] = read;
    rightInfoJson[EDIT_INDEX] = edit;
    rightInfoJson[FC_INDEX] = fullCtrl;
}

static DLPFileAccess DeserializePermInfo(const unordered_json& rightInfoJson)
{
    bool edit = false;
    bool fullCtrl = false;
    if (rightInfoJson.contains(EDIT_INDEX) && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }
    if (rightInfoJson.contains(FC_INDEX) && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }
    if (fullCtrl) {
        return DLPFileAccess::FULL_CONTROL;
    }
    if (edit) {
        return DLPFileAccess::CONTENT_EDIT;
    }
    return DLPFileAccess::READ_ONLY;
}

static int32_t CheckPolicySerializableInMock(const PermissionPolicy& policy)
{
    // dlp_parse path does not support DOMAIN account certificate generation in this mock.
    if (policy.ownerAccountType_ == DOMAIN_ACCOUNT) {
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }

    // For other account types, missing cipher params are treated as invalid value.
    if (policy.GetAeskey() == nullptr || policy.GetIv() == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!CheckAesParamLen(policy.GetAeskeyLen()) || !CheckAesParamLen(policy.GetIvLen())) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (policy.GetHmacKey() != nullptr && !CheckAesParamLen(policy.GetHmacKeyLen())) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!CheckAccountType(policy.ownerAccountType_)) {
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    return DLP_OK;
}

static void SerializeBasePolicy(const PermissionPolicy& policy, unordered_json& jsonObj)
{
    jsonObj["version"] = policy.dlpVersion_;
    jsonObj[OWNER_ACCOUNT] = policy.ownerAccount_;
    jsonObj[OWNER_ACCOUNT_NAME] = policy.ownerAccount_;
    jsonObj[OWNER_ACCOUNT_ID] = policy.ownerAccountId_;
    jsonObj[OWNER_ACCOUNT_TYPE] = static_cast<uint32_t>(policy.ownerAccountType_);
    jsonObj[PERM_EXPIRY_TIME] = policy.expireTime_;
    jsonObj[ACTION_UPON_EXPIRY] = policy.actionUponExpiry_;
    jsonObj[NEED_ONLINE] = policy.needOnline_;
    jsonObj[CUSTOM_PROPERTY] = policy.customProperty_;
    jsonObj[FILEID] = policy.fileId;
    jsonObj[ALLOWED_OPEN_COUNT] = policy.allowedOpenCount_;
    jsonObj[WATERMARK_CONFIG] = policy.waterMarkConfig_;
    jsonObj[COUNTDOWN] = policy.countdown_;
    jsonObj[NICK_NAME_MASK] = policy.nickNameMask_;
}

static void SerializeCryptoPolicy(const PermissionPolicy& policy, unordered_json& jsonObj)
{
    jsonObj[AES_KEY] = ToHex(policy.GetAeskey(), policy.GetAeskeyLen());
    jsonObj[IV_KEY] = ToHex(policy.GetIv(), policy.GetIvLen());
    jsonObj[HMAC_KEY] = ToHex(policy.GetHmacKey(), policy.GetHmacKeyLen());
}

static void SerializeAuthUsers(const PermissionPolicy& policy, unordered_json& jsonObj)
{
    unordered_json accountJson = unordered_json::object();
    for (const auto& userInfo : policy.authUsers_) {
        unordered_json rightInfoJson = unordered_json::object();
        SerializePermInfo(userInfo.authPerm, rightInfoJson);
        accountJson[userInfo.authAccount][RIGHT_INDEX] = rightInfoJson;
        accountJson[userInfo.authAccount][ACCOUNT_TYPE] = static_cast<uint32_t>(userInfo.authAccountType);
        accountJson[userInfo.authAccount][USER_PERM_EXPIRY] = userInfo.permExpiryTime;
    }
    jsonObj[ACCOUNT_INDEX] = accountJson;
}

static void SerializeEveryone(const PermissionPolicy& policy, unordered_json& jsonObj)
{
    if (!policy.supportEveryone_) {
        return;
    }
    unordered_json rightInfoJson = unordered_json::object();
    SerializePermInfo(policy.everyonePerm_, rightInfoJson);
    jsonObj[EVERYONE_INDEX][RIGHT_INDEX] = rightInfoJson;
}

static void ResetPolicyForMockDeserialize(PermissionPolicy& policy)
{
    policy.ownerAccount_ = "";
    policy.ownerAccountId_ = "";
    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    policy.expireTime_ = 0;
    policy.actionUponExpiry_ = 0;
    policy.needOnline_ = 0;
    policy.debug_ = false;
    policy.supportEveryone_ = false;
    policy.everyonePerm_ = DLPFileAccess::NO_PERMISSION;
    policy.authUsers_.clear();
    policy.customProperty_ = "";
    policy.waterMarkConfig_ = false;
    policy.countdown_ = 0;
    policy.canFindWaterMarkConfig_ = false;
    policy.canFindCountdown_ = false;
    policy.nickNameMask_ = "";
    policy.fileId = "";
    policy.allowedOpenCount_ = 0;
}

static void DeserializeBasePolicy(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    if (jsonObj.contains(OWNER_ACCOUNT) && jsonObj.at(OWNER_ACCOUNT).is_string()) {
        jsonObj.at(OWNER_ACCOUNT).get_to(policy.ownerAccount_);
    } else if (jsonObj.contains(OWNER_ACCOUNT_NAME) && jsonObj.at(OWNER_ACCOUNT_NAME).is_string()) {
        jsonObj.at(OWNER_ACCOUNT_NAME).get_to(policy.ownerAccount_);
    }
    if (jsonObj.contains(OWNER_ACCOUNT_ID) && jsonObj.at(OWNER_ACCOUNT_ID).is_string()) {
        jsonObj.at(OWNER_ACCOUNT_ID).get_to(policy.ownerAccountId_);
    }
    if (jsonObj.contains(OWNER_ACCOUNT_TYPE) && jsonObj.at(OWNER_ACCOUNT_TYPE).is_number_unsigned()) {
        uint32_t type = INVALID_ACCOUNT;
        jsonObj.at(OWNER_ACCOUNT_TYPE).get_to(type);
        if (CheckAccountType(static_cast<DlpAccountType>(type))) {
            policy.ownerAccountType_ = static_cast<DlpAccountType>(type);
        }
    }
    if (jsonObj.contains(PERM_EXPIRY_TIME) && jsonObj.at(PERM_EXPIRY_TIME).is_number_unsigned()) {
        jsonObj.at(PERM_EXPIRY_TIME).get_to(policy.expireTime_);
    }
    if (jsonObj.contains(ACTION_UPON_EXPIRY) && jsonObj.at(ACTION_UPON_EXPIRY).is_number_unsigned()) {
        jsonObj.at(ACTION_UPON_EXPIRY).get_to(policy.actionUponExpiry_);
    }
    if (jsonObj.contains(NEED_ONLINE) && jsonObj.at(NEED_ONLINE).is_number_unsigned()) {
        jsonObj.at(NEED_ONLINE).get_to(policy.needOnline_);
    }
}

static void DeserializeExtraPolicy(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    if (jsonObj.contains(CUSTOM_PROPERTY) && jsonObj.at(CUSTOM_PROPERTY).is_string()) {
        jsonObj.at(CUSTOM_PROPERTY).get_to(policy.customProperty_);
    }
    if (jsonObj.contains(FILEID) && jsonObj.at(FILEID).is_string()) {
        jsonObj.at(FILEID).get_to(policy.fileId);
    }
    if (jsonObj.contains(ALLOWED_OPEN_COUNT) && jsonObj.at(ALLOWED_OPEN_COUNT).is_number_integer()) {
        jsonObj.at(ALLOWED_OPEN_COUNT).get_to(policy.allowedOpenCount_);
    }
    if (jsonObj.contains(WATERMARK_CONFIG) && jsonObj.at(WATERMARK_CONFIG).is_boolean()) {
        jsonObj.at(WATERMARK_CONFIG).get_to(policy.waterMarkConfig_);
        policy.canFindWaterMarkConfig_ = true;
    }
    if (jsonObj.contains(COUNTDOWN) && jsonObj.at(COUNTDOWN).is_number_integer()) {
        jsonObj.at(COUNTDOWN).get_to(policy.countdown_);
        policy.canFindCountdown_ = true;
    }
    if (jsonObj.contains(NICK_NAME_MASK) && jsonObj.at(NICK_NAME_MASK).is_string()) {
        jsonObj.at(NICK_NAME_MASK).get_to(policy.nickNameMask_);
    }
}

static void DeserializeCryptoPolicy(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    if (jsonObj.contains(AES_KEY) && jsonObj.at(AES_KEY).is_string()) {
        std::string aesHex;
        jsonObj.at(AES_KEY).get_to(aesHex);
        std::vector<uint8_t> aes;
        if (!aesHex.empty() && FromHex(aesHex, aes)) {
            policy.SetAeskey(aes.data(), static_cast<uint32_t>(aes.size()));
        }
    }
    if (jsonObj.contains(IV_KEY) && jsonObj.at(IV_KEY).is_string()) {
        std::string ivHex;
        jsonObj.at(IV_KEY).get_to(ivHex);
        std::vector<uint8_t> iv;
        if (!ivHex.empty() && FromHex(ivHex, iv)) {
            policy.SetIv(iv.data(), static_cast<uint32_t>(iv.size()));
        }
    }
    if (jsonObj.contains(HMAC_KEY) && jsonObj.at(HMAC_KEY).is_string()) {
        std::string hmacHex;
        jsonObj.at(HMAC_KEY).get_to(hmacHex);
        std::vector<uint8_t> hmac;
        if (!hmacHex.empty() && FromHex(hmacHex, hmac)) {
            policy.SetHmacKey(hmac.data(), static_cast<uint32_t>(hmac.size()));
        }
    }
}

static void DeserializeEveryone(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    if (!jsonObj.contains(EVERYONE_INDEX) || !jsonObj.at(EVERYONE_INDEX).is_object()) {
        return;
    }
    const auto& everyoneInfoJson = jsonObj.at(EVERYONE_INDEX);
    if (!everyoneInfoJson.contains(RIGHT_INDEX) || !everyoneInfoJson.at(RIGHT_INDEX).is_object()) {
        return;
    }
    policy.supportEveryone_ = true;
    policy.everyonePerm_ = DeserializePermInfo(everyoneInfoJson.at(RIGHT_INDEX));
}

static void DeserializeAuthUsers(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    if (!jsonObj.contains(ACCOUNT_INDEX) || !jsonObj.at(ACCOUNT_INDEX).is_object()) {
        return;
    }
    const auto& authUsersJson = jsonObj.at(ACCOUNT_INDEX);
    for (auto iter = authUsersJson.begin(); iter != authUsersJson.end(); ++iter) {
        if (!iter.value().is_object()) {
            continue;
        }
        AuthUserInfo authInfo;
        authInfo.authAccount = iter.key();
        authInfo.authPerm = DLPFileAccess::READ_ONLY;
        authInfo.permExpiryTime = UINT64_MAX;
        authInfo.authAccountType = CLOUD_ACCOUNT;

        const auto& accountInfoJson = iter.value();
        if (accountInfoJson.contains(ACCOUNT_TYPE) && accountInfoJson.at(ACCOUNT_TYPE).is_number_unsigned()) {
            uint32_t accountType = INVALID_ACCOUNT;
            accountInfoJson.at(ACCOUNT_TYPE).get_to(accountType);
            if (CheckAccountType(static_cast<DlpAccountType>(accountType))) {
                authInfo.authAccountType = static_cast<DlpAccountType>(accountType);
            }
        }
        if (accountInfoJson.contains(RIGHT_INDEX) && accountInfoJson.at(RIGHT_INDEX).is_object()) {
            authInfo.authPerm = DeserializePermInfo(accountInfoJson.at(RIGHT_INDEX));
        }
        if (accountInfoJson.contains(USER_PERM_EXPIRY) && accountInfoJson.at(USER_PERM_EXPIRY).is_number_unsigned()) {
            accountInfoJson.at(USER_PERM_EXPIRY).get_to(authInfo.permExpiryTime);
        }
        policy.authUsers_.emplace_back(authInfo);
    }
}

// Stub implementation for test mock - no dependency on dlp_permission_serializer
int32_t StubSerializeDlpPermission(const PermissionPolicy& policy, unordered_json& jsonObj)
{
    int32_t checkRet = CheckPolicySerializableInMock(policy);
    if (checkRet != DLP_OK) {
        return checkRet;
    }

    jsonObj = unordered_json::object();
    SerializeBasePolicy(policy, jsonObj);
    SerializeCryptoPolicy(policy, jsonObj);
    SerializeAuthUsers(policy, jsonObj);
    SerializeEveryone(policy, jsonObj);
    return DLP_OK;
}

int32_t StubDeserializeDlpPermission(const unordered_json& jsonObj, PermissionPolicy& policy)
{
    ResetPolicyForMockDeserialize(policy);
    DeserializeBasePolicy(jsonObj, policy);
    DeserializeExtraPolicy(jsonObj, policy);
    DeserializeCryptoPolicy(jsonObj, policy);
    DeserializeEveryone(jsonObj, policy);
    DeserializeAuthUsers(jsonObj, policy);
    return DLP_OK;
}
}  // namespace

int32_t DlpPermissionKit::GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert)
{
    unordered_json jsonObj;
    int32_t res = StubSerializeDlpPermission(policy, jsonObj);
    if (res != DLP_OK) {
        return res;
    }
    std::string certStr = jsonObj.dump();
    cert = std::vector<uint8_t>(certStr.begin(), certStr.end());
    return DLP_OK;
}

int32_t DlpPermissionKit::ParseDlpCertificate(sptr<CertParcel>& certParcel, PermissionPolicy& policy,
    const std::string& appId, bool offlineAccess)
{
    (void)offlineAccess;
    
    if (certParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "ParseDlpCertificate input null certParcel");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    
    if (appId.empty()) {
        DLP_LOG_ERROR(LABEL, "ParseDlpCertificate input empty appId");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    
    if (certParcel->cert.empty()) {
        DLP_LOG_ERROR(LABEL, "ParseDlpCertificate input empty cert");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    
    std::string encJsonStr(certParcel->cert.begin(), certParcel->cert.end());
    auto jsonObj = unordered_json::parse(encJsonStr, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    certParcel->offlineCert = certParcel->cert;
    return StubDeserializeDlpPermission(jsonObj, policy);
}

int32_t DlpPermissionKit::SetReadFlag(uint32_t uid)
{
    return DLP_OK;
}

int32_t DlpPermissionKit::SetFileInfo(const std::string& uri, const FileInfo& fileInfo)
{
    (void)uri;
    (void)fileInfo;
    return DLP_OK;
}

int32_t DlpPermissionKit::GetWaterMark(const bool waterMarkConfig)
{
    (void)waterMarkConfig;
    return DLP_OK;
}

int32_t DlpPermissionKit::GetAbilityInfos(const AAFwk::Want& want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    (void)want;
    (void)flags;
    (void)userId;
    abilityInfos = g_mockAbilityInfos;
    return g_mockGetAbilityInfosRet;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

namespace OHOS {
namespace Security {
namespace DlpPermissionUnitTest {
void SetMockGetAbilityInfos(int32_t ret, const std::vector<AppExecFwk::AbilityInfo>& abilityInfos)
{
    OHOS::Security::DlpPermission::g_mockGetAbilityInfosRet = ret;
    OHOS::Security::DlpPermission::g_mockAbilityInfos = abilityInfos;
}

void ResetDlpPermissionKitMockState()
{
    OHOS::Security::DlpPermission::g_mockGetAbilityInfosRet = DlpPermission::DLP_OK;
    OHOS::Security::DlpPermission::g_mockAbilityInfos.clear();
}
}  // namespace DlpPermissionUnitTest
}  // namespace Security
}  // namespace OHOS
