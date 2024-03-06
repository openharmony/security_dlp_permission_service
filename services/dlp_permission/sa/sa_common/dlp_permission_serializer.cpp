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

#include "dlp_permission_serializer.h"
#include <cinttypes>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "hex_string.h"
#include "permission_policy.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
const std::string KIA_INDEX = "KIA";
const std::string OWNER_ACCOUNT_NAME = "ownerAccountName";
const std::string OWNER_ACCOUNT_ID = "ownerAccountId";
const std::string VERSION_INDEX = "version";
const std::string PERM_EXPIRY_TIME = "expireTime";
const std::string ACCOUNT_INDEX = "account";
const std::string AESKEY = "filekey";
const std::string AESKEY_LEN = "filekeyLen";
const std::string IV = "iv";
const std::string IV_LEN = "ivLen";
const std::string HMACKEY = "hmacKey";
const std::string HMACKEY_LEN = "hmacKeyLen";
const std::string DLP_VERSION_LOW_CAMEL_CASE = "dlpVersion";
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string EXTRA_INFO_LEN = "extraInfoLen";
const std::string EXTRA_INFO = "extraInfo";
const std::string ENC_ACCOUNT_TYPE = "accountType";
const std::string ONLINE_POLICY_CONTENT = "plaintextPolicy";
const std::string NEED_ONLINE = "needOnline";
const std::string FILE_INDEX = "file";
const std::string POLICY_INDEX = "policy";
const std::string READ_INDEX = "read";
const std::string EDIT_INDEX = "edit";
const std::string FC_INDEX = "fullCtrl";
const std::string RIGHT_INDEX = "right";
const std::string EVERYONE_INDEX = "everyone";
const std::string ENC_POLICY_INDEX = "encPolicy";
const std::string POLICY_CERT_VERSION = "policyCertVersion";
const std::string ONLINE_CERT = "onlineCert";
const std::string ENC_POLICY = "encPolicy";
const std::string OFFLINE_CERT = "offlineCert";
const std::string ACCOUNT_TYPE = "accountType";
const std::string RECEIVER_ACCOUNT_INFO = "receiverAccountInfo";
constexpr uint64_t  VALID_TIME_STAMP = 2147483647;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionSerializer"};
}  // namespace

DlpPermissionSerializer& DlpPermissionSerializer::GetInstance()
{
    static DlpPermissionSerializer instance;
    return instance;
}

static int32_t ReadUint8ArrayFromJson(const unordered_json& permJson, uint8_t** buff, uint32_t& buffLen,
    const std::string& keyName, const std::string& lenName)
{
    if (!lenName.empty() && permJson.find(lenName) != permJson.end() && permJson.at(lenName).is_number()) {
        permJson.at(lenName).get_to(buffLen);
    }

    if (permJson.find(keyName) != permJson.end() && permJson.at(keyName).is_string()) {
        std::string tmp = permJson.at(keyName).get<std::string>();

        uint32_t length = tmp.size() / BYTE_TO_HEX_OPER_LENGTH;
        if (length != buffLen) {
            buffLen = length;
        }
        *buff = new (std::nothrow) uint8_t[length];
        if (*buff == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
        }
        int32_t res = HexStringToByte(tmp.c_str(), *buff, length);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Hexstring to byte fail");
            memset_s(*buff, length, 0, length);
            delete[] *buff;
            *buff = nullptr;
        }

        return res;
    }
    return DLP_OK;
}

static void TransHexStringToByte(std::string& outer, const std::string& input)
{
    uint32_t len = input.size() / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t* buff = new (std::nothrow) uint8_t[len + 1];
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }

    int32_t res = HexStringToByte(input.c_str(), buff, len);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Hexstring to byte fail");
        (void)memset_s(buff, len, 0, len);
        delete[] buff;
        buff = nullptr;
        return;
    }
    buff[len] = '\0';
    outer = reinterpret_cast<char *>(buff);
    (void)memset_s(buff, len, 0, len);
    delete[] buff;
}

static void SerializeAuthUserInfo(unordered_json& authUsersJson,
    const AuthUserInfo& userInfo)
{
    bool read = false;
    bool edit = false;
    bool fullCtrl = false;

    switch (userInfo.authPerm) {
        case READ_ONLY: {
            read = true;
            break;
        }
        case CONTENT_EDIT: {
            edit = true;
            break;
        }
        case FULL_CONTROL: {
            read = true;
            edit = true;
            fullCtrl = true;
            break;
        }
        default:
            break;
    }

    unordered_json rightInfoJson;
    rightInfoJson[READ_INDEX] = read;
    rightInfoJson[EDIT_INDEX] = edit;
    rightInfoJson[FC_INDEX] = fullCtrl;
    unordered_json accountRight;
    accountRight[RIGHT_INDEX] = rightInfoJson;
    authUsersJson[userInfo.authAccount.c_str()] = accountRight;
    return;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserInfo(const unordered_json& accountInfoJson,
    AuthUserInfo& userInfo)
{
    unordered_json rightInfoJson;
    if (accountInfoJson.find(RIGHT_INDEX) != accountInfoJson.end() && accountInfoJson.at(RIGHT_INDEX).is_object()) {
        accountInfoJson.at(RIGHT_INDEX).get_to(rightInfoJson);
    }

    bool edit = false;
    bool fullCtrl = false;

    if (rightInfoJson.find(EDIT_INDEX) != rightInfoJson.end() && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }

    if (rightInfoJson.find(FC_INDEX) != rightInfoJson.end() && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }

    if (fullCtrl) {
        userInfo.authPerm = FULL_CONTROL;
    } else if (edit) {
        userInfo.authPerm = CONTENT_EDIT;
    } else {
        userInfo.authPerm = READ_ONLY;
    }

    userInfo.permExpiryTime = VALID_TIME_STAMP;
    userInfo.authAccountType = CLOUD_ACCOUNT;

    return DLP_OK;
}

static unordered_json SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers)
{
    unordered_json authUsersJson;
    for (auto it = authUsers.begin(); it != authUsers.end(); ++it) {
        SerializeAuthUserInfo(authUsersJson, *it);
    }
    return authUsersJson;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserList(
    const unordered_json& authUsersJson, std::vector<AuthUserInfo>& userList)
{
    for (auto iter = authUsersJson.begin(); iter != authUsersJson.end(); ++iter) {
        AuthUserInfo authInfo;
        std::string name = iter.key();
        authInfo.authAccount = name;
        unordered_json accountInfo = iter.value();
        int32_t res = DeserializeAuthUserInfo(accountInfo, authInfo);
        if (res == DLP_OK) {
            userList.emplace_back(authInfo);
        } else {
            userList.clear();
            return res;
        }
    }
    return DLP_OK;
}

static void SerializeEveryoneInfo(const PermissionPolicy& policy, unordered_json& permInfoJson)
{
    if (policy.supportEveryone_) {
        bool read = false;
        bool edit = false;
        bool fullCtrl = false;

        switch (policy.everyonePerm_) {
            case READ_ONLY: {
                read = true;
                break;
            }
            case CONTENT_EDIT: {
                edit = true;
                break;
            }
            case FULL_CONTROL: {
                read = true;
                edit = true;
                fullCtrl = true;
                break;
            }
            default:
                break;
        }

        unordered_json rightInfoJson;
        rightInfoJson[READ_INDEX] = read;
        rightInfoJson[EDIT_INDEX] = edit;
        rightInfoJson[FC_INDEX] = fullCtrl;
        unordered_json everyoneJson;
        everyoneJson[RIGHT_INDEX] = rightInfoJson;
        permInfoJson[EVERYONE_INDEX] = everyoneJson;
        return;
    }
}

int32_t DlpPermissionSerializer::SerializeDlpPermission(const PermissionPolicy& policy, unordered_json& permInfoJson)
{
    uint32_t keyHexLen = policy.GetAeskeyLen() * BYTE_TO_HEX_OPER_LENGTH + 1;
    auto keyHex = std::make_unique<char[]>(keyHexLen);
    int32_t res = ByteToHexString(policy.GetAeskey(), policy.GetAeskeyLen(), keyHex.get(), keyHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        return res;
    }

    uint32_t ivHexLen = policy.GetIvLen() * BYTE_TO_HEX_OPER_LENGTH + 1;
    auto ivHex = std::make_unique<char[]>(ivHexLen);
    res = ByteToHexString(policy.GetIv(), policy.GetIvLen(), ivHex.get(), ivHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        return res;
    }

    uint32_t hmacKeyHexLen = policy.GetHmacKeyLen() * BYTE_TO_HEX_OPER_LENGTH + 1;
    auto hmacKeyHex = std::make_unique<char[]>(hmacKeyHexLen);
    res = ByteToHexString(policy.GetHmacKey(), policy.GetHmacKeyLen(), hmacKeyHex.get(), hmacKeyHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        return res;
    }

    unordered_json authUsersJson = SerializeAuthUserList(policy.authUsers_);
    unordered_json policyJson;
    policyJson[KIA_INDEX] = "";
    policyJson[OWNER_ACCOUNT_NAME] = policy.ownerAccount_;
    policyJson[OWNER_ACCOUNT_ID] = policy.ownerAccountId_;
    policyJson[VERSION_INDEX] = 1;
    policyJson[PERM_EXPIRY_TIME] = policy.expireTime_;
    policyJson[NEED_ONLINE] = policy.needOnline_;
    policyJson[ACCOUNT_INDEX] = authUsersJson;
    SerializeEveryoneInfo(policy, policyJson);
    permInfoJson[POLICY_INDEX] = policyJson;

    unordered_json fileEnc;
    fileEnc[AESKEY] = keyHex.get();
    fileEnc[AESKEY_LEN] = policy.GetAeskeyLen();
    fileEnc[IV] = ivHex.get();
    fileEnc[IV_LEN] = policy.GetIvLen();
    fileEnc[HMACKEY] = hmacKeyHex.get();
    fileEnc[HMACKEY_LEN] = policy.GetHmacKeyLen();
    fileEnc[DLP_VERSION_LOW_CAMEL_CASE] = policy.dlpVersion_;
    permInfoJson[FILE_INDEX] = fileEnc;
    
    DLP_LOG_INFO(LABEL, "Serialize successfully!");
    return DLP_OK;
}

static int32_t GetPolicyJson(const unordered_json& permJson, unordered_json& plainPolicyJson)
{
    if (permJson.find(ONLINE_POLICY_CONTENT) != permJson.end() && permJson.at(ONLINE_POLICY_CONTENT).is_string()) {
        std::string plainHexPolicy;
        permJson.at(ONLINE_POLICY_CONTENT).get_to(plainHexPolicy);
        std::string plainPolicy;
        TransHexStringToByte(plainPolicy, plainHexPolicy);
        if (!unordered_json::accept(plainPolicy)) {
            return DLP_PARSE_ERROR_VALUE_INVALID;
        }
        plainPolicyJson = unordered_json::parse(plainPolicy);
        if (plainPolicyJson.is_discarded() || (!plainPolicyJson.is_object())) {
            DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
            return DLP_PARSE_ERROR_VALUE_INVALID;
        }
    } else {
        plainPolicyJson = permJson;
    }
    return DLP_OK;
}

bool DlpPermissionSerializer::DeserializeEveryoneInfo(const unordered_json& policyJson, PermissionPolicy& policy)
{
    if (policyJson.find(EVERYONE_INDEX) == policyJson.end() || !policyJson.at(EVERYONE_INDEX).is_object()) {
        return false;
    }

    policy.supportEveryone_ = true;
    unordered_json everyoneInfoJson;
    policyJson.at(EVERYONE_INDEX).get_to(everyoneInfoJson);

    unordered_json rightInfoJson;
    if (everyoneInfoJson.find(RIGHT_INDEX) == everyoneInfoJson.end() ||
        !everyoneInfoJson.at(RIGHT_INDEX).is_object()) {
        return false;
    }
    everyoneInfoJson.at(RIGHT_INDEX).get_to(rightInfoJson);

    bool edit = false;
    bool fullCtrl = false;

    if (rightInfoJson.find(EDIT_INDEX) != rightInfoJson.end() && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }

    if (rightInfoJson.find(FC_INDEX) != rightInfoJson.end() && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }

    if (fullCtrl) {
        policy.everyonePerm_ = FULL_CONTROL;
    } else if (edit) {
        policy.everyonePerm_ = CONTENT_EDIT;
    } else {
        policy.everyonePerm_ = READ_ONLY;
    }
    return true;
}

static void InitPermissionPolicy(PermissionPolicy& policy, const std::vector<AuthUserInfo>& userList,
    unordered_json policyJson)
{
    policy.authUsers_ = userList;
    if (policyJson.find(OWNER_ACCOUNT_NAME) != policyJson.end() && policyJson.at(OWNER_ACCOUNT_NAME).is_string()) {
        policyJson.at(OWNER_ACCOUNT_NAME).get_to(policy.ownerAccount_);
    }
    if (policyJson.find(OWNER_ACCOUNT_ID) != policyJson.end() && policyJson.at(OWNER_ACCOUNT_ID).is_string()) {
        policyJson.at(OWNER_ACCOUNT_ID).get_to(policy.ownerAccountId_);
    }
    if (policyJson.find(PERM_EXPIRY_TIME) != policyJson.end() && policyJson.at(PERM_EXPIRY_TIME).is_number()) {
        policyJson.at(PERM_EXPIRY_TIME).get_to(policy.expireTime_);
    }
    if (policyJson.find(NEED_ONLINE) != policyJson.end() && policyJson.at(NEED_ONLINE).is_number()) {
        policyJson.at(NEED_ONLINE).get_to(policy.needOnline_);
    }
    policy.ownerAccountType_ = CLOUD_ACCOUNT;
}

static int32_t DeserializeFileEncJson(PermissionPolicy& policy, unordered_json& plainPolicyJson)
{
    unordered_json fileEncJson;
    if (plainPolicyJson.find(FILE_INDEX) != plainPolicyJson.end() && plainPolicyJson.at(FILE_INDEX).is_object()) {
        plainPolicyJson.at(FILE_INDEX).get_to(fileEncJson);
    }
    uint8_t* key = nullptr;
    uint32_t keyLen = 0;
    int32_t res = ReadUint8ArrayFromJson(fileEncJson, &key, keyLen, AESKEY, AESKEY_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetAeskey(key, keyLen);
    (void)memset_s(key, keyLen, 0, keyLen);
    delete[] key;
    key = nullptr;

    uint8_t* iv = nullptr;
    uint32_t ivLen = 0;
    res = ReadUint8ArrayFromJson(fileEncJson, &iv, ivLen, IV, IV_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetIv(iv, ivLen);
    (void)memset_s(iv, ivLen, 0, ivLen);
    delete[] iv;
    iv = nullptr;

    uint8_t* hmacKey = nullptr;
    uint32_t hmacKeyLen = 0;
    res = ReadUint8ArrayFromJson(fileEncJson, &hmacKey, hmacKeyLen, HMACKEY, HMACKEY_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetHmacKey(hmacKey, hmacKeyLen);
    (void)memset_s(hmacKey, hmacKeyLen, 0, hmacKeyLen);
    delete[] hmacKey;
    hmacKey = nullptr;

    policy.dlpVersion_ = 0;
    if (fileEncJson.find(DLP_VERSION_LOW_CAMEL_CASE) != fileEncJson.end() &&
        fileEncJson.at(DLP_VERSION_LOW_CAMEL_CASE).is_number()) {
        fileEncJson.at(DLP_VERSION_LOW_CAMEL_CASE).get_to(policy.dlpVersion_);
        DLP_LOG_DEBUG(LABEL, "set dlpVersion from DLP_CERT, dlpVersion = %{public}d", policy.dlpVersion_);
    }
    return DLP_OK;
}

int32_t DlpPermissionSerializer::DeserializeDlpPermission(const unordered_json& permJson, PermissionPolicy& policy)
{
    unordered_json plainPolicyJson;
    int32_t res = GetPolicyJson(permJson, plainPolicyJson);
    if (res != DLP_OK) {
        return res;
    }
    unordered_json policyJson;
    if (plainPolicyJson.find(POLICY_INDEX) != plainPolicyJson.end() && plainPolicyJson.at(POLICY_INDEX).is_object()) {
        plainPolicyJson.at(POLICY_INDEX).get_to(policyJson);
    }

    unordered_json accountListJson;
    if (policyJson.find(ACCOUNT_INDEX) != policyJson.end() && policyJson.at(ACCOUNT_INDEX).is_object()) {
        policyJson.at(ACCOUNT_INDEX).get_to(accountListJson);
    }
    DeserializeEveryoneInfo(policyJson, policy);

    std::vector<AuthUserInfo> userList;
    res = DeserializeAuthUserList(accountListJson, userList);
    if (res != DLP_OK) {
        return res;
    }
    InitPermissionPolicy(policy, userList, policyJson);

    res = DeserializeFileEncJson(policy, plainPolicyJson);
    if (res != DLP_OK) {
        return res;
    }
    return DLP_OK;
}

int32_t DlpPermissionSerializer::SerializeEncPolicyData(const DLP_EncPolicyData& encData, unordered_json& encDataJson)
{
    if (encData.dataLen == 0 || encData.dataLen > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert lenth %{public}d is invalid", encData.dataLen);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    uint32_t encDataHexLen = encData.dataLen * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* encDataHex = new (std::nothrow) char[encDataHexLen];
    if (encDataHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t res = ByteToHexString(encData.data, encData.dataLen, encDataHex, encDataHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(encDataHex, encDataHexLen);
        return res;
    }

    encDataJson = {
        {ENC_DATA_LEN, encData.dataLen},
        {ENC_DATA, encDataHex},
        {ENC_ACCOUNT_TYPE, encData.accountType},
    };
    DLP_LOG_INFO(LABEL, "Serialize successfully!");
    FreeCharBuffer(encDataHex, encDataHexLen);
    return DLP_OK;
}

int32_t DlpPermissionSerializer::DeserializeEncPolicyData(const unordered_json& encDataJson, DLP_EncPolicyData& encData,
    bool isNeedAdapter)
{
    if (encDataJson.find(ENC_ACCOUNT_TYPE) != encDataJson.end() && encDataJson.at(ENC_ACCOUNT_TYPE).is_number()) {
        encDataJson.at(ENC_ACCOUNT_TYPE).get_to(encData.accountType);
    }

    if (isNeedAdapter) {
        DLP_LOG_INFO(LABEL, "open 4.0 Dlp File");
        return DLP_OK;
    }

    int32_t res = ReadUint8ArrayFromJson(encDataJson, &encData.data, encData.dataLen, ENC_DATA, ENC_DATA_LEN);
    if (res != DLP_OK) {
        return res;
    }
    DLP_LOG_INFO(LABEL, "Deserialize successfully!");
    return DLP_OK;
}

int32_t getEncJson(const unordered_json& encDataJson, unordered_json& certJson, std::string dataKey,
    std::string extraKey)
{
    if (encDataJson.find(dataKey) == encDataJson.end() || !encDataJson.at(dataKey).is_string()) {
        DLP_LOG_ERROR(LABEL, "key=%{public}s not found", dataKey.c_str());
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (encDataJson.find(extraKey) == encDataJson.end() || !encDataJson.at(extraKey).is_string()) {
        DLP_LOG_ERROR(LABEL, "key=%{public}s not found", extraKey.c_str());
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    certJson[ENC_POLICY] = encDataJson.at(dataKey).get<std::string>();
    certJson[EXTRA_INFO] = encDataJson.at(extraKey).get<std::string>();
    return DLP_OK;
}

int32_t DlpPermissionSerializer::DeserializeEncPolicyDataByFirstVersion(const unordered_json& encDataJson,
    const unordered_json& offlineEncDataJson, DLP_EncPolicyData& encData, std::string ownerAccountId)
{
    unordered_json serverJson;
    int res = getEncJson(encDataJson, serverJson, ENC_DATA, EXTRA_INFO);
    if (res != DLP_OK) {
        return res;
    }
    unordered_json data = { { POLICY_CERT_VERSION, 1 },
                            { OWNER_ACCOUNT_ID, ownerAccountId },
                            { ONLINE_CERT, serverJson } };
    if (offlineEncDataJson != nullptr && !offlineEncDataJson.is_null()) {
        unordered_json offlineServerJson;
        if (offlineEncDataJson.find(ACCOUNT_TYPE) != offlineEncDataJson.end() &&
            offlineEncDataJson.at(ACCOUNT_TYPE).is_number()) {
            uint32_t accountType;
            offlineEncDataJson.at(ACCOUNT_TYPE).get_to(accountType);
            offlineServerJson[ACCOUNT_TYPE] = accountType;
        }
        res = getEncJson(offlineEncDataJson, offlineServerJson, ENC_POLICY, EXTRA_INFO);
        if (res != DLP_OK) {
            return res;
        }
        data[OFFLINE_CERT] = offlineServerJson;
    }
    std::string encDataStr = data.dump();
    encData.data = new (std::nothrow) uint8_t[encDataStr.length()];
    if (encData.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    encData.dataLen = encDataStr.length();
    res = memcpy_s(encData.data, encDataStr.length(),
        reinterpret_cast<const uint8_t*>(encDataStr.c_str()), encDataStr.length());
    if (res != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy encData fill fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
