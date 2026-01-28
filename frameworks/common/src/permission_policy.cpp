/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "permission_policy.h"
#include <chrono>
#include <cinttypes>
#include <set>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_public_interface.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPolicyCheck"};
const uint32_t MAX_ACCOUNT_SIZE = 1024;
const uint32_t MAX_ACCOUNT_NUM = 100;
const uint32_t NO_EXPIRATION_DATA = 0;
const std::set<uint32_t> VALID_AESPARAM_LEN = {16, 24, 32};
}  // namespace

static bool CheckAesParam(const uint8_t* buff, uint32_t len)
{
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes key or iv is null");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "Aes key or iv len invalid, len=%{public}u", len);
        return false;
    }
    return true;
}

static bool CheckAccount(const std::string& account)
{
    uint32_t accountSize = account.size();
    if (accountSize == 0 || accountSize > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Account len invalid, len=%{public}u", accountSize);
        return false;
    }
    return true;
}

static bool CheckPerm(uint32_t perm)
{
    if (perm <= static_cast<uint32_t>(DLPFileAccess::NO_PERMISSION) ||
        perm > static_cast<uint32_t>(DLPFileAccess::FULL_CONTROL)) {
        DLP_LOG_ERROR(LABEL, "Auth Perm invalid, perm=%{public}u", perm);
        return false;
    }
    return true;
}

static bool CheckTime(uint64_t time)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    if (time < curTime) {
        DLP_LOG_ERROR(LABEL, "Perm expiry time is earlier than current time, cur=%{public}s, set=%{public}s",
            std::to_string(curTime).c_str(), std::to_string(time).c_str());
        return false;
    }
    return true;
}

static bool CheckAuthUserInfo(const AuthUserInfo& info)
{
    return (CheckAccount(info.authAccount) &&
            CheckPerm(static_cast<uint32_t>(info.authPerm)) &&
            CheckTime(info.permExpiryTime) &&
            CheckAccountType(info.authAccountType));
}

static bool CheckAuthUserInfoList(const std::vector<AuthUserInfo>& authUsers)
{
    uint32_t userNum = authUsers.size();
    if (userNum > MAX_ACCOUNT_NUM) {
        DLP_LOG_ERROR(LABEL, "Auth users number exceeds %{public}u, total=%{public}u", MAX_ACCOUNT_NUM, userNum);
        return false;
    }
    return (std::none_of(authUsers.begin(), authUsers.end(),
        [](const auto& iter) { return !CheckAuthUserInfo(iter); }));
}

static void FreeUint8Buffer(uint8_t** buff, uint32_t& buffLen)
{
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "Uint8 buffer is already nullptr.");
        return;
    }
    if (*buff != nullptr) {
        memset_s(*buff, buffLen, 0, buffLen);
        delete[] *buff;
        *buff = nullptr;
    }
    buffLen = 0;
}

void PermissionPolicy::FreePermissionPolicyMem()
{
    FreeUint8Buffer(&aeskey_, aeskeyLen_);
    FreeUint8Buffer(&iv_, ivLen_);
    FreeUint8Buffer(&hmacKey_, hmacKeyLen_);
    ownerAccount_ = "";
    ownerAccountId_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    customProperty_ = "";
    authUsers_.clear();
}

PermissionPolicy::PermissionPolicy()
{
    ownerAccount_ = "";
    ownerAccountId_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_ = {};
    expireTime_ = 0;
    actionUponExpiry_ = 0;
    needOnline_ = 0;
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
    hmacKey_ = nullptr;
    hmacKeyLen_ = 0;
    dlpVersion_ = CURRENT_VERSION;
    debug_ = false;
    customProperty_ = "";
    fileId = "";
    allowedOpenCount_ = 0;
    waterMarkConfig_ = false;
    canFindWaterMarkConfig_ = false;
    canFindCountdown_ = false;
}

PermissionPolicy::PermissionPolicy(const DlpProperty& property)
{
    ownerAccount_ = property.ownerAccount;
    ownerAccountId_ = property.ownerAccountId;
    ownerAccountType_ = property.ownerAccountType;
    authUsers_ = property.authUsers;
    supportEveryone_ = property.supportEveryone;
    everyonePerm_ = property.everyonePerm;
    expireTime_ = property.expireTime;
    needOnline_ = !property.offlineAccess;
    actionUponExpiry_ = static_cast<uint32_t>(property.actionUponExpiry);
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
    hmacKey_ = nullptr;
    hmacKeyLen_ = 0;
    dlpVersion_ = CURRENT_VERSION;
    debug_ = false;
    customProperty_ = property.customProperty.enterprise;
    fileId = property.fileId;
    allowedOpenCount_ = property.allowedOpenCount;
    waterMarkConfig_ = property.waterMarkConfig;
    countdown_ = property.countdown;
    canFindWaterMarkConfig_ = false;
    canFindCountdown_ = false;
}

PermissionPolicy::~PermissionPolicy()
{
    FreePermissionPolicyMem();
}

bool PermissionPolicy::IsValid() const
{
    if (this->ownerAccountType_ == ENTERPRISE_ACCOUNT) {
        return (CheckAesParam(this->aeskey_, this->aeskeyLen_) &&
            CheckAesParam(this->iv_, this->ivLen_) && CheckAuthUserInfoList(this->authUsers_) &&
            (this->hmacKeyLen_ == 0 || CheckAesParam(this->hmacKey_, this->hmacKeyLen_)));
    }
    return (CheckAccount(this->ownerAccount_) && CheckAccount(this->ownerAccountId_) &&
        CheckAccountType(this->ownerAccountType_) && CheckAesParam(this->aeskey_, this->aeskeyLen_) &&
        CheckAesParam(this->iv_, this->ivLen_) && CheckAuthUserInfoList(this->authUsers_) &&
        (this->hmacKeyLen_ == 0 || CheckAesParam(this->hmacKey_, this->hmacKeyLen_)));
}

void PermissionPolicy::SetDebug(bool debug)
{
    debug_ = debug;
}

static void SetKey(const uint8_t* originalKey, uint32_t originalKeyLen, uint8_t** key, uint32_t& keyLen)
{
    if (key == nullptr) {
        DLP_LOG_ERROR(LABEL, "key is null.");
        return;
    }
    if (originalKey == nullptr) {
        DLP_LOG_INFO(LABEL, "Set key to null");
        FreeUint8Buffer(key, keyLen);
        return;
    }
    if (!CheckAesParamLen(originalKeyLen)) {
        DLP_LOG_ERROR(LABEL, "Key len invalid, len=%{public}u", originalKeyLen);
        return;
    }
    FreeUint8Buffer(key, keyLen);
    *key = new (std::nothrow) uint8_t[originalKeyLen];
    if (*key == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for key fail", originalKeyLen);
        return;
    }
    keyLen = originalKeyLen;
    if (memcpy_s(*key, keyLen, originalKey, originalKeyLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy key buff fail");
        FreeUint8Buffer(key, keyLen);
        return;
    }
}

void PermissionPolicy::SetAeskey(const uint8_t* key, uint32_t keyLen)
{
    DLP_LOG_DEBUG(LABEL, "Start set key.");
    SetKey(key, keyLen, &aeskey_, aeskeyLen_);
}

uint8_t* PermissionPolicy::GetAeskey() const
{
    return aeskey_;
}

uint32_t PermissionPolicy::GetAeskeyLen() const
{
    return aeskeyLen_;
}

void PermissionPolicy::SetIv(const uint8_t* iv, uint32_t ivLen)
{
    DLP_LOG_DEBUG(LABEL, "Start set offset.");
    SetKey(iv, ivLen, &iv_, ivLen_);
}

uint8_t* PermissionPolicy::GetIv() const
{
    return iv_;
}

uint32_t PermissionPolicy::GetIvLen() const
{
    return ivLen_;
}

void PermissionPolicy::SetHmacKey(const uint8_t* key, uint32_t keyLen)
{
    DLP_LOG_DEBUG(LABEL, "Start set hmac key.");
    SetKey(key, keyLen, &hmacKey_, hmacKeyLen_);
}

uint8_t* PermissionPolicy::GetHmacKey() const
{
    return hmacKey_;
}

uint32_t PermissionPolicy::GetHmacKeyLen() const
{
    return hmacKeyLen_;
}

int32_t PermissionPolicy::GetAllowedOpenCount() const
{
    return allowedOpenCount_;
}

bool PermissionPolicy::GetwaterMarkConfig() const
{
    return waterMarkConfig_;
}

int32_t PermissionPolicy::GetCountdown() const
{
    return countdown_;
}

void PermissionPolicy::CopyPolicyHmac(const PermissionPolicy& srcPolicy)
{
    if (srcPolicy.hmacKeyLen_ == 0 || srcPolicy.hmacKey_ == nullptr) {
        return;
    }
    SetHmacKey(srcPolicy.hmacKey_, srcPolicy.hmacKeyLen_);
}

void PermissionPolicy::CopyPermissionPolicy(const PermissionPolicy& srcPolicy)
{
    if (!srcPolicy.IsValid()) {
        return;
    }
    DLP_LOG_DEBUG(LABEL, "accountType %{public}u needOnline %{public}u expireTime %{private}" PRId64,
        srcPolicy.ownerAccountType_, srcPolicy.needOnline_, srcPolicy.expireTime_);
    ownerAccount_ = srcPolicy.ownerAccount_;
    ownerAccountId_ = srcPolicy.ownerAccountId_;
    ownerAccountType_ = srcPolicy.ownerAccountType_;
    authUsers_ = srcPolicy.authUsers_;
    supportEveryone_ = srcPolicy.supportEveryone_;
    everyonePerm_ = srcPolicy.everyonePerm_;
    expireTime_ = srcPolicy.expireTime_;
    actionUponExpiry_ = srcPolicy.actionUponExpiry_;
    needOnline_ = srcPolicy.needOnline_;
    customProperty_ = srcPolicy.customProperty_;
    SetAeskey(srcPolicy.aeskey_, srcPolicy.aeskeyLen_);
    SetIv(srcPolicy.iv_, srcPolicy.ivLen_);
    CopyPolicyHmac(srcPolicy);
    dlpVersion_ = srcPolicy.dlpVersion_;
    if (srcPolicy.ownerAccountType_ == ENTERPRISE_ACCOUNT) {
        appId = srcPolicy.appId;
    }
    fileId = srcPolicy.fileId;
    allowedOpenCount_ = srcPolicy.allowedOpenCount_;
    waterMarkConfig_ = srcPolicy.waterMarkConfig_;
    countdown_ = srcPolicy.countdown_;
    canFindWaterMarkConfig_ = srcPolicy.canFindWaterMarkConfig_;
    canFindCountdown_ = srcPolicy.canFindCountdown_;
}

int32_t PermissionPolicy::CheckActionUponExpiry()
{
    if (expireTime_ != NO_EXPIRATION_DATA) {
        if (actionUponExpiry_ > static_cast<uint32_t>(ActionType::OPEN) ||
           actionUponExpiry_ < static_cast<uint32_t>(ActionType::NOTOPEN)) {
            return DLP_PARSE_ERROR_VALUE_INVALID;
        }
    } else {
        actionUponExpiry_ = static_cast<uint32_t>(ActionType::NOTOPEN);
    }
    return DLP_OK;
}

bool CheckAccountType(DlpAccountType accountType)
{
    if (accountType != CLOUD_ACCOUNT && accountType != DOMAIN_ACCOUNT && accountType != APPLICATION_ACCOUNT
        && accountType != ENTERPRISE_ACCOUNT) {
        DLP_LOG_ERROR(LABEL, "Account type is invalid, type=%{public}d", accountType);
        return false;
    }
    return true;
}

void FreeCharBuffer(char* buff, uint32_t buffLen)
{
    if (buff != nullptr) {
        memset_s(buff, buffLen, 0, buffLen);
        delete[] buff;
    }
}

bool CheckAesParamLen(uint32_t len)
{
    return VALID_AESPARAM_LEN.count(len) > 0;
}

bool SandboxInfo::Marshalling(Parcel &out) const
{
    if (!(out.WriteInt32(appIndex))) {
        DLP_LOG_ERROR(LABEL, "Write appIndex fail");
        return false;
    }
    if (!(out.WriteUint32(tokenId))) {
        DLP_LOG_ERROR(LABEL, "Write tokenId fail");
        return false;
    }
    return true;
}

SandboxInfo* SandboxInfo::Unmarshalling(Parcel &in)
{
    auto *parcel = new (std::nothrow) SandboxInfo();
    if (parcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!(in.ReadInt32(parcel->appIndex))) {
        DLP_LOG_ERROR(LABEL, "Read appIndex fail");
        delete parcel;
        return nullptr;
    }
    if (!(in.ReadUint32(parcel->tokenId))) {
        DLP_LOG_ERROR(LABEL, "Read tokenId fail");
        delete parcel;
        return nullptr;
    }
    return parcel;
}

bool FileInfo::Marshalling(Parcel &out) const
{
    if (!(out.WriteBool(isNotOwnerAndReadOnce))) {
        DLP_LOG_ERROR(LABEL, "Write isNotOwnerAndReadOnce fail");
        return false;
    }
    if (!(out.WriteBool(isWatermark))) {
        DLP_LOG_ERROR(LABEL, "Write isWatermark fail");
        return false;
    }
    if (!(out.WriteString(accountName))) {
        DLP_LOG_ERROR(LABEL, "Write accountName fail");
        return false;
    }
    if (!(out.WriteString(maskInfo))) {
        DLP_LOG_ERROR(LABEL, "Write maskInfo fail");
        return false;
    }
    if (!(out.WriteString(fileId))) {
        DLP_LOG_ERROR(LABEL, "Write fileId fail");
        return false;
    }
    return true;
}

FileInfo* FileInfo::Unmarshalling(Parcel &in)
{
    auto *parcel = new (std::nothrow) FileInfo();
    do {
        if (parcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
            break;
        }
        if (!(in.ReadBool(parcel->isNotOwnerAndReadOnce))) {
            DLP_LOG_ERROR(LABEL, "Read isNotOwnerAndReadOnce fail");
            break;
        }
        if (!(in.ReadBool(parcel->isWatermark))) {
            DLP_LOG_ERROR(LABEL, "Read isWatermark fail");
            break;
        }
        if (!(in.ReadString(parcel->accountName))) {
            DLP_LOG_ERROR(LABEL, "Read accountName fail");
            break;
        }
        if (!(in.ReadString(parcel->maskInfo))) {
            DLP_LOG_ERROR(LABEL, "Read maskInfo fail");
            break;
        }
        if (!(in.ReadString(parcel->fileId))) {
            DLP_LOG_ERROR(LABEL, "Read fileId fail");
            break;
        }
        return parcel;
    } while (0);
    if (parcel) {
        delete parcel;
    }
    return nullptr;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS