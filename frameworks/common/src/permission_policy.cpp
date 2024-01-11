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
    if (perm <= NO_PERMISSION || perm > FULL_CONTROL) {
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
    return (CheckAccount(info.authAccount) && CheckPerm(info.authPerm) && CheckTime(info.permExpiryTime) &&
            CheckAccountType(info.authAccountType));
}

static bool CheckAuthUserInfoList(const std::vector<AuthUserInfo>& authUsers_)
{
    uint32_t userNum = authUsers_.size();
    if (userNum > MAX_ACCOUNT_NUM) {
        DLP_LOG_ERROR(LABEL, "Auth users number exceeds %{public}u, total=%{public}u", MAX_ACCOUNT_NUM, userNum);
        return false;
    }
    return (std::none_of(authUsers_.begin(), authUsers_.end(),
        [](const auto& iter) { return !CheckAuthUserInfo(iter); }));
}

static void FreeUint8Buffer(uint8_t** buff, uint32_t& buffLen)
{
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
    authUsers_.clear();
}

PermissionPolicy::PermissionPolicy()
{
    ownerAccount_ = "";
    ownerAccountId_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_ = {};
    expireTime_ = 0;
    needOnline_ = 0;
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
    hmacKey_ = nullptr;
    hmacKeyLen_ = 0;
    dlpVersion_ = CURRENT_VERSION;
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
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
    hmacKey_ = nullptr;
    hmacKeyLen_ = 0;
    dlpVersion_ = CURRENT_VERSION;
}

PermissionPolicy::~PermissionPolicy()
{
    FreePermissionPolicyMem();
}

bool PermissionPolicy::IsValid() const
{
    return (CheckAccount(this->ownerAccount_) && CheckAccount(this->ownerAccountId_) &&
        CheckAccountType(this->ownerAccountType_) && CheckAesParam(this->aeskey_, this->aeskeyLen_) &&
        CheckAesParam(this->iv_, this->ivLen_) && CheckAuthUserInfoList(this->authUsers_) &&
        (this->hmacKeyLen_ == 0 || CheckAesParam(this->hmacKey_, this->hmacKeyLen_)));
}

void PermissionPolicy::SetAeskey(const uint8_t* key, uint32_t keyLen)
{
    if (key == nullptr) {
        DLP_LOG_INFO(LABEL, "Set aes key to null");
        FreeUint8Buffer(&aeskey_, aeskeyLen_);
        return;
    }
    if (!CheckAesParamLen(keyLen)) {
        DLP_LOG_ERROR(LABEL, "Aes key len invalid, len=%{public}u", keyLen);
        return;
    }
    FreeUint8Buffer(&aeskey_, aeskeyLen_);
    if (keyLen < 1) {
        DLP_LOG_ERROR(LABEL, "keyLen error");
        return;
    }
    aeskey_ = new (std::nothrow) uint8_t[keyLen];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for aes key fail", keyLen);
        return;
    }
    aeskeyLen_ = keyLen;
    if (memcpy_s(aeskey_, aeskeyLen_, key, keyLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy aes key buff fail");
        FreeUint8Buffer(&aeskey_, aeskeyLen_);
        return;
    }
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
    if (iv == nullptr) {
        DLP_LOG_INFO(LABEL, "Set iv to null");
        FreeUint8Buffer(&iv_, ivLen_);
        return;
    }
    if (!CheckAesParamLen(ivLen)) {
        DLP_LOG_ERROR(LABEL, "Iv len invalid, len=%{public}u", ivLen);
        return;
    }
    FreeUint8Buffer(&iv_, ivLen_);
    if (ivLen < 1) {
        DLP_LOG_ERROR(LABEL, "ivLen error %{public}u", ivLen);
        return;
    }
    iv_ = new (std::nothrow) uint8_t[ivLen];
    if (iv_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for iv fail", ivLen);
        return;
    }
    ivLen_ = ivLen;
    if (memcpy_s(iv_, ivLen_, iv, ivLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy iv buff fail");
        FreeUint8Buffer(&iv_, ivLen_);
        return;
    }
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
    if (key == nullptr) {
        DLP_LOG_INFO(LABEL, "Set hmacKey to null");
        FreeUint8Buffer(&hmacKey_, hmacKeyLen_);
        return;
    }
    if (!CheckAesParamLen(keyLen)) {
        DLP_LOG_ERROR(LABEL, "keyLen invalid, len = %{public}u", keyLen);
        return;
    }
    FreeUint8Buffer(&hmacKey_, hmacKeyLen_);
    if (keyLen < 1) {
        DLP_LOG_ERROR(LABEL, "keyLen error %{public}u", keyLen);
        return;
    }
    hmacKeyLen_ = keyLen;
    hmacKey_ = new (std::nothrow) uint8_t[hmacKeyLen_];
    if (hmacKey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for hmacKey fail", keyLen);
        return;
    }
    if (memcpy_s(hmacKey_, hmacKeyLen_, key, keyLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy hmacKey buff fail");
        FreeUint8Buffer(&hmacKey_, hmacKeyLen_);
        return;
    }
}

uint8_t* PermissionPolicy::GetHmacKey() const
{
    return hmacKey_;
}

uint32_t PermissionPolicy::GetHmacKeyLen() const
{
    return hmacKeyLen_;
}

void PermissionPolicy::CopyPolicyHmac(const PermissionPolicy& srcPolicy)
{
    if (srcPolicy.hmacKeyLen_ != 0) {
        FreeUint8Buffer(&hmacKey_, hmacKeyLen_);
        hmacKeyLen_ = srcPolicy.hmacKeyLen_;
        hmacKey_ = new (std::nothrow) uint8_t[hmacKeyLen_];
        if (hmacKey_ == nullptr) {
            DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for hmacKey fail", hmacKeyLen_);
            FreePermissionPolicyMem();
            return;
        }
        if (memcpy_s(hmacKey_, hmacKeyLen_, srcPolicy.hmacKey_, srcPolicy.hmacKeyLen_) != EOK) {
            DLP_LOG_ERROR(LABEL, "Memcpy hmacKey buff fail");
            FreePermissionPolicyMem();
            return;
        }
    }
}

void PermissionPolicy::CopyPermissionPolicy(const PermissionPolicy& srcPolicy)
{
    if (!srcPolicy.IsValid()) {
        return;
    }
    DLP_LOG_DEBUG(LABEL, "ownerAccount_ %{private}s ownerAccountId %{private}s"
        " accountType %{public}u needOnline %{public}u expireTime %{public}" PRId64,
        srcPolicy.ownerAccount_.c_str(), srcPolicy.ownerAccountId_.c_str(),
        srcPolicy.ownerAccountType_, srcPolicy.needOnline_, srcPolicy.expireTime_);
    ownerAccount_ = srcPolicy.ownerAccount_;
    ownerAccountId_ = srcPolicy.ownerAccountId_;
    ownerAccountType_ = srcPolicy.ownerAccountType_;
    authUsers_ = srcPolicy.authUsers_;
    supportEveryone_ = srcPolicy.supportEveryone_;
    everyonePerm_ = srcPolicy.everyonePerm_;
    expireTime_ = srcPolicy.expireTime_;
    needOnline_ = srcPolicy.needOnline_;
    aeskeyLen_ = srcPolicy.aeskeyLen_;
    aeskey_ = new (std::nothrow) uint8_t[aeskeyLen_];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for aes key fail", aeskeyLen_);
        return;
    }
    if (memcpy_s(aeskey_, aeskeyLen_, srcPolicy.aeskey_, srcPolicy.aeskeyLen_) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy aes key buff fail");
        FreePermissionPolicyMem();
        return;
    }
    ivLen_ = srcPolicy.ivLen_;
    iv_ = new (std::nothrow) uint8_t[ivLen_];
    if (iv_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}u buff for iv fail", ivLen_);
        FreePermissionPolicyMem();
        return;
    }
    if (memcpy_s(iv_, ivLen_, srcPolicy.iv_, srcPolicy.ivLen_) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy iv buff fail");
        FreePermissionPolicyMem();
        return;
    }
    CopyPolicyHmac(srcPolicy);
    dlpVersion_ = srcPolicy.dlpVersion_;
}

bool CheckAccountType(DlpAccountType accountType)
{
    if (accountType != CLOUD_ACCOUNT && accountType != DOMAIN_ACCOUNT && accountType != APPLICATION_ACCOUNT) {
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
        buff = nullptr;
    }
}

bool CheckAesParamLen(uint32_t len)
{
    return VALID_AESPARAM_LEN.count(len) > 0;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS