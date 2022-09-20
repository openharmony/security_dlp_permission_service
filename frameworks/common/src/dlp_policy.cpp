/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dlp_policy.h"
#include <chrono>
#include <set>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
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
        DLP_LOG_ERROR(LABEL, "Aes key or iv len invalid, len=%{public}d", len);
        return false;
    }
    return true;
}

static bool CheckAccount(const std::string& account)
{
    uint32_t accountSize = account.size();
    if (accountSize == 0 || accountSize > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Account len invalid, len=%{public}d", accountSize);
        return false;
    }
    return true;
}

static bool CheckPerm(uint32_t perm)
{
    if (perm <= 0 || perm >= DEFAULT_PERM) {
        DLP_LOG_ERROR(LABEL, "Auth Perm invalid, perm=%{public}d", perm);
        return false;
    }
    return true;
}

static bool CheckTime(uint64_t time)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    if (time < curTime) {
        DLP_LOG_ERROR(LABEL,
            "Perm expiry time is earlier than current time, cur=%{public}" PRId64 ", set=%{public}" PRId64 "", curTime,
            time);
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
        DLP_LOG_ERROR(LABEL, "Auth users number exceeds %{public}d, total=%{public}d", MAX_ACCOUNT_NUM, userNum);
        return false;
    }
    for (auto iter : authUsers_) {
        if (!CheckAuthUserInfo(iter)) {
            return false;
        }
    }
    return true;
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
    ownerAccount_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_.clear();
}

PermissionPolicy::PermissionPolicy()
{
    ownerAccount_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_ = {};
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
}

PermissionPolicy::PermissionPolicy(const DlpProperty& property)
{
    ownerAccount_ = property.ownerAccount;
    ownerAccountType_ = property.ownerAccountType;
    authUsers_ = property.authUsers;
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
}

PermissionPolicy::~PermissionPolicy()
{
    FreePermissionPolicyMem();
}

bool PermissionPolicy::IsValid() const
{
    return (CheckAccount(this->ownerAccount_) && CheckAccountType(this->ownerAccountType_) &&
            CheckAesParam(this->aeskey_, this->aeskeyLen_) && CheckAesParam(this->iv_, this->ivLen_) &&
            CheckAuthUserInfoList(this->authUsers_));
}

void PermissionPolicy::SetAeskey(const uint8_t* key, uint32_t keyLen)
{
    if (key == nullptr) {
        DLP_LOG_INFO(LABEL, "Set aes key to null");
        FreeUint8Buffer(&aeskey_, aeskeyLen_);
        return;
    }
    if (!CheckAesParamLen(keyLen)) {
        DLP_LOG_ERROR(LABEL, "Aes key len invalid, len=%{public}d", keyLen);
        return;
    }
    FreeUint8Buffer(&aeskey_, aeskeyLen_);
    aeskey_ = new (std::nothrow) uint8_t[keyLen];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}d buff for aes key fail", keyLen);
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
        DLP_LOG_ERROR(LABEL, "Iv len invalid, len=%{public}d", ivLen);
        return;
    }
    FreeUint8Buffer(&iv_, ivLen_);
    iv_ = new (std::nothrow) uint8_t[ivLen];
    if (iv_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}d buff for iv fail", ivLen);
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

void PermissionPolicy::CopyPermissionPolicy(const PermissionPolicy& srcPolicy)
{
    if (!srcPolicy.IsValid()) {
        return;
    }
    ownerAccount_ = srcPolicy.ownerAccount_;
    ownerAccountType_ = srcPolicy.ownerAccountType_;
    authUsers_ = srcPolicy.authUsers_;
    aeskeyLen_ = srcPolicy.aeskeyLen_;
    aeskey_ = new (std::nothrow) uint8_t[aeskeyLen_];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc %{public}d buff for aes key fail", aeskeyLen_);
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
        DLP_LOG_ERROR(LABEL, "Alloc %{public}d buff for iv fail", ivLen_);
        FreePermissionPolicyMem();
        return;
    }
    if (memcpy_s(iv_, ivLen_, srcPolicy.iv_, srcPolicy.ivLen_) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy iv buff fail");
        FreePermissionPolicyMem();
        return;
    }
}

bool CheckAccountType(DlpAccountType accountType)
{
    if (accountType > APPLICATION_ACCOUNT || accountType < CLOUD_ACCOUNT) {
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