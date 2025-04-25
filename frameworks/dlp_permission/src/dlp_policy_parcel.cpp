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

#include "dlp_policy_parcel.h"
#include "dlp_permission_log.h"
#include "permission_policy.h"
#include "securec.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
const uint32_t MAX_ACCOUNT_NUM = 100;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionParcel"};
}

bool DlpPolicyParcel::Marshalling(Parcel& out) const
{
    if (!MarshallingUserList(out)) {
        DLP_LOG_ERROR(LABEL, "Marshalling user list fail");
        return false;
    }
    if (!(out.WriteBool(this->policyParams_.supportEveryone_))) {
        DLP_LOG_ERROR(LABEL, "Write supportEveryone_ fail");
        return false;
    }
    if (!(out.WriteUint8(static_cast<uint8_t>(this->policyParams_.everyonePerm_)))) {
        DLP_LOG_ERROR(LABEL, "Write everyonePerm_ fail");
        return false;
    }

    if (!MarshallingAccountInfo(out)) {
        DLP_LOG_ERROR(LABEL, "Marshalling accountInfo fail");
        return false;
    }
    if (!(out.WriteUint8(static_cast<uint8_t>(this->policyParams_.perm_)))) {
        DLP_LOG_ERROR(LABEL, "Write perm fail");
        return false;
    }

    if (!MarshallingKey(out)) {
        DLP_LOG_ERROR(LABEL, "Marshalling key fail");
        return false;
    }
    if (!MarshallingExpireTime(out)) {
        DLP_LOG_ERROR(LABEL, "Marshalling expire time fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.dlpVersion_))) {
        DLP_LOG_ERROR(LABEL, "Write dlpVersion_ fail");
        return false;
    }
    if (!(out.WriteBool(this->policyParams_.debug_))) {
        DLP_LOG_ERROR(LABEL, "Write debug_ fail");
        return false;
    }
    return true;
}

bool DlpPolicyParcel::MarshallingUserList(Parcel& out) const
{
    const std::vector<AuthUserInfo>& userList = this->policyParams_.authUsers_;
    uint32_t listSize = userList.size();
    if (listSize > MAX_ACCOUNT_NUM) {
        DLP_LOG_ERROR(LABEL, "Auth users number exceeds %{public}u, total=%{public}u", MAX_ACCOUNT_NUM, listSize);
        return false;
    }
    if (!(out.WriteUint32(listSize))) {
        DLP_LOG_ERROR(LABEL, "Write auth user num fail");
        return false;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = new (std::nothrow) AuthUserInfoParcel();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "Alloc auth user info parcel fail");
            return false;
        }
        authUserInfoParcel->authUserInfo_ = userList[i];
        if (!(out.WriteParcelable(authUserInfoParcel))) {
            DLP_LOG_ERROR(LABEL, "Write auth user info parcel fail");
            return false;
        }
    }
    return true;
}

bool DlpPolicyParcel::MarshallingAccountInfo(Parcel& out) const
{
    if (!(out.WriteString(this->policyParams_.ownerAccount_))) {
        DLP_LOG_ERROR(LABEL, "Write owner account fail");
        return false;
    }
    if (!(out.WriteString(this->policyParams_.ownerAccountId_))) {
        DLP_LOG_ERROR(LABEL, "Write owner accountId fail");
        return false;
    }
    if (!(out.WriteUint8(this->policyParams_.ownerAccountType_))) {
        DLP_LOG_ERROR(LABEL, "Write owner account type fail");
        return false;
    }
    if (!(out.WriteString(this->policyParams_.accountName_))) {
        DLP_LOG_ERROR(LABEL, "Write accountName fail");
        return false;
    }
    if (!(out.WriteString(this->policyParams_.acountId_))) {
        DLP_LOG_ERROR(LABEL, "Write accountId fail");
        return false;
    }
    if (!(out.WriteUint8(this->policyParams_.acountType_))) {
        DLP_LOG_ERROR(LABEL, "Write accountType fail");
        return false;
    }
    if (!(out.WriteString(this->policyParams_.customProperty_))) {
        DLP_LOG_ERROR(LABEL, "Write customProperty fail");
        return false;
    }
    return true;
}

bool DlpPolicyParcel::MarshallingKey(Parcel& out) const
{
    if (!(out.WriteUint32(this->policyParams_.GetAeskeyLen()))) {
        DLP_LOG_ERROR(LABEL, "Write aes key len fail");
        return false;
    }
    if (!(out.WriteBuffer(this->policyParams_.GetAeskey(), this->policyParams_.GetAeskeyLen()))) {
        DLP_LOG_ERROR(LABEL, "Write aes key fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.GetIvLen()))) {
        DLP_LOG_ERROR(LABEL, "Write iv len fail");
        return false;
    }
    if (!(out.WriteBuffer(this->policyParams_.GetIv(), this->policyParams_.GetIvLen()))) {
        DLP_LOG_ERROR(LABEL, "Write iv fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.GetHmacKeyLen()))) {
        DLP_LOG_ERROR(LABEL, "Write Hmac len fail");
        return false;
    }
    if (this->policyParams_.GetHmacKeyLen() > 0) {
        if (!(out.WriteBuffer(this->policyParams_.GetHmacKey(), this->policyParams_.GetHmacKeyLen()))) {
            DLP_LOG_ERROR(LABEL, "Write Hmac fail");
            return false;
        }
    }
    return true;
}

bool DlpPolicyParcel::MarshallingExpireTime(Parcel& out) const
{
    if (!(out.WriteUint64(this->policyParams_.expireTime_))) {
        DLP_LOG_ERROR(LABEL, "Write expireTime_ fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.actionUponExpiry_))) {
        DLP_LOG_ERROR(LABEL, "Write actionUponExpiry_ fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.needOnline_))) {
        DLP_LOG_ERROR(LABEL, "Write needOnline_ fail");
        return false;
    }
    return true;
}

static bool ReadKey(PermissionPolicy& policy, Parcel& in)
{
    uint32_t len;
    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "Read aes key len fail");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "Aes key len is invalid, len=%{public}u", len);
        return false;
    }
    const uint8_t* key = in.ReadUnpadBuffer(len);
    if (key == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read aes key fail");
        return false;
    }
    policy.SetAeskey(key, len);

    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "Read iv len fail");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "Iv len is invalid, len=%{public}u", len);
        return false;
    }
    const uint8_t* iv = in.ReadUnpadBuffer(len);
    if (iv == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read iv fail");
        return false;
    }
    policy.SetIv(iv, len);

    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "Read hmac key len fail");
        return false;
    }
    const uint8_t* hmacKey = nullptr;
    if (len > 0) {
        hmacKey = in.ReadUnpadBuffer(len);
        if (hmacKey == nullptr) {
            DLP_LOG_ERROR(LABEL, "Read hmacKey fail");
            return false;
        }
    }
    policy.SetHmacKey(hmacKey, len);
    return true;
}

static bool ReadAesParam(PermissionPolicy& policy, Parcel& in)
{
    if (!ReadKey(policy, in)) {
        return false;
    }

    if (!(in.ReadUint64(policy.expireTime_))) {
        DLP_LOG_ERROR(LABEL, "Read expiryTime_ fail");
        return false;
    }
    if (!(in.ReadUint32(policy.actionUponExpiry_))) {
        DLP_LOG_ERROR(LABEL, "Read actionUponExpiry_ fail");
        return false;
    }
    if (!(in.ReadUint32(policy.needOnline_))) {
        DLP_LOG_ERROR(LABEL, "Read needOnline_ fail");
        return false;
    }
    if (!(in.ReadUint32(policy.dlpVersion_))) {
        DLP_LOG_ERROR(LABEL, "Read dlpVersion_ fail");
        return false;
    }
    if (!(in.ReadBool(policy.debug_))) {
        DLP_LOG_ERROR(LABEL, "Read debug_ fail");
        return false;
    }
    return true;
}

static bool ReadAccountInfo(PermissionPolicy& policy, Parcel& in)
{
    if (!(in.ReadString(policy.ownerAccount_))) {
        DLP_LOG_ERROR(LABEL, "Read owner account fail");
        return false;
    }
    if (!(in.ReadString(policy.ownerAccountId_))) {
        DLP_LOG_ERROR(LABEL, "Read owner accountId fail");
        return false;
    }
    uint8_t res = 0;
    if (!(in.ReadUint8(res))) {
        DLP_LOG_ERROR(LABEL, "Read owner account type fail");
        return false;
    }
    policy.ownerAccountType_ = static_cast<DlpAccountType>(res);
    if (!(in.ReadString(policy.accountName_))) {
        DLP_LOG_ERROR(LABEL, "Read accountName fail");
        return false;
    }
    if (!(in.ReadString(policy.acountId_))) {
        DLP_LOG_ERROR(LABEL, "Read accountId fail");
        return false;
    }
    uint8_t type = 0;
    if (!(in.ReadUint8(type))) {
        DLP_LOG_ERROR(LABEL, "Read account type fail");
        return false;
    }
    if (!(in.ReadString(policy.customProperty_))) {
        DLP_LOG_ERROR(LABEL, "Read customProperty fail");
        return false;
    }
    policy.acountType_ = static_cast<DlpAccountType>(type);
    return true;
}

static bool ReadParcel(Parcel& in, DlpPolicyParcel* policyParcel)
{
    uint32_t listSize;
    if (!in.ReadUint32(listSize)) {
        DLP_LOG_ERROR(LABEL, "Read auth user num fail");
        return false;
    }
    if (listSize > MAX_ACCOUNT_NUM) {
        DLP_LOG_ERROR(LABEL, "Auth users number exceeds %{public}u, total=%{public}u", MAX_ACCOUNT_NUM, listSize);
        return false;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = in.ReadParcelable<AuthUserInfoParcel>();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "Read auth user info parcel fail");
            return false;
        }
        policyParcel->policyParams_.authUsers_.emplace_back(authUserInfoParcel->authUserInfo_);
    }
    if (!(in.ReadBool(policyParcel->policyParams_.supportEveryone_))) {
        DLP_LOG_ERROR(LABEL, "Read supportEveryone_ fail");
        return false;
    }
    uint8_t everyonePerm;
    if (!(in.ReadUint8(everyonePerm))) {
        DLP_LOG_ERROR(LABEL, "Read everyonePerm_ fail");
        return false;
    }
    policyParcel->policyParams_.everyonePerm_ = static_cast<DLPFileAccess>(everyonePerm);
    if (!ReadAccountInfo(policyParcel->policyParams_, in)) {
        DLP_LOG_ERROR(LABEL, "Read owner account info fail");
        return false;
    }
    uint8_t perm = 0;
    if (!(in.ReadUint8(perm))) {
        DLP_LOG_ERROR(LABEL, "Read owner account type fail");
        return false;
    }
    policyParcel->policyParams_.perm_ = static_cast<DLPFileAccess>(perm);
    return ReadAesParam(policyParcel->policyParams_, in);
}

DlpPolicyParcel* DlpPolicyParcel::Unmarshalling(Parcel& in)
{
    DlpPolicyParcel* policyParcel = new (std::nothrow) DlpPolicyParcel();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc policy parcel fail");
        return nullptr;
    }

    if (!ReadParcel(in, policyParcel)) {
        delete policyParcel;
        policyParcel = nullptr;
    }
    return policyParcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
