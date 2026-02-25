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

#include "dlp_file.h"

#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_public_interface.h"
#include "dlp_permission_log.h"
#include "dlp_zip.h"
#include "dlp_utils.h"
#include "hex_string.h"
#include "ohos_account_kits.h"
#ifdef DLP_PARSE_INNER
#include "os_account_manager.h"
#endif // DLP_PARSE_INNER
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Defer = std::shared_ptr<void>;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFile"};
const uint32_t FIRST = 1;
} // namespace

DlpFile::DlpFile(int32_t dlpFd, const std::string &realType)
    : dlpFd_(dlpFd), realType_(realType), isFuseLink_(false), authPerm_(DLPFileAccess::READ_ONLY)
{
    cert_.data = nullptr;
    cert_.size = 0;

    offlineCert_.data = nullptr;
    offlineCert_.size = 0;

    cipher_.tagIv.iv.data = nullptr;
    cipher_.tagIv.iv.size = 0;
    cipher_.encKey.data = nullptr;
    cipher_.encKey.size = 0;
    cipher_.usageSpec = { 0 };
    cipher_.hmacKey.data = nullptr;
    cipher_.hmacKey.size = 0;

    hmac_.data = nullptr;
    hmac_.size = 0;

    encDataFd_ = -1;
    offlineAccess_ = 0;
    version_ = CURRENT_VERSION;
    accountType_ = 0;
    fileIdPlaintext_ = "";
    allowedOpenCount_ = 0;
    waterMarkConfig_ = false;
    countdown_ = false;
}

DlpFile::~DlpFile() = default;

bool DlpFile::IsValidCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec,
    const struct DlpBlob& hmacKey) const
{
    if (key.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "key data null");
        return false;
    }

    if (key.size != DLP_KEY_LEN_128 && key.size != DLP_KEY_LEN_192 && key.size != DLP_KEY_LEN_256) {
        DLP_LOG_ERROR(LABEL, "key size invalid");
        return false;
    }

    if (spec.mode != DLP_MODE_CTR || spec.algParam == nullptr) {
        DLP_LOG_ERROR(LABEL, "spec invalid");
        return false;
    }

    struct DlpBlob& iv = spec.algParam->iv;
    if (iv.size != IV_SIZE || iv.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "iv invalid");
        return false;
    }

    if (hmacKey.data != nullptr && hmacKey.size != DLP_KEY_LEN_256) {
        DLP_LOG_ERROR(LABEL, "hmacKey size invalid");
        return false;
    }
    return true;
}

int32_t DlpFile::CopyBlobParam(const struct DlpBlob& src, struct DlpBlob& dst) const
{
    if (src.data == nullptr || src.size == 0 || src.size > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "src data null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint8_t* blobData = new (std::nothrow)uint8_t[src.size];
    if (blobData == nullptr) {
        DLP_LOG_ERROR(LABEL, "blobData null");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (memcpy_s(blobData, src.size, src.data, src.size) != EOK) {
        DLP_LOG_ERROR(LABEL, "memcpy_s error");
        delete[] blobData;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (dst.data != nullptr) {
        (void)memset_s(dst.data, dst.size, 0, dst.size);
        delete[] dst.data;
        dst.data = nullptr;
    }
    dst.data = blobData;
    dst.size = src.size;
    return DLP_OK;
}

int32_t DlpFile::CleanBlobParam(struct DlpBlob& blob) const
{
    if (blob.data == nullptr || blob.size == 0) {
        DLP_LOG_ERROR(LABEL, "blobData null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    (void)memset_s(blob.data, blob.size, 0, blob.size);
    delete[] blob.data;
    blob.data = nullptr;
    blob.size = 0;
    return DLP_OK;
}

int32_t DlpFile::GetLocalAccountName(std::string& account) const
{
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (accountInfo.first) {
        account = accountInfo.second.name_;
        return DLP_OK;
    }
    DLP_LOG_ERROR(LABEL, "QueryOhosAccountInfo accountInfo error");
    return DLP_PARSE_ERROR_ACCOUNT_INVALID;
}

int32_t DlpFile::GetDomainAccountName(std::string& account) const
{
#ifdef DLP_PARSE_INNER
    if (DLP_OK != DlpPermissionKit::GetDomainAccountNameInfo(account)) {
        DLP_LOG_ERROR(LABEL, "GetDomainAccountName error");
        return DLP_PARSE_ERROR_GET_ACCOUNT_FAIL;
    }
#endif
    return DLP_OK;
}

bool DlpFile::UpdateDlpFilePermission()
{
    if (!policy_.accountName_.empty()) {
        DLP_LOG_INFO(LABEL, "AccountName_ is not empty, perm is  %{public}d", policy_.perm_);
        authPerm_ = policy_.perm_;
        return true;
    }
    std::string accountName;
    if (policy_.ownerAccountType_ == ENTERPRISE_ACCOUNT) {
        if (policy_.authUsers_.size() < 1) {
            DLP_LOG_ERROR(LABEL, "enterprise account authUsers failed");
            return false;
        }
        authPerm_ = policy_.authUsers_[0].authPerm;
        return true;
    } else if (policy_.ownerAccountType_ == DOMAIN_ACCOUNT) {
        if (GetDomainAccountName(accountName) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "query GetDomainAccountName failed");
            return false;
        }
    } else {
        DLP_LOG_DEBUG(LABEL, "AuthPerm_ is readonly");
        authPerm_ = DLPFileAccess::READ_ONLY;
        return true;
    }

    if (accountName == policy_.ownerAccount_) {
        DLP_LOG_DEBUG(LABEL, "current account is owner, it has full permission");
        authPerm_ = DLPFileAccess::FULL_CONTROL;
        return true;
    }

    if (policy_.supportEveryone_) {
        DLP_LOG_DEBUG(LABEL, "everyone has perm permission %{public}d", policy_.everyonePerm_);
        authPerm_ = policy_.everyonePerm_;
    } else {
        DLP_LOG_DEBUG(LABEL, "everyone has not perm permission %{public}d", policy_.everyonePerm_);
    }

    for (int32_t i = 0; i < static_cast<int32_t>(policy_.authUsers_.size()); i++) {
        if (accountName == policy_.authUsers_[i].authAccount) {
            authPerm_ = policy_.authUsers_[i].authPerm;
            DLP_LOG_DEBUG(LABEL, "current account match authUsers list, authPerm_ %{public}d",
                authPerm_);
        }
    }
    return true;
}

int32_t DlpFile::SetCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec, const struct DlpBlob& hmacKey)
{
    if (!IsValidCipher(key, spec, hmacKey)) {
        DLP_LOG_ERROR(LABEL, "dlp file cipher is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    // copy iv from param.
    int32_t res = CopyBlobParam(spec.algParam->iv, cipher_.tagIv.iv);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file copy iv param failed, res %{public}d", res);
        return res;
    }

    // copy key from param.
    res = CopyBlobParam(key, cipher_.encKey);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file copy key param failed, res %{public}d", res);
        CleanBlobParam(cipher_.tagIv.iv);
        return res;
    }

    // copy hmacKey from param.
    if (hmacKey.data != nullptr) {
        res = CopyBlobParam(hmacKey, cipher_.hmacKey);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "dlp file copy hmacKey param failed, res %{public}d", res);
            CleanBlobParam(cipher_.tagIv.iv);
            CleanBlobParam(cipher_.encKey);
            return res;
        }
    }

    cipher_.usageSpec.mode = spec.mode;
    cipher_.usageSpec.algParam = &cipher_.tagIv;
    return DLP_OK;
}

int32_t DlpFile::SetPolicy(const PermissionPolicy& policy)
{
    if (!policy.IsValid()) {
        DLP_LOG_ERROR(LABEL, "invalid policy");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (policy.dlpVersion_ != 0) {
        version_ = policy.dlpVersion_;
    }
    policy_.CopyPermissionPolicy(policy);
    UpdateDlpFilePermission();
    return DLP_OK;
};

bool DlpFile::GetOfflineAccess()
{
    return !!offlineAccess_;
}

bool DlpFile::NeedAdapter()
{
    return version_ == FIRST && CURRENT_VERSION != FIRST;
}

void DlpFile::GetEncryptCert(struct DlpBlob& cert) const
{
    cert.data = cert_.data;
    cert.size = cert_.size;
}

void DlpFile::GetOfflineCert(struct DlpBlob& cert) const
{
    cert.data = offlineCert_.data;
    cert.size = offlineCert_.size;
}

int32_t DlpFile::PrepareBuff(struct DlpBlob& message1, struct DlpBlob& message2) const
{
    message1.size = DLP_BUFF_LEN;
    message1.data = new (std::nothrow) uint8_t[DLP_BUFF_LEN];
    if (message1.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "message1.data null");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    message2.size = DLP_BUFF_LEN;
    message2.data = new (std::nothrow) uint8_t[DLP_BUFF_LEN];
    if (message2.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "message2.data null");
        delete[] message1.data;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    (void)memset_s(message1.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    (void)memset_s(message2.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    return DLP_OK;
}

int32_t DlpFile::DupUsageSpec(struct DlpUsageSpec& spec)
{
    if (cipher_.usageSpec.algParam == nullptr ||
        cipher_.usageSpec.algParam->iv.data == nullptr ||
        cipher_.usageSpec.algParam->iv.size != IV_SIZE) {
        DLP_LOG_ERROR(LABEL, "chipher_ is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    spec.mode = cipher_.usageSpec.mode;
    spec.algParam = new (std::nothrow) struct DlpCipherParam;
    if (spec.algParam == nullptr) {
        DLP_LOG_ERROR(LABEL, "new alg param failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    spec.algParam->iv.data = new (std::nothrow) uint8_t[IV_SIZE]();
    if (spec.algParam->iv.data == nullptr) {
        delete spec.algParam;
        DLP_LOG_ERROR(LABEL, "new iv failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    spec.algParam->iv.size = cipher_.usageSpec.algParam->iv.size;
    if (memcpy_s(spec.algParam->iv.data, IV_SIZE,
        cipher_.usageSpec.algParam->iv.data, cipher_.usageSpec.algParam->iv.size) != EOK) {
        delete[] spec.algParam->iv.data;
        delete spec.algParam;
        DLP_LOG_ERROR(LABEL, "copy iv failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::DoDlpBlockCryptOperation(struct DlpBlob& message1, struct DlpBlob& message2,
    uint64_t offset, bool isEncrypt)
{
    if (offset % DLP_BLOCK_SIZE != 0 || message1.data == nullptr || message1.size == 0
        ||  message2.data == nullptr || message2.size == 0) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t counterIndex = offset / DLP_BLOCK_SIZE;
    struct DlpUsageSpec spec;
    if (DupUsageSpec(spec) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "spec dup failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    DlpCtrModeIncreaeIvCounter(spec.algParam->iv, counterIndex);
    int32_t ret = isEncrypt ? DlpOpensslAesEncrypt(&cipher_.encKey, &spec, &message1, &message2) :
        DlpOpensslAesDecrypt(&cipher_.encKey, &spec, &message1, &message2);
    delete[] spec.algParam->iv.data;
    delete spec.algParam;
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "do block crypt fail");
        return DLP_PARSE_ERROR_CRYPT_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::FillHoleData(uint64_t holeStart, uint64_t holeSize)
{
    DLP_LOG_INFO(LABEL, "Need create a hole filled with 0s, hole start %{public}s size %{public}s",
        std::to_string(holeStart).c_str(), std::to_string(holeSize).c_str());
    uint32_t holeBufSize = (holeSize < HOLE_BUFF_SMALL_SIZE) ? HOLE_BUFF_SMALL_SIZE : HOLE_BUFF_SIZE;
    std::unique_ptr<uint8_t[]> holeBuff(new (std::nothrow) uint8_t[holeBufSize]());
    if (holeBuff == nullptr) {
        DLP_LOG_ERROR(LABEL, "New buf failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    uint64_t fillLen = 0;
    while (fillLen < holeSize) {
        uint32_t writeSize = ((holeSize - fillLen) < holeBufSize) ? (holeSize - fillLen) : holeBufSize;
        int32_t res = DoDlpFileWrite(holeStart + fillLen, holeBuff.get(), writeSize);
        if (res < 0) {
            DLP_LOG_ERROR(LABEL, "Write failed, error %{public}d.", res);
            return res;
        }
        fillLen += writeSize;
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
