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
const uint32_t SECOND = 2;
const uint32_t HMAC_SIZE = 32;
const uint32_t HMAC_OFFSET = 68;
const uint32_t DLP_CWD_MAX = 256;
const std::string DLP_GENERAL_INFO = "dlp_general_info";
const std::string DLP_CERT = "dlp_cert";
const std::string DLP_ENC_DATA = "encrypted_data";
const std::string DLP_OPENING_ENC_DATA = "opened_encrypted_data";
const std::string DLP_GEN_FILE = "gen_dlp_file";
const std::string DEFAULT_STRINGS = "";
} // namespace
std::mutex g_fileOpLock_;

static int32_t GetFileSize(int32_t fd, uint64_t& fileLen);

DlpFile::DlpFile(int32_t dlpFd, const std::string &workDir, int64_t index, bool isZip, const std::string &realType)
    : dlpFd_(dlpFd), workDir_(workDir), dirIndex_(std::to_string(index)), realType_(realType), isZip_(isZip),
    isFuseLink_(false), authPerm_(DLPFileAccess::READ_ONLY)
{
    head_.magic = DLP_FILE_MAGIC;
    head_.version = CURRENT_VERSION;
    head_.offlineAccess = 0;
    head_.txtOffset = INVALID_FILE_SIZE;
    head_.txtSize = INVALID_FILE_SIZE;
    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = 0;
    head_.contactAccountOffset = 0;
    head_.contactAccountSize = 0;
    head_.offlineCertOffset = 0;
    head_.offlineCertSize = 0;

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
}

DlpFile::~DlpFile()
{
    // clear key
    if (cipher_.encKey.data != nullptr) {
        (void)memset_s(cipher_.encKey.data, cipher_.encKey.size, 0, cipher_.encKey.size);
        delete[] cipher_.encKey.data;
        cipher_.encKey.data = nullptr;
    }

    // clear iv
    if (cipher_.tagIv.iv.data != nullptr) {
        (void)memset_s(cipher_.tagIv.iv.data, cipher_.tagIv.iv.size, 0, cipher_.tagIv.iv.size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
    }

    // clear encrypt cert
    if (cert_.data != nullptr) {
        (void)memset_s(cert_.data, head_.certSize, 0, head_.certSize);
        delete[] cert_.data;
        cert_.data = nullptr;
    }

    if (offlineCert_.data != nullptr) {
        (void)memset_s(offlineCert_.data, head_.offlineCertSize, 0, head_.offlineCertSize);
        delete[] offlineCert_.data;
        offlineCert_.data = nullptr;
    }

    // clear hmacKey
    if (cipher_.hmacKey.data != nullptr) {
        (void)memset_s(cipher_.hmacKey.data, cipher_.hmacKey.size, 0, cipher_.hmacKey.size);
        delete[] cipher_.hmacKey.data;
        cipher_.hmacKey.data = nullptr;
    }

    // clear hmac_
    if (hmac_.data != nullptr) {
        (void)memset_s(hmac_.data, hmac_.size, 0, hmac_.size);
        delete[] hmac_.data;
        hmac_.data = nullptr;
    }

    CleanTmpFile();
}

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
    AccountSA::OsAccountInfo osAccountInfo;
    if (OHOS::AccountSA::OsAccountManager::QueryCurrentOsAccount(osAccountInfo) != 0) {
        DLP_LOG_ERROR(LABEL, "QueryCurrentOsAccount return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    AccountSA::DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        DLP_LOG_ERROR(LABEL, "accountName_ empty");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    account = domainInfo.accountName_;
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
    if (policy_.ownerAccountType_ == DOMAIN_ACCOUNT) {
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

int32_t DlpFile::SetContactAccount(const std::string& contactAccount)
{
    if (contactAccount.size() == 0 || contactAccount.size() > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "contactAccount param failed");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    contactAccount_ = contactAccount;
    if (head_.certSize != 0) {
        head_.contactAccountSize = static_cast<uint32_t>(contactAccount.size());
        head_.txtOffset = head_.contactAccountOffset + head_.contactAccountSize;
    }
    return DLP_OK;
};

int32_t DlpFile::SetPolicy(const PermissionPolicy& policy)
{
    if (!policy.IsValid()) {
        DLP_LOG_ERROR(LABEL, "invalid policy");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (policy.dlpVersion_ != 0) {
        head_.version = policy.dlpVersion_;
    }
    policy_.CopyPermissionPolicy(policy);
    UpdateDlpFilePermission();
    return DLP_OK;
};

void DlpFile::SetOfflineAccess(bool flag)
{
    head_.offlineAccess = static_cast<uint32_t>(flag);
}

bool DlpFile::GetOfflineAccess()
{
    return !!head_.offlineAccess;
}

bool DlpFile::IsValidDlpHeader(const struct DlpHeader& head) const
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountOffset != sizeof(struct DlpHeader) ||
        head.txtOffset != (sizeof(struct DlpHeader) + head.contactAccountSize) ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.offlineCertSize > DLP_MAX_CERT_SIZE ||
        !(head.certOffset == head.txtOffset || head.certOffset == head.txtOffset + head.txtSize + HMAC_OFFSET)) {
        DLP_LOG_ERROR(LABEL, "IsValidDlpHeader error");
        return false;
    }
    return true;
}

int32_t DlpFile::CheckDlpFile()
{
    if (dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }

    if (IsZipFile(dlpFd_)) {
        return DLP_OK;
    }
    if (lseek(dlpFd_, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    uint64_t fileLen = 0;
    int32_t ret = GetFileSize(dlpFd_, fileLen);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    if (fileLen <= sizeof(struct DlpHeader) || fileLen >= DLP_MAX_RAW_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "dlp file error");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (read(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file head, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (!IsValidDlpHeader(head_)) {
        DLP_LOG_ERROR(LABEL, "parse dlp file header error.");
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_PARSE_ERROR_FILE_NOT_DLP;
    }
    if (head_.txtSize == 0) {
        if (fileLen < head_.txtOffset + head_.txtSize + head_.certSize) {
            DLP_LOG_ERROR(LABEL, "dlp file head is error");
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
    } else if (fileLen < head_.txtOffset + head_.txtSize + head_.certSize + HMAC_OFFSET) {
        DLP_LOG_ERROR(LABEL, "dlp file head is error");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (head_.version > CURRENT_VERSION) {
        DLP_LOG_ERROR(LABEL, "head_.version > CURRENT_VERSION can not open");
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_PARSE_ERROR_FILE_VERSION_BIGGER_THAN_CURRENT;
    }
    return DLP_OK;
}

bool DlpFile::NeedAdapter()
{
    return head_.version == FIRST && CURRENT_VERSION != FIRST;
}

uint32_t DlpFile::GetOfflineCertSize(void)
{
    return head_.offlineCertSize;
}

static bool IsExistFile(const std::string& path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISREG(buf.st_mode);
}

static int32_t GetFileContent(const std::string& path, std::string& content)
{
    if (!IsExistFile(path)) {
        DLP_LOG_INFO(LABEL, "cannot find file, path = %{public}s", path.c_str());
        return DLP_RETENTION_FILE_FIND_FILE_ERROR;
    }
    std::stringstream buffer;
    std::ifstream i(path);
    if (!i.is_open()) {
        DLP_LOG_INFO(LABEL, "cannot open file %{public}s, errno %{public}d.", path.c_str(), errno);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    buffer << i.rdbuf();
    content = buffer.str();
    i.close();
    return DLP_OK;
}

bool DlpFile::ParseDlpInfo()
{
    std::string content;
    (void)GetFileContent(DLP_GENERAL_INFO, content);
    GenerateInfoParams params;
    int32_t res = ParseDlpGeneralInfo(content, params);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "ParseDlpGeneralInfo %{public}s", content.c_str());
        return false;
    }
    head_.version = params.version;
    head_.offlineAccess = params.offlineAccessFlag;
    extraInfo_ = params.extraInfo;
    contactAccount_ = params.contactAccount;
    if (!params.hmacVal.empty()) {
        hmac_.size = params.hmacVal.size() / BYTE_TO_HEX_OPER_LENGTH;
        if (hmac_.size > HMAC_SIZE) {
            DLP_LOG_ERROR(LABEL, "hmac_.size is invalid");
            return false;
        }
        CleanBlobParam(hmac_);
        hmac_.data = new (std::nothrow)uint8_t[hmac_.size];
        if (hmac_.data == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return false;
        }
        return HexStringToByte(params.hmacVal.c_str(), params.hmacVal.length(), hmac_.data, hmac_.size) == DLP_OK;
    }
    return true;
}

bool DlpFile::ParseCert()
{
    struct stat fz;
    if (stat(DLP_CERT.c_str(), &fz) != 0) {
        DLP_LOG_ERROR(LABEL, "ParseCert failed, %{public}s", strerror(errno));
        return false;
    }
    CleanBlobParam(cert_);
    if (fz.st_size == 0 || fz.st_size > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert size is too large or equit to 0.");
        return false;
    }
    cert_.data = new (std::nothrow) uint8_t[fz.st_size];
    if (cert_.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "new failed");
        return false;
    }
    cert_.size = static_cast<uint32_t>(fz.st_size);
    int32_t fd = open(DLP_CERT.c_str(), O_RDONLY);
    if (fd == -1) {
        DLP_LOG_ERROR(LABEL, "open failed, %{public}s", strerror(errno));
        return false;
    }

    uint32_t size = static_cast<uint32_t>(read(fd, cert_.data, cert_.size));
    (void)close(fd);
    fd = -1;
    if (size != cert_.size) {
        DLP_LOG_ERROR(LABEL, "read failed, %{public}s", strerror(errno));
        return false;
    }
    return true;
}

bool DlpFile::ParseEncData()
{
    int32_t fd = open(DLP_OPENING_ENC_DATA.c_str(), O_RDWR);
    if (fd == -1) {
        DLP_LOG_ERROR(LABEL, "ParseEncData failed, %{public}s", strerror(errno));
        return false;
    }
    encDataFd_ = fd;
    return true;
}

bool DlpFile::CleanTmpFile()
{
    if (!isZip_) {
        return true;
    }

    close(encDataFd_);
    encDataFd_ = -1;
    std::lock_guard<std::mutex> lock(g_fileOpLock_);
    char cwd[DLP_CWD_MAX] = {0};
    GETCWD_AND_CHECK(cwd, DLP_CWD_MAX, false, LABEL);
    Defer p(nullptr, [&](...) {
        if (chdir(cwd) != 0) {
            DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
        }
    });

    if (chdir(workDir_.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
        return false;
    }

    if (chdir(dirIndex_.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
    }

    if (unlink(DLP_GENERAL_INFO.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "unlink failed, %{public}s errno %{public}s", DLP_GENERAL_INFO.c_str(), strerror(errno));
    }

    if (unlink(DLP_CERT.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "unlink failed, %{public}s errno %{public}s", DLP_CERT.c_str(), strerror(errno));
    }

    if (unlink(DLP_OPENING_ENC_DATA.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "unlink failed, %{public}s errno %{public}s",
            DLP_OPENING_ENC_DATA.c_str(), strerror(errno));
    }

    if (chdir(workDir_.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "chdir failed, errno %{public}s", strerror(errno));
    }

    if (rmdir(dirIndex_.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "rmdir failed, %{public}s errno %{public}s", dirIndex_.c_str(), strerror(errno));
    }

    if (rmdir(workDir_.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "rmdir failed, %{public}s errno %{public}s", workDir_.c_str(), strerror(errno));
    }

    return true;
}

int32_t DlpFile::UnzipDlpFile()
{
    std::lock_guard<std::mutex> lock(g_fileOpLock_);
    isZip_ = true;
    head_.txtOffset = 0;
    char cwd[DLP_CWD_MAX] = {0};
    GETCWD_AND_CHECK(cwd, DLP_CWD_MAX, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    Defer p(nullptr, [&](...) {
        if (chdir(cwd) != 0) {
            DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
        }
    });

    CHDIR_AND_CHECK(workDir_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    MKDIR_AND_CHECK(dirIndex_.c_str(), S_IRWXU, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    CHDIR_AND_CHECK(dirIndex_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    if (!CheckUnzipFileInfo(dlpFd_)) {
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    UnzipSpecificFile(dlpFd_, DLP_GENERAL_INFO.c_str(), DLP_GENERAL_INFO.c_str());
    if (!ParseDlpInfo()) {
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    UnzipSpecificFile(dlpFd_, DLP_CERT.c_str(), DLP_CERT.c_str());
    if (!ParseCert()) {
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    UnzipSpecificFile(dlpFd_, DLP_ENC_DATA.c_str(), DLP_OPENING_ENC_DATA.c_str());
    if (!ParseEncData()) {
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    return DLP_OK;
}

int32_t DlpFile::GetDlpHmacAndGenFile(void)
{
    if (head_.txtSize == 0) {
        CleanBlobParam(hmac_);
        return DLP_OK;
    }
    uint32_t hmacStrLen = 0;
    (void)lseek(dlpFd_, head_.txtSize + head_.txtOffset, SEEK_SET);
    if (read(dlpFd_, &hmacStrLen, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read hmacStrLen, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (hmacStrLen != HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH) {
        DLP_LOG_ERROR(LABEL, "the hmac size is error: %{public}d", hmacStrLen);
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    uint8_t *tempBufHmacStr = new (std::nothrow) uint8_t[hmacStrLen + 1];
    if (tempBufHmacStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "new tempBuf failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)memset_s(tempBufHmacStr, hmacStrLen + 1, 0, hmacStrLen + 1);
    if (read(dlpFd_, tempBufHmacStr, hmacStrLen) != (ssize_t)hmacStrLen) {
        DLP_LOG_ERROR(LABEL, "can not read tempBufHmacStr, %{public}s", strerror(errno));
        delete[] tempBufHmacStr;
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    CleanBlobParam(hmac_);
    hmac_.size = hmacStrLen / BYTE_TO_HEX_OPER_LENGTH;
    hmac_.data = new (std::nothrow) uint8_t[hmac_.size];
    if (hmac_.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "new hmac size failed");
        delete[] tempBufHmacStr;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (HexStringToByte((char *)tempBufHmacStr, hmacStrLen, hmac_.data, hmac_.size) != DLP_OK) {
        delete[] tempBufHmacStr;
        DLP_LOG_ERROR(LABEL, "HexStringToByte failed");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    delete[] tempBufHmacStr;
    return DLP_OK;
}

int32_t DlpFile::ParseDlpHeaderInRaw()
{
    int32_t ret = CheckDlpFile();
    if (ret != DLP_OK) {
        return ret;
    }
    uint8_t* buf = new (std::nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc buffer failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)lseek(dlpFd_, head_.certOffset, SEEK_SET);
    if (read(dlpFd_, buf, head_.certSize) != (ssize_t)head_.certSize) {
        delete[] buf;
        DLP_LOG_ERROR(LABEL, "can not read dlp file cert, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    CleanBlobParam(cert_);
    cert_.data = buf;
    cert_.size = head_.certSize;
    uint8_t *tmpBuf = new (std::nothrow)uint8_t[head_.contactAccountSize];
    if (tmpBuf == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc tmpBuf failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)lseek(dlpFd_, head_.contactAccountOffset, SEEK_SET);
    if (read(dlpFd_, tmpBuf, head_.contactAccountSize) != (ssize_t)head_.contactAccountSize) {
        delete[] tmpBuf;
        DLP_LOG_ERROR(LABEL, "can not read dlp contact account, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    contactAccount_ = std::string(tmpBuf, tmpBuf + head_.contactAccountSize);
    delete[] tmpBuf;
    if (head_.offlineCertSize != 0) {
        tmpBuf = new (std::nothrow)uint8_t[head_.offlineCertSize];
        if (tmpBuf == nullptr) {
            DLP_LOG_WARN(LABEL, "alloc tmpBuf failed.");
            return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
        }
        (void)lseek(dlpFd_, head_.offlineCertOffset, SEEK_SET);
        if (read(dlpFd_, tmpBuf, head_.offlineCertSize) != (ssize_t)head_.offlineCertSize) {
            delete[] tmpBuf;
            DLP_LOG_ERROR(LABEL, "can not read dlp offlineCert, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
        CleanBlobParam(offlineCert_);
        offlineCert_.data = tmpBuf;
        offlineCert_.size = head_.offlineCertSize;
    }
    return GetDlpHmacAndGenFile();
}

int32_t DlpFile::ParseDlpHeader()
{
    if (IsZipFile(dlpFd_)) {
        return UnzipDlpFile();
    } else {
        return ParseDlpHeaderInRaw();
    }
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

int32_t DlpFile::SetEncryptCert(const struct DlpBlob& cert)
{
    if (cert.data == nullptr || cert.size > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert data invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (cert_.data != nullptr) {
        delete[] cert_.data;
        cert_.data = nullptr;
    }

    if (CopyBlobParam(cert, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    head_.contactAccountOffset = sizeof(struct DlpHeader);
    head_.certSize = cert_.size;
    return DLP_OK;
}

int32_t DlpFile::UpdateCertAndText(const std::vector<uint8_t>& cert, const std::string& workDir,
    struct DlpBlob certBlob)
{
    if (CopyBlobParam(certBlob, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (isZip_) {
        return GenFileInZip(-1);
    }
    // version 1 single file auto convert to version 2 zip file, set version
    head_.version = SECOND;
    head_.offlineCertSize = cert.size();
    head_.certSize = cert.size();

    (void)lseek(dlpFd_, 0, SEEK_SET);
    if (write(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "write dlp head_ data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    (void)lseek(dlpFd_, head_.offlineCertOffset, SEEK_SET);
    if (write(dlpFd_, certBlob.data, certBlob.size) != (ssize_t)head_.offlineCertSize) {
        DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
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

int32_t DlpFile::DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
    uint64_t inFileLen, bool isEncrypt)
{
    struct DlpBlob message;
    struct DlpBlob outMessage;
    if (PrepareBuff(message, outMessage) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "prepare buff failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    uint64_t dlpContentOffset = inOffset;
    int32_t ret = DLP_OK;
    while (inOffset < inFileLen) {
        uint32_t readLen = ((inFileLen - inOffset) < DLP_BUFF_LEN) ? (inFileLen - inOffset) : DLP_BUFF_LEN;
        (void)memset_s(message.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
        (void)memset_s(outMessage.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
        if (read(inFd, message.data, readLen) != (ssize_t)readLen) {
            DLP_LOG_ERROR(LABEL, "Read size do not equal readLen");
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }

        message.size = readLen;
        outMessage.size = readLen;
        // Implicit condition: DLP_BUFF_LEN must be DLP_BLOCK_SIZE aligned
        ret = DoDlpBlockCryptOperation(message, outMessage, inOffset - dlpContentOffset, isEncrypt);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "do crypt operation fail");
            break;
        }

        if (write(outFd, outMessage.data, readLen) != (ssize_t)readLen) {
            DLP_LOG_ERROR(LABEL, "write fd failed, %{public}s", strerror(errno));
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }
        inOffset += readLen;
    }

    delete[] message.data;
    delete[] outMessage.data;
    return ret;
}

int32_t DlpFile::DoDlpContentCopyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset, uint64_t inFileLen)
{
    if (inOffset > inFileLen) {
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    uint8_t *data = new (std::nothrow) uint8_t[DLP_BUFF_LEN];
    if (data == nullptr) {
        DLP_LOG_ERROR(LABEL, "prepare buff failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t ret = DLP_OK;
    while (inOffset < inFileLen) {
        uint32_t readLen = ((inFileLen - inOffset) < DLP_BUFF_LEN) ? (inFileLen - inOffset) : DLP_BUFF_LEN;
        (void)memset_s(data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);

        if (read(inFd, data, readLen) != (ssize_t)readLen) {
            DLP_LOG_ERROR(LABEL, "Read size do not equal readLen");
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }

        if (write(outFd, data, readLen) != (ssize_t)readLen) {
            DLP_LOG_ERROR(LABEL, "write fd failed, %{public}s", strerror(errno));
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }
        inOffset += readLen;
    }
    delete[] data;
    return ret;
}

static int32_t GetFileSize(int32_t fd, uint64_t& fileLen)
{
    int32_t ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    off_t readLen = lseek(fd, 0, SEEK_END);
    if (readLen == static_cast<off_t>(-1) || static_cast<uint64_t>(readLen) > UINT32_MAX) {
        DLP_LOG_ERROR(LABEL, "get file size failed, %{public}s", strerror(errno));
    } else {
        fileLen = static_cast<uint64_t>(readLen);
        ret = DLP_OK;
    }
    (void)lseek(fd, 0, SEEK_SET);
    return ret;
}

static std::string SetDlpGeneralInfo(bool accessFlag, std::string& contactAccount, const std::string& hmacStr,
    const uint32_t& version, const std::string& realType)
{
    GenerateInfoParams params = {
        .version = version,
        .offlineAccessFlag = accessFlag,
        .contactAccount = contactAccount,
        .extraInfo = {"kia_info", "cert_info", "enc_data"},
        .hmacVal = hmacStr,
        .realType = realType,
    };
    std::string out;
    GenerateDlpGeneralInfo(params, out);
    return out;
}

int32_t DlpFile::GenEncData(int32_t inPlainFileFd)
{
    int32_t encFile = -1;
    if (inPlainFileFd == -1) {
        encFile = open(DLP_OPENING_ENC_DATA.c_str(), O_RDWR);
    } else {
        uint64_t fileLen = 0;
        int32_t ret = GetFileSize(inPlainFileFd, fileLen);
        CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

        OPEN_AND_CHECK(encFile, DLP_OPENING_ENC_DATA.c_str(), O_RDWR | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
        encDataFd_ = encFile;
        ret = DoDlpContentCryptyOperation(inPlainFileFd, encFile, 0, fileLen, true);
        CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
        LSEEK_AND_CHECK(encFile, 0, SEEK_SET, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    }
    return encFile;
}

int32_t DlpFile::GenerateHmacVal(int32_t encFile, struct DlpBlob& out)
{
    lseek(encFile, 0, SEEK_SET);
    int32_t fd = dup(encFile);
    uint64_t fileLen = 0;

    int32_t ret = GetFileSize(fd, fileLen);
    if (ret != DLP_OK) {
        (void)close(fd);
        DLP_LOG_ERROR(LABEL, "failed to get fileLen");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (fileLen == 0) {
        (void)close(fd);
        CleanBlobParam(out);
        return DLP_OK;
    }

    ret = DlpHmacEncode(cipher_.hmacKey, fd, out);
    (void)close(fd);
    return ret;
}

int32_t DlpFile::GetHmacVal(int32_t encFile, std::string& hmacStr)
{
    if (head_.version < HMAC_VERSION) {
        return DLP_OK;
    }
    if (hmac_.size == 0) {
        uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
        if (outBuf == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
        }
        struct DlpBlob out = {
            .size = HMAC_SIZE,
            .data = outBuf,
        };
        int ret = GenerateHmacVal(encFile, out);
        if (ret != DLP_OK) {
            CleanBlobParam(out);
            return ret;
        }
        if (out.size == 0) {
            return DLP_OK;
        }
        hmac_.size = out.size;
        hmac_.data = out.data;
    }
    uint32_t hmacHexLen = hmac_.size * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* hmacHex = new (std::nothrow) char[hmacHexLen];
    if (hmacHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int ret = ByteToHexString(hmac_.data, hmac_.size, hmacHex, hmacHexLen);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(hmacHex, hmacHexLen);
        return ret;
    }
    hmacStr = hmacHex;
    FreeCharBuffer(hmacHex, hmacHexLen);
    return DLP_OK;
}

int32_t DlpFile::AddGeneralInfoToBuff(int32_t encFile)
{
    std::string hmacStr;
    int ret = GetHmacVal(encFile, hmacStr);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetHmacVal fail");
        return ret;
    }
    std::string ja = SetDlpGeneralInfo(head_.offlineAccess, contactAccount_, hmacStr, head_.version, realType_);
    ret = AddBuffToZip(reinterpret_cast<const void *>(ja.c_str()), ja.size(),
        DLP_GENERAL_INFO.c_str(), DLP_GEN_FILE.c_str());
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    return DLP_OK;
}

int32_t DlpFile::GenFileInZip(int32_t inPlainFileFd)
{
    if (isZip_ == false) {
        return DLP_OK;
    }
    char cwd[DLP_CWD_MAX] = {0};
    std::lock_guard<std::mutex> lock(g_fileOpLock_);
    GETCWD_AND_CHECK(cwd, DLP_CWD_MAX, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    Defer p(nullptr, [&](...) {
        (void)chdir(cwd);
    });
    CHDIR_AND_CHECK(workDir_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    if (inPlainFileFd != -1) {
        MKDIR_AND_CHECK(dirIndex_.c_str(), S_IRWXU, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    }
    CHDIR_AND_CHECK(dirIndex_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    int32_t tmpFile;
    OPEN_AND_CHECK(tmpFile, DLP_GEN_FILE.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR,
        DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    Defer p2(nullptr, [&](...) {
        (void)close(tmpFile);
        (void)unlink(DLP_GEN_FILE.c_str());
    });
    int32_t ret = AddBuffToZip(reinterpret_cast<const void *>(cert_.data), cert_.size,
        DLP_CERT.c_str(), DLP_GEN_FILE.c_str());
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    int32_t encFile = GenEncData(inPlainFileFd);
    Defer p3(nullptr, [&](...) {
        if (inPlainFileFd == -1) {
            (void)close(encFile);
        }
    });

    ret = AddFileContextToZip(encFile, DLP_ENC_DATA.c_str(), DLP_GEN_FILE.c_str());
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    ret = AddGeneralInfoToBuff(encFile);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    uint64_t zipSize = 0;
    ret = GetFileSize(tmpFile, zipSize);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    LSEEK_AND_CHECK(dlpFd_, 0, SEEK_SET, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    ret = DoDlpContentCopyOperation(tmpFile, dlpFd_, 0, zipSize);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    FTRUNCATE_AND_CHECK(dlpFd_, zipSize, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    (void)fsync(dlpFd_);
    return DLP_OK;
}

int32_t DlpFile::DoWriteHmacAndCert(uint32_t hmacStrLen, std::string& hmacStr)
{
    if (write(dlpFd_, &hmacStrLen, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "write hmacStrLen failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, hmacStr.c_str(), hmacStrLen) != static_cast<int32_t>(hmacStrLen)) {
        DLP_LOG_ERROR(LABEL, "write hmacStr failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, cert_.data, head_.certSize) != (ssize_t)head_.certSize) {
        DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::DoHmacAndCrypty(int32_t inPlainFileFd, off_t fileLen)
{
    if (DoDlpContentCryptyOperation(inPlainFileFd, dlpFd_, 0, fileLen, true) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DoDlpContentCryptyOperation error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    (void)lseek(dlpFd_, head_.txtOffset, SEEK_SET);
    DLP_LOG_DEBUG(LABEL, "begin DlpHmacEncode");
    uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
    if (outBuf == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    struct DlpBlob out = {
        .size = HMAC_SIZE,
        .data = outBuf,
    };
    int32_t ret = DlpHmacEncode(cipher_.hmacKey, dlpFd_, out);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DlpHmacEncode fail: %{public}d", ret);
        CleanBlobParam(out);
        return ret;
    }
    hmac_.size = out.size;
    hmac_.data = out.data;
    uint32_t hmacHexLen = hmac_.size * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* hmacHex = new (std::nothrow) char[hmacHexLen];
    if (hmacHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    ret = ByteToHexString(hmac_.data, hmac_.size, hmacHex, hmacHexLen);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "ByteToHexString error");
        FreeCharBuffer(hmacHex, hmacHexLen);
        return ret;
    }
    std::string hmacStr = hmacHex;
    FreeCharBuffer(hmacHex, hmacHexLen);
    uint32_t hmacStrLen = hmacStr.size();
    (void)lseek(dlpFd_, head_.txtOffset + fileLen, SEEK_SET);
    return DoWriteHmacAndCert(hmacStrLen, hmacStr);
}

int32_t DlpFile::GenFileInRaw(int32_t inPlainFileFd)
{
    off_t fileLen = lseek(inPlainFileFd, 0, SEEK_END);
    head_.txtSize = static_cast<uint64_t>(fileLen);
    if (fileLen == 0) {
        head_.certOffset = head_.txtOffset + head_.txtSize;
        head_.offlineCertOffset = head_.txtOffset + head_.txtSize;
    } else {
        head_.certOffset = head_.txtOffset + head_.txtSize + HMAC_OFFSET;
        head_.offlineCertOffset = head_.txtOffset + head_.txtSize + HMAC_OFFSET;
    }
    DLP_LOG_DEBUG(LABEL, "fileLen %{public}s", std::to_string(head_.txtSize).c_str());

    // clean dlpFile
    if (ftruncate(dlpFd_, 0) == -1) {
        DLP_LOG_ERROR(LABEL, "truncate dlp file to zero failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(inPlainFileFd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek plain file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(dlpFd_, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "write dlp head failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, contactAccount_.c_str(), contactAccount_.size()) !=
        static_cast<int32_t>(contactAccount_.size())) {
        DLP_LOG_ERROR(LABEL, "write dlp contact data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (fileLen == 0) {
        DLP_LOG_INFO(LABEL, "Plaintext file len is 0, do not need encrypt");
        if (write(dlpFd_, cert_.data, head_.certSize) != (ssize_t)head_.certSize) {
            DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        return DLP_OK;
    }
    DLP_LOG_DEBUG(LABEL, "begin DoHmacAndCrypty");
    return DoHmacAndCrypty(inPlainFileFd, fileLen);
}

int32_t DlpFile::GenFile(int32_t inPlainFileFd)
{
    if (inPlainFileFd < 0 || dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    off_t fileLen = lseek(inPlainFileFd, 0, SEEK_END);
    if (fileLen == static_cast<off_t>(-1) || fileLen > static_cast<off_t>(DLP_MAX_CONTENT_SIZE)) {
        DLP_LOG_ERROR(LABEL, "inFd len is invalid, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (lseek(inPlainFileFd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek inFd start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (isZip_) {
        head_.txtOffset = 0;
        if (hmac_.size != 0) {
            CleanBlobParam(hmac_);
        }
        return GenFileInZip(inPlainFileFd);
    } else {
        return GenFileInRaw(inPlainFileFd);
    }
}

int32_t DlpFile::RemoveDlpPermissionInZip(int32_t outPlainFileFd)
{
    std::lock_guard<std::mutex> lock(g_fileOpLock_);
    char cwd[DLP_CWD_MAX] = {0};
    GETCWD_AND_CHECK(cwd, DLP_CWD_MAX, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    Defer p(nullptr, [&](...) {
        if (chdir(cwd) != 0) {
            DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
        }
    });

    CHDIR_AND_CHECK(workDir_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    CHDIR_AND_CHECK(dirIndex_.c_str(), DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    int32_t encFd = open(DLP_OPENING_ENC_DATA.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    Defer p2(nullptr, [&](...) {
        if (close(encFd) != 0) {
            DLP_LOG_ERROR(LABEL, "close failed, %{public}s", strerror(errno));
        }
    });

    uint64_t fileSize = 0;
    int32_t ret = GetFileSize(encFd, fileSize);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    ret = DoDlpContentCryptyOperation(encFd, outPlainFileFd, 0, fileSize, false);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    return DLP_OK;
}

int32_t DlpFile::RemoveDlpPermissionInRaw(int32_t outPlainFileFd)
{
    off_t fileLen = lseek(dlpFd_, 0, SEEK_END);
    if (fileLen == static_cast<off_t>(-1) || fileLen > static_cast<off_t>(DLP_MAX_CONTENT_SIZE)) {
        DLP_LOG_ERROR(LABEL, "can not get dlp file len, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    // clean plainTxtFile
    if (ftruncate(outPlainFileFd, 0) == -1) {
        DLP_LOG_ERROR(LABEL, "truncate plain file to zero failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(outPlainFileFd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek plain file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(dlpFd_, head_.txtOffset, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (fileLen == static_cast<off_t>(head_.txtOffset)) {
        DLP_LOG_INFO(LABEL, "Dlp file have no content");
        return DLP_OK;
    }

    return DoDlpContentCryptyOperation(dlpFd_, outPlainFileFd, head_.txtOffset, fileLen, false);
}

int32_t DlpFile::RemoveDlpPermission(int32_t outPlainFileFd)
{
    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }

    if (authPerm_ != DLPFileAccess::FULL_CONTROL) {
        DLP_LOG_ERROR(LABEL, "check permission fail, remove dlp permission failed.");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }

    if (outPlainFileFd < 0 || dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (!IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "cipher params is invalid");
        return DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID;
    }

    if (isZip_) {
        return RemoveDlpPermissionInZip(outPlainFileFd);
    } else {
        return RemoveDlpPermissionInRaw(outPlainFileFd);
    }
}

int32_t DlpFile::DlpFileRead(uint32_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid)
{
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        (offset >= DLP_MAX_CONTENT_SIZE - size) ||
        opFd < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset - alignOffset;
    uint32_t alignSize = size + prefixingSize;

    if (lseek(opFd, head_.txtOffset + alignOffset, SEEK_SET) == -1) {
        DLP_LOG_ERROR(LABEL, "lseek dlp file failed. %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    auto encBuff = std::make_unique<uint8_t[]>(alignSize);
    auto outBuff = std::make_unique<uint8_t[]>(alignSize);

    int32_t readLen = read(opFd, encBuff.get(), alignSize);
    if (readLen == -1) {
        DLP_LOG_ERROR(LABEL, "read buff fail, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (readLen <= static_cast<int32_t>(prefixingSize)) {
        return 0;
    }

    struct DlpBlob message1 = {.size = readLen, .data = encBuff.get()};
    struct DlpBlob message2 = {.size = readLen, .data = outBuff.get()};
    if (DoDlpBlockCryptOperation(message1, message2, alignOffset, false) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "decrypt fail");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (memcpy_s(buf, size, outBuff.get() + prefixingSize, message2.size - prefixingSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "copy decrypt result failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (hasRead) {
        return message2.size - prefixingSize;
    }
    int32_t res = DlpPermissionKit::SetReadFlag(uid);
    if (res != DLP_OK) {
        return res;
    }
    hasRead = true;
    return message2.size - prefixingSize;
}

int32_t DlpFile::WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size)
{
    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset % DLP_BLOCK_SIZE;
    uint32_t requestSize = (size < (DLP_BLOCK_SIZE - prefixingSize)) ? size : (DLP_BLOCK_SIZE - prefixingSize);
    uint32_t writtenSize = prefixingSize + requestSize;
    uint8_t enBuf[DLP_BLOCK_SIZE] = {0};
    uint8_t deBuf[DLP_BLOCK_SIZE] = {0};
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;

    do {
        if (prefixingSize == 0) {
            break;
        }
        int32_t readLen = read(opFd, enBuf, prefixingSize);
        if (readLen == -1) {
            DLP_LOG_ERROR(LABEL, "read first block prefixing fail, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        if (readLen == 0) {
            break;
        }

        struct DlpBlob message1 = {.size = prefixingSize, .data = enBuf};
        struct DlpBlob message2 = {.size = prefixingSize, .data = deBuf};
        if (DoDlpBlockCryptOperation(message1, message2, alignOffset, false) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "decrypt appending bytes fail, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_CRYPT_FAIL;
        }
    } while (false);

    if (memcpy_s(deBuf + prefixingSize, DLP_BLOCK_SIZE - prefixingSize, buf, requestSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "copy write buffer first block failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    struct DlpBlob message1 = {.size = writtenSize, .data = deBuf};
    struct DlpBlob message2 = {.size = writtenSize, .data = enBuf};
    if (DoDlpBlockCryptOperation(message1, message2, alignOffset, true) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "enrypt first block fail");
        return DLP_PARSE_ERROR_CRYPT_FAIL;
    }

    if (lseek(opFd, head_.txtOffset + alignOffset, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "lseek failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(opFd, enBuf, writtenSize) != (ssize_t)writtenSize) {
        DLP_LOG_ERROR(LABEL, "write failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return requestSize;
}

int32_t DlpFile::DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;
    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE * DLP_BLOCK_SIZE);
    if (lseek(opFd, head_.txtOffset + alignOffset, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "lseek dlp file offset %{public}s failed, %{public}s",
            std::to_string(head_.txtOffset + offset).c_str(), strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    /* write first block data, if it may be not aligned */
    int32_t writenSize = WriteFirstBlockData(offset, static_cast<uint8_t *>(buf), size);
    if (writenSize < 0) {
        DLP_LOG_ERROR(LABEL, "encrypt prefix data failed");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (static_cast<uint32_t>(writenSize) >= size) {
        return writenSize;
    }

    uint8_t *restBlocksPtr = static_cast<uint8_t *>(buf) + writenSize;
    uint32_t restBlocksSize = size - static_cast<uint32_t>(writenSize);
    uint8_t* writeBuff = new (std::nothrow) uint8_t[restBlocksSize]();
    if (writeBuff == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc write buffer fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    /* first aligned block has been writen, write the rest */
    struct DlpBlob message1 = {.size = restBlocksSize, .data = restBlocksPtr};
    struct DlpBlob message2 = {.size = restBlocksSize, .data = writeBuff};

    int32_t ret = DoDlpBlockCryptOperation(message1, message2, alignOffset + DLP_BLOCK_SIZE, true);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "encrypt write buffer fail");
        delete[] writeBuff;
        return ret;
    }

    ret = write(opFd, writeBuff, restBlocksSize);
    delete[] writeBuff;
    if (ret <= 0) {
        DLP_LOG_ERROR(LABEL, "write buff failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    return ret + static_cast<int32_t>(writenSize);
}

uint64_t DlpFile::GetFsContentSize() const
{
    struct stat fileStat;
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;
    int32_t ret = fstat(opFd, &fileStat);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "fstat error %{public}d , errno %{public}d dlpfd: %{public}d ", ret, errno, opFd);
        return INVALID_FILE_SIZE;
    }
    if (head_.txtOffset > fileStat.st_size || fileStat.st_size >= static_cast<off_t>(INVALID_FILE_SIZE)) {
        DLP_LOG_ERROR(LABEL, "size error %{public}s %{public}s", std::to_string(head_.txtOffset).c_str(),
            std::to_string(static_cast<uint64_t>(fileStat.st_size)).c_str());
        return INVALID_FILE_SIZE;
    }
    if (static_cast<uint64_t>(fileStat.st_size) - head_.txtOffset == 0) {
        DLP_LOG_ERROR(LABEL, "linkFile size %{public}s, txtOffset %{public}s",
            std::to_string(static_cast<uint64_t>(fileStat.st_size)).c_str(),
            std::to_string(head_.txtOffset).c_str());
    }
    return isZip_ ? static_cast<uint64_t>(fileStat.st_size) : head_.txtSize;
}

int32_t DlpFile::UpdateDlpFileContentSize()
{
    uint64_t contentSize = GetFsContentSize();
    if (contentSize == INVALID_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "get fs content size failed");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    head_.txtSize = contentSize;
    DLP_LOG_DEBUG(LABEL, "Update dlp file content size");

    if (isZip_ == false) {
        if (lseek(dlpFd_, 0, SEEK_SET) == static_cast<off_t>(-1)) {
            DLP_LOG_ERROR(LABEL, "Lseek failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }

        if (write(dlpFd_, &head_, sizeof(head_)) != sizeof(head_)) {
            DLP_LOG_ERROR(LABEL, "Write failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
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

int32_t DlpFile::DlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, write failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        (offset >= DLP_MAX_CONTENT_SIZE - size) ||
        opFd < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "Dlp file param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint64_t curSize = GetFsContentSize();
    if (curSize != INVALID_FILE_SIZE && curSize < offset &&
        (FillHoleData(curSize, offset - curSize) != DLP_OK)) {
        DLP_LOG_ERROR(LABEL, "Fill hole data failed");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    int32_t res = DoDlpFileWrite(offset, buf, size);
    UpdateDlpFileContentSize();

    // modify dlp file, clear old hmac value and will generate new
    if (hmac_.size != 0) {
        CleanBlobParam(hmac_);
    }
    GenFileInZip(-1);
    return res;
}

int32_t DlpFile::Truncate(uint64_t size)
{
    DLP_LOG_INFO(LABEL, "Truncate file size %{public}s", std::to_string(size).c_str());

    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, truncate failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = isZip_ ? encDataFd_ : dlpFd_;
    if (opFd < 0 || size >= DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint64_t curSize = GetFsContentSize();
    int32_t res = DLP_OK;
    if (size < curSize) {
        res = ftruncate(opFd, head_.txtOffset + size);
        UpdateDlpFileContentSize();
        GenFileInZip(-1);
    } else if (size > curSize) {
        res = FillHoleData(curSize, size - curSize);
        UpdateDlpFileContentSize();
        GenFileInZip(-1);
    } else {
        DLP_LOG_INFO(LABEL, "Truncate file size equals origin file");
    }

    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Truncate file size %{public}s failed, %{public}s",
            std::to_string(size).c_str(), strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::HmacCheck()
{
    DLP_LOG_DEBUG(LABEL, "start HmacCheck, dlpVersion = %{public}d", head_.version);
    if (head_.version < HMAC_VERSION) {
        DLP_LOG_INFO(LABEL, "no hmac check");
        return DLP_OK;
    }

    uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
    if (outBuf == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    struct DlpBlob out = {
        .size = HMAC_SIZE,
        .data = outBuf,
    };
    if (isZip_) {
        int ret = GenerateHmacVal(encDataFd_, out);
        if (ret != DLP_OK) {
            CleanBlobParam(out);
            return ret;
        }
    } else {
        (void)lseek(dlpFd_, head_.txtOffset, SEEK_SET);
        DLP_LOG_DEBUG(LABEL, "start DlpHmacEncodeForRaw");
        if (DlpHmacEncodeForRaw(cipher_.hmacKey, dlpFd_, head_.txtSize, out) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "DlpHmacEncodeForRaw fail");
            CleanBlobParam(out);
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        DLP_LOG_DEBUG(LABEL, "end DlpHmacEncodeForRaw");
    }

    if (out.size == 0 || (out.size == hmac_.size && memcmp(hmac_.data, out.data, out.size) == 0)) {
        DLP_LOG_INFO(LABEL, "verify success");
        if (out.size != 0) {
            CleanBlobParam(out);
        }
        return DLP_OK;
    }
    DLP_LOG_ERROR(LABEL, "verify fail");
    CleanBlobParam(out);
    return DLP_PARSE_ERROR_FILE_VERIFICATION_FAIL;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
