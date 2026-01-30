/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_raw_file.h"

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
#include "dlp_utils.h"
#include "hex_string.h"
#ifdef DLP_PARSE_INNER
#include "os_account_manager.h"
#endif // DLP_PARSE_INNER
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Defer = std::shared_ptr<void>;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpRawFile"};
const uint32_t FILE_HEAD = 8;
const uint32_t HMAC_SIZE = 32;
const uint32_t MAX_CERT_SIZE = 30 * 1024;
const std::string DEFAULT_STRINGS = "";
const int32_t FILEID_SIZE = 46;
const int32_t FILEID_SIZE_OPPOSITE = -46;
const int32_t COUNTDOWN_OPPOSITE = -62;
const int32_t COUNTDOWN_FILETYPE = 10000;
} // namespace

static int32_t GetFileSize(int32_t fd, uint64_t& fileLen);

DlpRawFile::DlpRawFile(int32_t dlpFd, const std::string &realType) : DlpFile(dlpFd, realType)
{
    head_.magic = DLP_FILE_MAGIC;
    head_.fileType = 0;
    head_.offlineAccess = 0;
    head_.algType = DLP_MODE_CTR;
    head_.txtOffset = INVALID_FILE_SIZE;
    head_.txtSize = 0;
    head_.hmacOffset = INVALID_FILE_SIZE;
    head_.hmacSize = 0;
    head_.certOffset = INVALID_FILE_SIZE;
    head_.certSize = 0;
    head_.contactAccountOffset = 0;
    head_.contactAccountSize = 0;
    head_.offlineCertOffset = INVALID_FILE_SIZE;
    head_.offlineCertSize = 0;
}

DlpRawFile::~DlpRawFile()
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
        (void)memset_s(cert_.data, cert_.size, 0, cert_.size);
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

#ifdef SUPPORT_DLP_CREDENTIAL
    if (head_.algType == DLP_MODE_HIAE) {
        ClearDlpHIAEMgr();
    }
#endif
}

int32_t DlpRawFile::SetContactAccount(const std::string& contactAccount)
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

void DlpRawFile::SetOfflineAccess(bool flag, int32_t allowedOpenCount)
{
    bool offlineAccess = false;
    if (allowedOpenCount > 0) {
        offlineAccess = false;
    } else {
        offlineAccess = flag;
    }
    DLP_LOG_DEBUG(LABEL, "SetOfflineAccess offlineAccess %{public}s flag %{public}s allowedOpenCount %{public}d",
        offlineAccess ? "true" : "false", flag ? "true" : "false", allowedOpenCount);
    offlineAccess_ = static_cast<uint32_t>(offlineAccess);
    head_.offlineAccess = static_cast<uint32_t>(offlineAccess);
}

bool DlpRawFile::IsValidDlpHeader(const struct DlpHeader& head) const
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > MAX_CERT_SIZE ||
        head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountOffset != sizeof(struct DlpHeader) + FILE_HEAD ||
        head.txtOffset != head.contactAccountOffset + head.contactAccountSize ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.hmacOffset != head.txtOffset + head.txtSize ||
        head.hmacSize != HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH || head.offlineCertSize > MAX_CERT_SIZE ||
        !(head.certOffset == head.txtOffset || head.certOffset == head.hmacOffset + head.hmacSize)) {
        DLP_LOG_ERROR(LABEL, "IsValidDlpHeader error");
        return false;
    }
    return true;
}

bool DlpRawFile::IsValidEnterpriseDlpHeader(const struct DlpHeader& head, uint32_t dlpHeaderSize)
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize != 0 ||
        head.contactAccountOffset != dlpHeaderSize + FILE_HEAD ||
        head.txtOffset != head.contactAccountOffset + head.contactAccountSize ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.hmacOffset != head.txtOffset + head.txtSize ||
        head.hmacSize != HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH || head.offlineCertSize > DLP_MAX_CERT_SIZE ||
        !(head.certOffset == head.txtOffset || head.certOffset == head.hmacOffset + head.hmacSize)) {
        DLP_LOG_ERROR(LABEL, "IsValidEnterpriseDlpHeader error.");
        return false;
    }
    return true;
}

int32_t DlpRawFile::ParseRawDlpHeader(uint64_t fileLen, uint32_t dlpHeaderSize)
{
    if (fileLen - FILE_HEAD <= dlpHeaderSize || dlpHeaderSize >= DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "dlp file error");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (read(dlpFd_, &head_, dlpHeaderSize) != dlpHeaderSize) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file head, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (!IsValidDlpHeader(head_)) {
        DLP_LOG_ERROR(LABEL, "file head is error");
        (void)memset_s(&head_, dlpHeaderSize, 0, dlpHeaderSize);
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    
    offlineAccess_ = head_.offlineAccess;
    if (head_.txtSize == 0) {
        if (fileLen < head_.hmacOffset + head_.certSize) {
            DLP_LOG_ERROR(LABEL, "file is error");
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
    } else if (fileLen < head_.hmacOffset + head_.hmacSize + head_.certSize) {
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (version_ > CURRENT_VERSION) {
        DLP_LOG_ERROR(LABEL, "version_ > CURRENT_VERSION");
        (void)memset_s(&head_, dlpHeaderSize, 0, dlpHeaderSize);
        return DLP_PARSE_ERROR_FILE_VERSION_BIGGER_THAN_CURRENT;
    }
#ifdef SUPPORT_DLP_CREDENTIAL
    if (head_.algType == DLP_MODE_CTR) {
        DLP_LOG_INFO(LABEL, "support openssl");
        return DLP_OK;
    }
    return InitDlpHIAEMgr();
#endif
    return DLP_OK;
}

int32_t DlpRawFile::ParseEnterpriseFileId(uint64_t fileLen, uint32_t fileIdSize)
{
    uint32_t idSize = 0;
    if (read(dlpFd_, &idSize, sizeof(uint32_t)) != sizeof(uint32_t) || idSize > fileIdSize) {
        DLP_LOG_ERROR(LABEL, "can not read fileid size , %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    uint8_t *buff = new (std::nothrow)uint8_t[idSize + 1];
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "buff is null");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    (void)memset_s(buff, idSize + 1, 0, idSize + 1);
    if (read(dlpFd_, buff, idSize) != idSize) {
        delete []buff;
        DLP_LOG_ERROR(LABEL, "can not read dlp file cert, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    char *char_buffer = reinterpret_cast<char *>(buff);
    std::string str(char_buffer, idSize);
    delete []buff;
    buff = nullptr;
    fileId_ = str;
    offlineAccess_ = head_.offlineAccess;
    if (head_.txtSize == 0) {
        if (fileLen < head_.hmacOffset + head_.certSize) {
            DLP_LOG_ERROR(LABEL, "file is error");
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
    } else if (fileLen < head_.hmacOffset + head_.hmacSize + head_.certSize) {
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (version_ > CURRENT_VERSION) {
        DLP_LOG_ERROR(LABEL, "version_ > CURRENT_VERSION");
        return DLP_PARSE_ERROR_FILE_VERSION_BIGGER_THAN_CURRENT;
    }
#ifdef SUPPORT_DLP_CREDENTIAL
    if (head_.algType == DLP_MODE_CTR) {
        DLP_LOG_INFO(LABEL, "support openssl");
        return DLP_OK;
    }
    return InitDlpHIAEMgr();
#endif
    return DLP_OK;
}

int32_t DlpRawFile::ParseEnterpriseRawDlpHeader(uint64_t fileLen, uint32_t dlpHeaderSize)
{
    accountType_ = ENTERPRISE_ACCOUNT;
    if (fileLen - FILE_HEAD < dlpHeaderSize || dlpHeaderSize >= MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "file size is error");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    if (read(dlpFd_, &head_, sizeof(head_)) != sizeof(head_)) {
        DLP_LOG_ERROR(LABEL, "can not read version_ or dlpHeaderSize, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    if (!IsValidEnterpriseDlpHeader(head_, dlpHeaderSize)) {
        DLP_LOG_ERROR(LABEL, "head_ is error");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    uint32_t idSize = 0;
    if (read(dlpFd_, &idSize, sizeof(uint32_t)) != sizeof(uint32_t) || idSize > dlpHeaderSize - FILE_HEAD) {
        DLP_LOG_ERROR(LABEL, "can not read appid size , %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    uint8_t *buff = new (std::nothrow)uint8_t[idSize + 1];
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "buff is null");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    (void)memset_s(buff, idSize + 1, 0, idSize + 1);
    if (read(dlpFd_, buff, idSize) != idSize) {
        delete []buff;
        DLP_LOG_ERROR(LABEL, "can not read dlp file cert, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    char *char_buffer = reinterpret_cast<char *>(buff);
    std::string str(char_buffer, idSize);
    delete []buff;
    buff = nullptr;
    appId_ = str;
    return ParseEnterpriseFileId(fileLen, dlpHeaderSize - idSize - FILE_HEAD);
}

int32_t DlpRawFile::CheckDlpFile()
{
    if (dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }

    if (lseek(dlpFd_, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    uint64_t fileLen = 0;
    int32_t ret = GetFileSize(dlpFd_, fileLen);
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    if (fileLen <= FILE_HEAD || fileLen > DLP_MAX_RAW_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "dlp file error");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }

    if (read(dlpFd_, &version_, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file version_, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    uint32_t dlpHeaderSize = 0;

    if (read(dlpFd_, &dlpHeaderSize, sizeof(uint32_t)) != sizeof(uint32_t) ||
        dlpHeaderSize < sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file dlpHeaderSize, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }

    if (version_ == CURRENT_VERSION && dlpHeaderSize == sizeof(struct DlpHeader)) {
        return ParseRawDlpHeader(fileLen, dlpHeaderSize);
    } else {
        return ParseEnterpriseRawDlpHeader(fileLen, dlpHeaderSize);
    }

    DLP_LOG_ERROR(LABEL, "the version or HeaderSize is error");
    return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
}

uint32_t DlpRawFile::GetOfflineCertSize(void)
{
    return head_.offlineCertSize;
}

int32_t DlpRawFile::WriteHmacProcess(void)
{
    (void)lseek(dlpFd_, head_.hmacOffset, SEEK_SET);
    uint8_t *tempBufHmacStr = new (std::nothrow) uint8_t[head_.hmacSize + 1];
    if (tempBufHmacStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "new tempBuf failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)memset_s(tempBufHmacStr, head_.hmacSize + 1, 0, head_.hmacSize + 1);
    if (read(dlpFd_, tempBufHmacStr, head_.hmacSize) != (ssize_t)head_.hmacSize) {
        DLP_LOG_ERROR(LABEL, "can not read tempBufHmacStr, %{public}s", strerror(errno));
        delete[] tempBufHmacStr;
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    CleanBlobParam(hmac_);
    hmac_.size = head_.hmacSize / BYTE_TO_HEX_OPER_LENGTH;
    hmac_.data = new (std::nothrow) uint8_t[hmac_.size];
    if (hmac_.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "new hmac size failed");
        delete[] tempBufHmacStr;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (HexStringToByte((char *)tempBufHmacStr, head_.hmacSize, hmac_.data, hmac_.size) != DLP_OK) {
        delete[] tempBufHmacStr;
        DLP_LOG_ERROR(LABEL, "HexStringToByte failed");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    delete[] tempBufHmacStr;
    return DLP_OK;
}

int32_t DlpRawFile::WriteFileIdPlaintextProcess(void)
{
    if (lseek(dlpFd_, COUNTDOWN_OPPOSITE, SEEK_END) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "get to waterConfig invalid");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    countdown_ = 0;
    if (read(dlpFd_, &countdown_, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read countdown, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    int32_t waterMarkTmp = 0;
    if (read(dlpFd_, &waterMarkTmp, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read waterMarkConfig, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    waterMarkConfig_ = (waterMarkTmp == 1);
    int32_t flag = 0;
    if (read(dlpFd_, &flag, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read flag, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    allowedOpenCount_ = 0;
    if (flag == 1) {
        if (read(dlpFd_, &allowedOpenCount_, sizeof(int32_t)) != sizeof(int32_t)) {
            DLP_LOG_ERROR(LABEL, "can not read allowedOpenCount, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
    }

    uint8_t *tmpBuf = new (std::nothrow)uint8_t[FILEID_SIZE];
    if (tmpBuf == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    off_t fileLen = lseek(dlpFd_, FILEID_SIZE_OPPOSITE, SEEK_END);
    if (fileLen == static_cast<off_t>(-1)) {
        delete[] tmpBuf;
        DLP_LOG_ERROR(LABEL, "get fileid fileLen invalid");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (read(dlpFd_, tmpBuf, FILEID_SIZE) != FILEID_SIZE) {
        delete[] tmpBuf;
        DLP_LOG_ERROR(LABEL, "can not read fileId, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    fileIdPlaintext_ = std::string(tmpBuf, tmpBuf + FILEID_SIZE);
    if (tmpBuf[0] != 0 && flag == 0) {
        allowedOpenCount_ = 1;
    }

    delete[] tmpBuf;
    return DLP_OK;
}

int32_t DlpRawFile::GetRawDlpHmac(void)
{
    int32_t flag = WriteHmacProcess();
    if (flag != DLP_OK) {
        return flag;
    }

    return WriteFileIdPlaintextProcess();
}

int32_t DlpRawFile::ProcessDlpFile()
{
    int32_t ret = CheckDlpFile();
    if (ret != DLP_OK) {
        return ret;
    }
    uint8_t* buf = new (std::nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
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
    uint8_t *tmpBuf = nullptr;
    if (accountType_ != ENTERPRISE_ACCOUNT) {
        uint8_t *tmpBuf = new (std::nothrow)uint8_t[head_.contactAccountSize];
        if (tmpBuf == nullptr) {
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
    }
    if (head_.offlineCertSize != 0 && head_.offlineCertSize == head_.certSize) {
        tmpBuf = new (std::nothrow)uint8_t[head_.offlineCertSize];
        if (tmpBuf == nullptr) {
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
    return GetRawDlpHmac();
}

int32_t DlpRawFile::SetEncryptCert(const struct DlpBlob& cert)
{
    if (cert.data == nullptr || cert.size > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert data invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (cert_.data != nullptr) {
        (void)memset_s(cert_.data, cert_.size, 0, cert_.size);
        delete[] cert_.data;
        cert_.data = nullptr;
    }

    if (CopyBlobParam(cert, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    head_.contactAccountOffset = sizeof(struct DlpHeader) + FILE_HEAD;
    head_.certSize = cert_.size;
    return DLP_OK;
}

int32_t DlpRawFile::UpdateCertAndText(const std::vector<uint8_t>& cert, struct DlpBlob certBlob)
{
    if (CopyBlobParam(certBlob, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    // version 1 single file auto convert to version 2 zip file, set version
    head_.offlineCertSize = cert.size();
    head_.certSize = cert.size();

    (void)lseek(dlpFd_, FILE_HEAD, SEEK_SET);
    if (write(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "write dlp head_ data failed, %{public}s", strerror(errno));
        if (dlpFd_ != -1 && errno == EBADF) {
            DLP_LOG_DEBUG(LABEL, "this dlp fd is readonly, unable write.");
            return DLP_OK;
        }
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    (void)lseek(dlpFd_, head_.offlineCertOffset, SEEK_SET);
    if (write(dlpFd_, certBlob.data, certBlob.size) != (ssize_t)head_.offlineCertSize) {
        DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

static int32_t GetFileSize(int32_t fd, uint64_t& fileLen)
{
    int32_t ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    off_t readLen = lseek(fd, 0, SEEK_END);
    if (readLen == static_cast<off_t>(-1) || static_cast<uint64_t>(readLen) > DLP_MAX_RAW_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "get file size failed, %{public}s", strerror(errno));
    } else {
        fileLen = static_cast<uint64_t>(readLen);
        ret = DLP_OK;
    }
    (void)lseek(fd, 0, SEEK_SET);
    return ret;
}

int32_t DlpRawFile::WriteRawFileProperty()
{
    if (lseek(dlpFd_, COUNTDOWN_OPPOSITE, SEEK_END) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "get offsize invalid");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, &countdown_, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "write countdown_ error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    int32_t waterMark = static_cast<int32_t>(waterMarkConfig_);
    if (write(dlpFd_, &waterMark, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "write waterMark_ error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    int32_t flag = 1;
    if (write(dlpFd_, &flag, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "write flag error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, &allowedOpenCount_, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "write allowedOpenCount_ error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, fileId_.c_str(), fileId_.size()) != static_cast<int32_t>(fileId_.size())) {
        DLP_LOG_ERROR(LABEL, "write dlpFd_ error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpRawFile::DoWriteHmacAndCert(uint32_t hmacStrLen, std::string& hmacStr)
{
    if (write(dlpFd_, hmacStr.c_str(), hmacStrLen) != static_cast<int32_t>(hmacStrLen)) {
        DLP_LOG_ERROR(LABEL, "write hmacStr failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (write(dlpFd_, cert_.data, head_.certSize) != (ssize_t)head_.certSize) {
        DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (MAX_CERT_SIZE < head_.certSize) {
        DLP_LOG_ERROR(LABEL, "the cert size is error");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    uint8_t* buffer = new (std::nothrow) uint8_t[MAX_CERT_SIZE - head_.certSize];
    if (buffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "buffer is nullptr");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    (void)memset_s(buffer, MAX_CERT_SIZE - head_.certSize, 0, MAX_CERT_SIZE - head_.certSize);
    if (write(dlpFd_, buffer, MAX_CERT_SIZE - head_.certSize) != (ssize_t)(MAX_CERT_SIZE - head_.certSize)) {
        DLP_LOG_ERROR(LABEL, "write buffer is error");
        delete[] buffer;
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    delete[] buffer;
    return WriteRawFileProperty();
}

int32_t DlpRawFile::DoHmacAndCrypty(int32_t inPlainFileFd, off_t fileLen)
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
    (void)lseek(dlpFd_, head_.hmacOffset, SEEK_SET);
    return DoWriteHmacAndCert(hmacStrLen, hmacStr);
}

int32_t DlpRawFile::DoWriteHeaderAndContactAccount(int32_t inPlainFileFd, uint64_t fileLen)
{
    if (write(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "write dlp head failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (accountType_ == ENTERPRISE_ACCOUNT) {
        uint32_t idSize = appId_.size();
        if (write(dlpFd_, &idSize, sizeof(uint32_t)) != sizeof(uint32_t)) {
            DLP_LOG_ERROR(LABEL, "write appId_ size failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        if (write(dlpFd_, appId_.c_str(), idSize) != static_cast<int32_t>(idSize)) {
            DLP_LOG_ERROR(LABEL, "write appId_ failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        idSize = fileId_.size();
        if (write(dlpFd_, &idSize, sizeof(uint32_t)) != sizeof(uint32_t)) {
            DLP_LOG_ERROR(LABEL, "write fileId_ size failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        if (write(dlpFd_, fileId_.c_str(), idSize) != static_cast<int32_t>(idSize)) {
            DLP_LOG_ERROR(LABEL, "write fileId_ failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
    } else {
        if (write(dlpFd_, contactAccount_.c_str(), contactAccount_.size()) !=
            static_cast<int32_t>(contactAccount_.size())) {
            DLP_LOG_ERROR(LABEL, "write dlp contact data failed, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
    }
    DLP_LOG_DEBUG(LABEL, "begin DoHmacAndCrypty");
    return DoHmacAndCrypty(inPlainFileFd, fileLen);
}

int32_t DlpRawFile::GenFileInRaw(int32_t inPlainFileFd)
{
    off_t fileLen = lseek(inPlainFileFd, 0, SEEK_END);
    if (accountType_ == ENTERPRISE_ACCOUNT) {
        head_.contactAccountSize = 0;
        head_.contactAccountOffset = FILE_HEAD + sizeof(DlpHeader) + appId_.size() + fileId_.size() + FILE_HEAD;
        head_.txtOffset = head_.contactAccountOffset + head_.contactAccountSize;
    }
    head_.txtSize = static_cast<uint64_t>(fileLen);
    head_.hmacOffset = head_.txtOffset + head_.txtSize;
    head_.hmacSize = HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH;
    head_.certOffset = head_.hmacOffset + head_.hmacSize;
    head_.offlineCertOffset = head_.hmacOffset + head_.hmacSize;

    DLP_LOG_DEBUG(LABEL, "fileLen %{public}s", std::to_string(head_.txtSize).c_str());
    auto iter = TYPE_TO_NUM_MAP.find(realType_);
    if (iter == TYPE_TO_NUM_MAP.end()) {
        DLP_LOG_DEBUG(LABEL, "find %{public}s type fail", realType_.c_str());
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    head_.fileType = iter->second;
    if (countdown_ > 0) {
        DLP_LOG_DEBUG(LABEL, "raw set countdown");
        head_.fileType = head_.fileType + COUNTDOWN_FILETYPE;
    }
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

    if (write(dlpFd_, &version_, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "write dlp dlpHeaderSize failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    uint32_t dlpHeaderSize = accountType_ == ENTERPRISE_ACCOUNT ?
        (sizeof(DlpHeader) + appId_.size() + fileId_.size() + FILE_HEAD) : sizeof(struct DlpHeader);
    if (write(dlpFd_, &dlpHeaderSize, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "write dlp dlpHeaderSize failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DoWriteHeaderAndContactAccount(inPlainFileFd, head_.txtSize);
}

int32_t DlpRawFile::GenFile(int32_t inPlainFileFd)
{
    if (inPlainFileFd < 0 || dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    
    int32_t result = setAlgType(inPlainFileFd, realType_);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "setAlgType fail, errno=%{public}d", result);
        return result;
    }

    return GenFileInRaw(inPlainFileFd);
}

int32_t DlpRawFile::RemoveDlpPermissionInRaw(int32_t outPlainFileFd)
{
    off_t fileLen = lseek(dlpFd_, 0, SEEK_END);
    if (fileLen == static_cast<off_t>(-1) || fileLen > static_cast<off_t>(DLP_MAX_RAW_CONTENT_SIZE)) {
        DLP_LOG_ERROR(LABEL, "can not get dlp file len, %{public}s", strerror(errno));
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

    return DoDlpContentCryptyOperation(dlpFd_, outPlainFileFd, 0, head_.txtSize, false);
}

int32_t DlpRawFile::RemoveDlpPermission(int32_t outPlainFileFd)
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

    return RemoveDlpPermissionInRaw(outPlainFileFd);
}

int32_t DlpRawFile::DlpFileRead(uint64_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid)
{
    int32_t opFd = dlpFd_;
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN || (offset >= DLP_MAX_RAW_CONTENT_SIZE - size) ||
        opFd < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint64_t prefixingSize = offset - alignOffset;
    uint64_t alignSize = size + prefixingSize;

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
    int32_t res = DLP_OK;
    if (head_.algType == DLP_MODE_CTR) {
        res = DoDlpBlockCryptOperation(message1, message2, alignOffset, false);
    } else {
        res = DoDlpHIAECryptOperation(message1, message2, alignOffset, false);
    }
    if (res != DLP_OK) {
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
    res = DlpPermissionKit::SetReadFlag(uid);
    if (res != DLP_OK) {
        return res;
    }
    hasRead = true;
    return message2.size - prefixingSize;
}

uint64_t DlpRawFile::GetFsContentSize() const
{
    struct stat fileStat;
    int32_t opFd = dlpFd_;
    int32_t ret = fstat(opFd, &fileStat);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "fstat error %{public}d , errno %{public}d dlpfd: %{public}d ", ret, errno, opFd);
        return INVALID_FILE_SIZE;
    }
    if (fileStat.st_size < static_cast<off_t>(head_.txtOffset) ||
        fileStat.st_size - static_cast<off_t>(head_.txtOffset) <= head_.hmacSize ||
        fileStat.st_size - static_cast<off_t>(head_.txtOffset) - head_.hmacSize < head_.certSize ||
        fileStat.st_size > static_cast<off_t>(DLP_MAX_RAW_CONTENT_SIZE)) {
        DLP_LOG_ERROR(LABEL, "size error %{public}s %{public}s", std::to_string(head_.txtOffset).c_str(),
            std::to_string(static_cast<uint64_t>(fileStat.st_size)).c_str());
        return INVALID_FILE_SIZE;
    }

    return static_cast<uint64_t>(fileStat.st_size) - head_.txtOffset - head_.hmacSize - MAX_CERT_SIZE;
}

int32_t DlpRawFile::UpdateDlpFileContentSize()
{
    uint64_t contentSize = GetFsContentSize();
    if (contentSize == INVALID_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "get fs content size failed");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    head_.txtSize = contentSize;
    DLP_LOG_DEBUG(LABEL, "Update dlp file content size");

    if (lseek(dlpFd_, FILE_HEAD, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "Lseek failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, &head_, sizeof(head_)) != sizeof(head_)) {
        DLP_LOG_ERROR(LABEL, "Write failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpRawFile::WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size)
{
    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset % DLP_BLOCK_SIZE;
    uint32_t requestSize = (size < (DLP_BLOCK_SIZE - prefixingSize)) ? size : (DLP_BLOCK_SIZE - prefixingSize);
    uint32_t writtenSize = prefixingSize + requestSize;
    uint8_t enBuf[DLP_BLOCK_SIZE] = {0};
    uint8_t deBuf[DLP_BLOCK_SIZE] = {0};
    int32_t opFd = dlpFd_;

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

int32_t DlpRawFile::DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    int32_t opFd = dlpFd_;
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
    if (ret != static_cast<int32_t>(restBlocksSize)) {
        DLP_LOG_ERROR(LABEL, "write buff failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return ret + static_cast<int32_t>(writenSize);
}

int32_t DlpRawFile::DlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, write failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = dlpFd_;
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        (offset >= DLP_MAX_RAW_CONTENT_SIZE - size) ||
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
    return res;
}

int32_t DlpRawFile::Truncate(uint64_t size)
{
    DLP_LOG_INFO(LABEL, "Truncate file size %{public}s", std::to_string(size).c_str());

    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, truncate failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = dlpFd_;
    if (opFd < 0 || size >= DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint64_t curSize = GetFsContentSize();
    int32_t res = DLP_OK;
    if (size < curSize) {
        res = ftruncate(opFd, head_.txtOffset + size);
        UpdateDlpFileContentSize();
    } else if (size > curSize) {
        res = FillHoleData(curSize, size - curSize);
        UpdateDlpFileContentSize();
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

int32_t DlpRawFile::HmacCheck()
{
    DLP_LOG_DEBUG(LABEL, "start HmacCheck, dlpVersion = %{public}d", version_);
    if (version_ < HMAC_VERSION) {
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

    (void)lseek(dlpFd_, head_.txtOffset, SEEK_SET);
    DLP_LOG_DEBUG(LABEL, "start DlpHmacEncodeForRaw");
    if (DlpHmacEncodeForRaw(cipher_.hmacKey, dlpFd_, head_.txtSize, out) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DlpHmacEncodeForRaw fail");
        CleanBlobParam(out);
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    DLP_LOG_DEBUG(LABEL, "end DlpHmacEncodeForRaw");

    if ((out.size == 0 && hmac_.size == 0) ||
        (out.size == hmac_.size && memcmp(hmac_.data, out.data, out.size) == 0)) {
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

int32_t DlpRawFile::setAlgType(int32_t inPlainFileFd, const std::string& realFileType)
{
    head_.algType = DLP_MODE_CTR;
    off_t fileLen = lseek(inPlainFileFd, 0, SEEK_END);
    if (fileLen == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "inFd len is invalid, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(inPlainFileFd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek inFd start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (fileLen > static_cast<off_t>(DLP_MIN_HIAE_SIZE) && DlpUtils::GetFileType(realFileType)) {
        head_.algType = DLP_MODE_HIAE;
    }
    return DLP_OK;
}

int32_t DlpRawFile::DoDlpHIAECryptOperation(struct DlpBlob& message1, struct DlpBlob& message2,
    uint64_t offset, bool isEncrypt)
{
#ifndef SUPPORT_DLP_CREDENTIAL
    return DoDlpBlockCryptOperation(message1, message2, offset, isEncrypt);
#endif

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

    int32_t ret = DLP_OK;
    uint32_t blockOffset = 0;
    uint32_t blockNum = (message1.size + HIAE_BLOCK_SIZE - 1) / HIAE_BLOCK_SIZE;
    for (uint32_t i = 0; i < blockNum; ++i) {
        uint64_t blockLen =
            ((message1.size - blockOffset) < HIAE_BLOCK_SIZE) ? (message1.size - blockOffset) : HIAE_BLOCK_SIZE;
        
        ret = isEncrypt ? DlpHIAEEncrypt(&cipher_.encKey, &spec, blockLen,
            message1.data + blockOffset, message2.data + blockOffset)
            : DlpHIAEDecrypt(&cipher_.encKey, &spec, blockLen,
            message1.data + blockOffset, message2.data + blockOffset);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "do HIAE crypt operation failed, ret: %{public}d", ret);
            break;
        }

        DlpCtrModeIncreaeIvCounter(spec.algParam->iv, HIAE_BLOCK_SIZE / DLP_BLOCK_SIZE);
        blockOffset += blockLen;
    }
    message2.size = message1.size;
    delete[] spec.algParam->iv.data;
    delete spec.algParam;
    return ret;
}

static bool IsInitDlpContentCryptyOperation(uint32_t algType)
{
#ifdef SUPPORT_DLP_CREDENTIAL
    if (algType == DLP_MODE_CTR) {
        DLP_LOG_INFO(LABEL, "support openssl");
    } else {
        if (InitDlpHIAEMgr() != DLP_OK) {
            return false;
        }
    }
#endif
    return true;
}

int32_t DlpRawFile::DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
    uint64_t inFileLen, bool isEncrypt)
{
    if (!IsInitDlpContentCryptyOperation(head_.algType)) {
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
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
        if (head_.algType == DLP_MODE_CTR) {
            ret = DoDlpBlockCryptOperation(message, outMessage, inOffset - dlpContentOffset, isEncrypt);
        } else {
            ret = DoDlpHIAECryptOperation(message, outMessage, inOffset - dlpContentOffset, isEncrypt);
        }
        
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "do crypt operation fail");
            break;
        }

        if (write(outFd, outMessage.data, readLen) != (ssize_t)readLen) {
            DLP_LOG_ERROR(LABEL, "write fd failed, %{public}s", strerror(errno));
            if (dlpFd_ != -1 && errno == EBADF) {
                DLP_LOG_DEBUG(LABEL, "this dlp fd is readonly, unable write.");
                break;
            }
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }
        inOffset += readLen;
    }

    delete[] message.data;
    delete[] outMessage.data;
    return ret;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
