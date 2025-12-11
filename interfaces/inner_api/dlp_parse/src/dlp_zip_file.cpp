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

#include "dlp_zip_file.h"
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <cstring>
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
#ifdef DLP_PARSE_INNER
#include "os_account_manager.h"
#endif // DLP_PARSE_INNER
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Defer = std::shared_ptr<void>;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpZipFile"};
const uint32_t HMAC_SIZE = 32;
const uint32_t DLP_CWD_MAX = 256;
const std::string DLP_GENERAL_INFO = "dlp_general_info";
const std::string DLP_CERT = "dlp_cert";
const std::string DLP_ENC_DATA = "encrypted_data";
const std::string DLP_OPENING_ENC_DATA = "opened_encrypted_data";
const std::string DLP_GEN_FILE = "gen_dlp_file";
const std::string DEFAULT_STRINGS = "";

struct GenerInfoParams {
    bool accessFlag;
    std::string contactAccount;
    std::string hmacStr;
    uint32_t version;
    std::string realType;
    uint32_t certSize;
    std::string fileId;
    int32_t allowedOpenCount;
    bool waterMarkConfig;
};
} // namespace

std::mutex g_fileOpLock_;

static int32_t GetFileSize(int32_t fd, uint64_t& fileLen);

DlpZipFile::DlpZipFile(int32_t dlpFd, const std::string &workDir, int64_t index, const std::string &realType)
    : DlpFile(dlpFd, realType), workDir_(workDir), dirIndex_(std::to_string(index))
{
    certSize_ = 0;
}

DlpZipFile::~DlpZipFile()
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
        (void)memset_s(offlineCert_.data, offlineCert_.size, 0, offlineCert_.size);
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

int32_t DlpZipFile::SetContactAccount(const std::string& contactAccount)
{
    if (contactAccount.size() == 0 || contactAccount.size() > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "contactAccount param failed");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    contactAccount_ = contactAccount;
    return DLP_OK;
};

void DlpZipFile::SetOfflineAccess(bool flag, int32_t allowedOpenCount)
{
    bool offlineAccess = false;
    if (allowedOpenCount > 0) {
        offlineAccess = false;
    } else {
        offlineAccess = flag;
    }
    offlineAccess_ = static_cast<uint32_t>(offlineAccess);
    DLP_LOG_DEBUG(LABEL, "SetOfflineAccess offlineAccess %{public}s flag %{public}s allowedOpenCount %{public}d",
        offlineAccess ? "true" : "false", flag ? "true" : "false", allowedOpenCount);
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
        DLP_LOG_INFO(LABEL, "cannot find file");
        return DLP_RETENTION_FILE_FIND_FILE_ERROR;
    }
    std::stringstream buffer;
    std::ifstream i(path);
    if (!i.is_open()) {
        DLP_LOG_INFO(LABEL, "cannot open file, errno %{public}d.", errno);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    buffer << i.rdbuf();
    content = buffer.str();
    i.close();
    return DLP_OK;
}

bool DlpZipFile::ParseDlpInfo()
{
    std::string content;
    (void)GetFileContent(DLP_GENERAL_INFO, content);
    GenerateInfoParams params;
    int32_t res = ParseDlpGeneralInfo(content, params);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "ParseDlpGeneralInfo %{public}s", content.c_str());
        return false;
    }
    version_ = params.version;
    offlineAccess_ = params.offlineAccessFlag;
    extraInfo_ = params.extraInfo;
    contactAccount_ = params.contactAccount;
    certSize_ = params.certSize;
    fileIdPlaintext_ = params.fileId;
    allowedOpenCount_ = params.allowedOpenCount;
    waterMarkConfig_ = params.waterMarkConfig;
    if (!params.hmacVal.empty()) {
        CleanBlobParam(hmac_);
        hmac_.size = params.hmacVal.size() / BYTE_TO_HEX_OPER_LENGTH;
        if (hmac_.size > HMAC_SIZE) {
            DLP_LOG_ERROR(LABEL, "hmac_.size is invalid");
            return false;
        }
        hmac_.data = new (std::nothrow)uint8_t[hmac_.size];
        if (hmac_.data == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return false;
        }
        return HexStringToByte(params.hmacVal.c_str(), params.hmacVal.length(), hmac_.data, hmac_.size) == DLP_OK;
    }
    return true;
}

bool DlpZipFile::ParseCert()
{
    struct stat fz;
    if (stat(DLP_CERT.c_str(), &fz) != 0) {
        DLP_LOG_ERROR(LABEL, "ParseCert failed, %{public}s", strerror(errno));
        return false;
    }
    CleanBlobParam(cert_);
    if (fz.st_size == 0 || fz.st_size > DLP_MAX_CERT_SIZE || certSize_ > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert size is too large or equit to 0.");
        return false;
    }
    uint32_t certSize = certSize_ ? certSize_ : static_cast<uint32_t>(fz.st_size);
    cert_.data = new (std::nothrow) uint8_t[certSize];
    if (cert_.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "new failed");
        return false;
    }
    cert_.size = static_cast<uint32_t>(certSize);
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

bool DlpZipFile::ParseEncData()
{
    int32_t fd = open(DLP_OPENING_ENC_DATA.c_str(), O_RDWR);
    if (fd == -1) {
        DLP_LOG_ERROR(LABEL, "ParseEncData failed, %{public}s", strerror(errno));
        return false;
    }
    encDataFd_ = fd;
    return true;
}

bool DlpZipFile::CleanTmpFile()
{
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

uint32_t DlpZipFile::GetOfflineCertSize(void)
{
    return certSize_;
}

int32_t DlpZipFile::ProcessDlpFile()
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

int32_t DlpZipFile::CheckDlpFile()
{
    if (dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }
    return DLP_OK;
}

int32_t DlpZipFile::SetEncryptCert(const struct DlpBlob& cert)
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
    return DLP_OK;
}

int32_t DlpZipFile::UpdateCertAndText(const std::vector<uint8_t>& cert, struct DlpBlob certBlob)
{
    if (CopyBlobParam(certBlob, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    certSize_ = cert_.size;
    return GenFileInZip(-1);
}

int32_t DlpZipFile::DoDlpContentCopyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset, uint64_t inFileLen)
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
            if (outFd != -1 && errno == EBADF) {
                break;
            }
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

static std::string SetDlpGeneralInfo(GenerInfoParams &genInfo)
{
    GenerateInfoParams params = {
        .version = genInfo.version,
        .offlineAccessFlag = genInfo.accessFlag,
        .contactAccount = genInfo.contactAccount,
        .extraInfo = {"kia_info", "cert_info", "enc_data"},
        .hmacVal = genInfo.hmacStr,
        .realType = genInfo.realType,
        .certSize = genInfo.certSize,
        .fileId = genInfo.fileId,
        .allowedOpenCount = genInfo.allowedOpenCount,
        .waterMarkConfig = genInfo.waterMarkConfig,
    };
    std::string out;
    GenerateDlpGeneralInfo(params, out);
    return out;
}

int32_t DlpZipFile::GenEncData(int32_t inPlainFileFd)
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

int32_t DlpZipFile::GenerateHmacVal(int32_t encFile, struct DlpBlob& out)
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

int32_t DlpZipFile::GetHmacVal(int32_t encFile, std::string& hmacStr)
{
    if (version_ < HMAC_VERSION) {
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

int32_t DlpZipFile::AddGeneralInfoToBuff(int32_t encFile)
{
    std::string hmacStr;
    int ret = GetHmacVal(encFile, hmacStr);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetHmacVal fail");
        return ret;
    }
    GenerInfoParams genInfo = {
        .accessFlag = static_cast<bool>(offlineAccess_),
        .contactAccount = contactAccount_,
        .hmacStr = hmacStr,
        .version = version_,
        .realType = realType_,
        .certSize = cert_.size,
        .fileId = fileId_,
        .allowedOpenCount = allowedOpenCount_,
        .waterMarkConfig = waterMarkConfig_,
    };

    std::string ja = SetDlpGeneralInfo(genInfo);
    ret = AddBuffToZip(reinterpret_cast<const void *>(ja.c_str()), ja.size(),
        DLP_GENERAL_INFO.c_str(), DLP_GEN_FILE.c_str());
    CHECK_RET(ret, 0, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);
    return DLP_OK;
}

int32_t DlpZipFile::GenFileInZip(int32_t inPlainFileFd)
{
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

    if (dlpFd_ != -1 && errno == EBADF) {
        DLP_LOG_DEBUG(LABEL, "this dlp fd is readonly, unable write.");
        return DLP_OK;
    }
    FTRUNCATE_AND_CHECK(dlpFd_, zipSize, DLP_PARSE_ERROR_FILE_OPERATE_FAIL, LABEL);

    (void)fsync(dlpFd_);
    return DLP_OK;
}

int32_t DlpZipFile::GenFile(int32_t inPlainFileFd)
{
    if (inPlainFileFd < 0 || dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (hmac_.size != 0) {
        CleanBlobParam(hmac_);
    }
    return GenFileInZip(inPlainFileFd);
}

int32_t DlpZipFile::RemoveDlpPermissionInZip(int32_t outPlainFileFd)
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

int32_t DlpZipFile::RemoveDlpPermission(int32_t outPlainFileFd)
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

    return RemoveDlpPermissionInZip(outPlainFileFd);
}

uint64_t DlpZipFile::GetFsContentSize() const
{
    struct stat fileStat;
    int32_t opFd = encDataFd_;
    int32_t ret = fstat(opFd, &fileStat);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "fstat error %{public}d , errno %{public}d dlpfd: %{public}d ", ret, errno, opFd);
        return INVALID_FILE_SIZE;
    }
    if (0 > fileStat.st_size || fileStat.st_size >= static_cast<off_t>(DLP_MAX_RAW_CONTENT_SIZE)) {
        DLP_LOG_ERROR(LABEL, "size error %{public}s",
            std::to_string(static_cast<uint64_t>(fileStat.st_size)).c_str());
        return INVALID_FILE_SIZE;
    }
    return static_cast<uint64_t>(fileStat.st_size);
}

int32_t DlpZipFile::UpdateDlpFileContentSize()
{
    uint64_t contentSize = GetFsContentSize();
    if (contentSize == INVALID_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "get fs content size failed");
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    DLP_LOG_DEBUG(LABEL, "Update dlp file content size");
    return DLP_OK;
}

int32_t DlpZipFile::DlpFileRead(uint64_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid)
{
    int32_t opFd = encDataFd_;
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        (offset >= DLP_MAX_CONTENT_SIZE - size) ||
        opFd < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec, cipher_.hmacKey)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset - alignOffset;
    uint32_t alignSize = size + prefixingSize;

    if (lseek(opFd, alignOffset, SEEK_SET) == -1) {
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

int32_t DlpZipFile::WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size)
{
    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset % DLP_BLOCK_SIZE;
    uint32_t requestSize = (size < (DLP_BLOCK_SIZE - prefixingSize)) ? size : (DLP_BLOCK_SIZE - prefixingSize);
    uint32_t writtenSize = prefixingSize + requestSize;
    uint8_t enBuf[DLP_BLOCK_SIZE] = {0};
    uint8_t deBuf[DLP_BLOCK_SIZE] = {0};
    int32_t opFd = encDataFd_;

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

    if (lseek(opFd, alignOffset, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "lseek failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(opFd, enBuf, writtenSize) != (ssize_t)writtenSize) {
        DLP_LOG_ERROR(LABEL, "write failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return requestSize;
}

int32_t DlpZipFile::DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    int32_t opFd = encDataFd_;
    uint64_t alignOffset = (offset / DLP_BLOCK_SIZE * DLP_BLOCK_SIZE);
    if (lseek(opFd, alignOffset, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "lseek dlp file offset %{public}s failed, %{public}s",
            std::to_string(offset).c_str(), strerror(errno));
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

int32_t DlpZipFile::DlpFileWrite(uint64_t offset, void* buf, uint32_t size)
{
    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, write failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = encDataFd_;
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

int32_t DlpZipFile::Truncate(uint64_t size)
{
    DLP_LOG_INFO(LABEL, "Truncate file size %{public}s", std::to_string(size).c_str());

    if (authPerm_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, truncate failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }
    int32_t opFd = encDataFd_;
    if (opFd < 0 || size >= DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint64_t curSize = GetFsContentSize();
    int32_t res = DLP_OK;
    if (size < curSize) {
        res = ftruncate(opFd, size);
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

int32_t DlpZipFile::HmacCheck()
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

    int ret = GenerateHmacVal(encDataFd_, out);
    if (ret != DLP_OK) {
        CleanBlobParam(out);
        return ret;
    }

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

int32_t DlpZipFile::DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
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
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
