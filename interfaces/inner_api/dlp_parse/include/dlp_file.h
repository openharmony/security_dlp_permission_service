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

#ifndef INTERFACES_INNER_API_DLP_FILE_H
#define INTERFACES_INNER_API_DLP_FILE_H

#include <string>
#include "dlp_crypt.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static constexpr uint64_t INVALID_FILE_SIZE = 0x0fffffffffffffff;
static constexpr uint32_t DLP_BUFF_LEN = 1024 * 1024; // 1M
static constexpr uint32_t IV_SIZE = 16;
static constexpr uint32_t DLP_FILE_MAGIC = 0x87f4922;
static constexpr uint32_t DLP_FUSE_MAX_BUFFLEN = (10 * 1024 * 1024); // 10M
static constexpr uint32_t DLP_BLOCK_SIZE = 16;
// dlp file only support 32bits size, apart from 10M max head size
static constexpr uint64_t DLP_MAX_CONTENT_SIZE = 0xffffffff - 0xA00000;
static constexpr uint64_t DLP_MAX_RAW_CONTENT_SIZE = 0xffffffff;
static constexpr uint32_t HOLE_BUFF_SIZE = 16 * 1024;
static constexpr uint32_t HOLE_BUFF_SMALL_SIZE = 1 * 1024;
static constexpr uint32_t MAX_HOLE_SIZE = 50 * 1024 * 1024; // 50M
static constexpr uint64_t DLP_MIN_HIAE_SIZE = 0xC0000000 - 0xA00000;
static constexpr uint32_t HIAE_BLOCK_SIZE = 4 * 1024;  // 4k

struct DlpCipher {
    struct DlpBlob encKey;
    struct DlpCipherParam tagIv;
    struct DlpUsageSpec usageSpec;
    struct DlpBlob hmacKey;
};

struct DlpHeader {
    uint32_t magic;
    uint32_t fileType;
    uint32_t offlineAccess;
    uint32_t algType;
    uint32_t certSize;
    uint32_t hmacSize;
    uint32_t contactAccountOffset;
    uint32_t contactAccountSize;
    uint32_t offlineCertSize;
    uint64_t txtOffset;
    uint64_t txtSize;
    uint64_t certOffset;
    uint64_t hmacOffset;
    uint64_t offlineCertOffset;
};

enum VALID_KEY_SIZE {
    DLP_KEY_LEN_128 = 16,
    DLP_KEY_LEN_192 = 24,
    DLP_KEY_LEN_256 = 32,
};

#define CHECK_RET(ret, expect, retcode, TAG)                            \
    do {                                                                \
        if ((ret) != (expect)) {                                            \
            DLP_LOG_ERROR(TAG, "check fail ret %{public}d, expect %{public}d, errno %{public}s", \
                ret, expect, strerror(errno));                          \
            return retcode;                                             \
        }                                                               \
    } while (0)                                                         \

#define CHDIR_AND_CHECK(path, ret, TAG)                                 \
    do {                                                                \
        if (chdir(path) != 0) {                                         \
            DLP_LOG_ERROR(TAG, "chdir fail, errno %{public}s", \
                strerror(errno));                                 \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define UNLINK_AND_CHECK(path, ret, TAG)                                \
    do {                                                                \
        if (unlink(path) != 0) {                                        \
            DLP_LOG_ERROR(TAG, "unlink fail, errno %{public}s", \
                strerror(errno));                                 \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define MKDIR_AND_CHECK(path, mode, ret, TAG)                           \
    do {                                                                \
        if (mkdir(path, mode) != 0) {                                   \
            DLP_LOG_ERROR(TAG, "mkdir fail, errno %{public}s", \
                strerror(errno));                                 \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define GETCWD_AND_CHECK(buf, size, ret, TAG)                           \
    do {                                                                \
        if (getcwd(buf, size) == nullptr) {                             \
            DLP_LOG_ERROR(TAG, "getcwd fail errno %{public}s",          \
                strerror(errno));                                       \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define LSEEK_AND_CHECK(fd, size, flag, ret, TAG)                       \
    do {                                                                \
        if (lseek(fd, size, flag) == -1) {                              \
            DLP_LOG_ERROR(TAG, "lseek failed, %{public}s",              \
                strerror(errno));                                       \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define OPEN_AND_CHECK(fd, path, flag, mode, ret, TAG)                  \
    do {                                                                \
        fd = open(path, flag, mode);                                    \
        if ((fd) == -1) {                                                \
            DLP_LOG_ERROR(TAG, "open failed, %{public}s",               \
                strerror(errno));                                       \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \

#define FTRUNCATE_AND_CHECK(fd, size, ret, TAG)                         \
    do {                                                                \
        if (ftruncate(fd, size) == -1) {                                \
            DLP_LOG_ERROR(TAG, "ftruncate failed, %{public}s",          \
                strerror(errno));                                       \
            return ret;                                                 \
        }                                                               \
    } while (0)                                                         \


class DlpFile {
public:
    DlpFile(int32_t dlpFd, const std::string &realType);
    virtual ~DlpFile();

    int32_t SetCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec, const struct DlpBlob& hmacKey);
    void GetEncryptCert(struct DlpBlob& cert) const;
    void GetOfflineCert(struct DlpBlob& cert) const;
    bool GetOfflineAccess();
    bool UpdateDlpFilePermission();
    bool NeedAdapter();
    int32_t SetPolicy(const PermissionPolicy& policy);
    virtual int32_t UpdateCertAndText(const std::vector<uint8_t>& cert, struct DlpBlob certBlob) = 0;
    virtual int32_t SetEncryptCert(const struct DlpBlob& cert) = 0;
    virtual void SetOfflineAccess(bool flag, int32_t allowedOpenCount) = 0;
    virtual int32_t RemoveDlpPermission(int outPlainFileFd) = 0;
    virtual int32_t DlpFileRead(uint64_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid) = 0;
    virtual int32_t DlpFileWrite(uint64_t offset, void* buf, uint32_t size) = 0;
    virtual uint64_t GetFsContentSize() const = 0;
    virtual int32_t CheckDlpFile() = 0;
    virtual int32_t HmacCheck() = 0;
    virtual uint32_t GetOfflineCertSize(void) = 0;
    virtual int32_t SetContactAccount(const std::string& contactAccount) = 0;
    virtual int32_t Truncate(uint64_t size) = 0;
    virtual int32_t UpdateDlpFileContentSize() = 0;
    virtual int32_t GenFile(int32_t inPlainFileFd) = 0;
    virtual int32_t ProcessDlpFile() = 0;
    virtual int32_t DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
                                                uint64_t inFileLen, bool isEncrypt) = 0;

    void GetPolicy(PermissionPolicy& policy) const
    {
        policy.CopyPermissionPolicy(policy_);
    };

    void GetContactAccount(std::string& contactAccount) const
    {
        contactAccount = contactAccount_;
    };

    void SetLinkStatus()
    {
        isFuseLink_ = true;
    };

    void RemoveLinkStatus()
    {
        isFuseLink_ = false;
    };

    DLPFileAccess GetAuthPerm()
    {
        return authPerm_;
    };

    void SetAppId(std::string appId)
    {
        appId_ = appId;
    };

    void SetFileId(std::string fileId)
    {
        fileId_ = fileId;
    };

    void SetAccountType(int32_t accountType)
    {
        accountType_ = accountType;
    };

    int32_t GetAccountType()
    {
        return accountType_;
    };

    std::string GetAppId()
    {
        return appId_;
    };

    void GetFileId(std::string& fileId) const
    {
        fileId = fileId_;
    };

    void GetFileIdPlaintext(std::string& fileIdPlaintext) const
    {
        fileIdPlaintext = fileIdPlaintext_;
    };

    void GetRealType(std::string& realType) const
    {
        realType = realType_;
    };

    void SetAllowedOpenCount(int32_t allowedOpenCount)
    {
        allowedOpenCount_ = allowedOpenCount;
    };

    int32_t GetAllowedOpenCount()
    {
        return allowedOpenCount_;
    };

    int32_t dlpFd_;
    friend class DlpRawFile;
    friend class DlpZipFile;
private:
    virtual bool IsValidCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec,
        const struct DlpBlob& hmacKey) const;
    virtual int32_t CopyBlobParam(const struct DlpBlob& src, struct DlpBlob& dst) const;
    virtual int32_t CleanBlobParam(struct DlpBlob& blob) const;
    virtual int32_t PrepareBuff(struct DlpBlob& message1, struct DlpBlob& message2) const;
    virtual int32_t GetLocalAccountName(std::string& account) const;
    virtual int32_t GetDomainAccountName(std::string& account) const;
    virtual int32_t DupUsageSpec(struct DlpUsageSpec& spec);
    virtual int32_t DoDlpBlockCryptOperation(struct DlpBlob& message1,
        struct DlpBlob& message2, uint64_t offset, bool isEncrypt);
    virtual int32_t WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size) = 0;
    virtual int32_t FillHoleData(uint64_t holeStart, uint64_t holeSize);
    virtual int32_t DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size) = 0;

    std::string realType_;
    bool isFuseLink_;
    DLPFileAccess authPerm_;
    int32_t encDataFd_;

    struct DlpBlob cert_;
    struct DlpBlob offlineCert_;
    struct DlpBlob hmac_;
    struct DlpCipher cipher_;
    std::string fileIdPlaintext_;
    // policy in certificate
    PermissionPolicy policy_;
    std::string contactAccount_;
    uint32_t version_;
    uint32_t offlineAccess_;
    std::string appId_;
    std::string fileId_;
    int32_t accountType_;
    int32_t allowedOpenCount_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_H */
