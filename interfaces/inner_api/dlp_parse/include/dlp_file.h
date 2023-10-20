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

#ifndef INTERFACES_INNER_API_DLP_FILE_H
#define INTERFACES_INNER_API_DLP_FILE_H

#include <string>
#include "dlp_crypt.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static constexpr uint32_t INVALID_FILE_SIZE = 0xffffffff;
static constexpr uint32_t DLP_BUFF_LEN = 4096;
static constexpr uint32_t IV_SIZE = 16;
static constexpr uint32_t DLP_FILE_MAGIC = 0x87f4922;
static constexpr uint32_t DLP_FUSE_MAX_BUFFLEN = (10 * 1024 * 1024); // 10M
static constexpr uint32_t DLP_BLOCK_SIZE = 16;
// dlp file only support 32bits size, apart from 10M max head size
static constexpr uint32_t DLP_MAX_CONTENT_SIZE = 0xffffffff - 0xA00000;
static constexpr uint32_t HOLE_BUFF_SIZE = 16 * 1024;
static constexpr uint32_t HOLE_BUFF_SMALL_SIZE = 1 * 1024;
static constexpr uint32_t MAX_HOLE_SIZE = 50 * 1024 * 1024; // 50M

enum DlpOperation {
    DLP_ENCRYPTION = 1,
    DLP_DECRYPTION = 2,
};

struct DlpCipher {
    struct DlpBlob encKey;
    struct DlpCipherParam tagIv;
    struct DlpUsageSpec usageSpec;
};

struct DlpHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t offlineAccess;
    uint32_t txtOffset;
    uint32_t txtSize;
    uint32_t certOffset;
    uint32_t certSize;
    uint32_t contactAccountOffset;
    uint32_t contactAccountSize;
    uint32_t offlineCertOffset;
    uint32_t offlineCertSize;
};

enum VALID_KEY_SIZE {
    DLP_KEY_LEN_128 = 16,
    DLP_KEY_LEN_192 = 24,
    DLP_KEY_LEN_256 = 32,
};

class DlpFile {
public:
    DlpFile(int32_t dlpFd);
    ~DlpFile();

    int32_t SetCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec);
    int32_t ParseDlpHeader();
    void GetEncryptCert(struct DlpBlob& cert) const;
    void GetOfflineCert(struct DlpBlob& cert) const;
    int32_t UpdateCertAndText(const std::vector<uint8_t>& cert, const std::string& workDir, struct DlpBlob certBlob);
    int32_t UpdateCert(struct DlpBlob certBlob);
    int32_t SetEncryptCert(const struct DlpBlob& cert);
    void SetOfflineAccess(bool flag);
    bool GetOfflineAccess();
    int32_t GenFile(int32_t inPlainFileFd);
    int32_t RemoveDlpPermission(int outPlainFileFd);
    int32_t DlpFileRead(uint32_t offset, void* buf, uint32_t size);
    int32_t DlpFileWrite(uint32_t offset, void* buf, uint32_t size);
    uint32_t GetFsContentSize() const;
    void UpdateDlpFilePermission();
    int32_t CheckDlpFile();
    bool NeedAdapter();
    int32_t SetPolicy(const PermissionPolicy& policy);
    void GetPolicy(PermissionPolicy& policy) const
    {
        policy.CopyPermissionPolicy(policy_);
    };

    int32_t SetContactAccount(const std::string& contactAccount);
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

    int32_t Truncate(uint32_t size);
    int32_t dlpFd_;

private:
    bool IsValidDlpHeader(const struct DlpHeader& head) const;
    bool IsValidPadding(uint32_t padding);
    bool IsValidCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec) const;
    int32_t CopyBlobParam(const struct DlpBlob& src, struct DlpBlob& dst) const;
    int32_t CleanBlobParam(struct DlpBlob& blob) const;
    int32_t UpdateFileCertData();
    int32_t PrepareBuff(struct DlpBlob& message1, struct DlpBlob& message2) const;
    int32_t GetLocalAccountName(std::string& account) const;
    int32_t GetDomainAccountName(std::string& account) const;
    int32_t DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint32_t inOffset,
        uint32_t inFileLen, bool isEncrypt);
    int32_t DoDlpContentCopyOperation(int32_t inFd, int32_t outFd, uint32_t inOffset, uint32_t inFileLen);
    int32_t WriteHeadAndCert(int tmpFile, const std::vector<uint8_t>& offlineCert);
    int32_t DupUsageSpec(struct DlpUsageSpec& spec);
    int32_t DoDlpBlockCryptOperation(struct DlpBlob& message1,
        struct DlpBlob& message2, uint32_t offset, bool isEncrypt);
    int32_t WriteFirstBlockData(uint32_t offset, void* buf, uint32_t size);
    int32_t FillHoleData(uint32_t holeStart, uint32_t holeSize);
    int32_t DoDlpFileWrite(uint32_t offset, void* buf, uint32_t size);
    int32_t UpdateDlpFileContentSize();
    int32_t UpdateFile(int tmpFile, const std::vector<uint8_t>& cert, uint32_t oldTxtOffset);
    int32_t GetTempFile(const std::string& workDir, int& tempFile, std::string& path);

    bool isFuseLink_;
    DLPFileAccess authPerm_;

    // dlp parse format
    struct DlpHeader head_;
    struct DlpBlob cert_;
    struct DlpBlob offlineCert_;
    struct DlpCipher cipher_;

    // policy in certificate
    PermissionPolicy policy_;
    std::string contactAccount_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_H */
