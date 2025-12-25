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

#ifndef INTERFACES_INNER_API_DLP_RAW_FILE_H
#define INTERFACES_INNER_API_DLP_RAW_FILE_H

#include "dlp_file.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class DlpRawFile : public DlpFile {
public:
    DlpRawFile(int32_t dlpFd, const std::string &realType);
    ~DlpRawFile();
    int32_t UpdateCertAndText(const std::vector<uint8_t>& cert, struct DlpBlob certBlob);
    int32_t SetEncryptCert(const struct DlpBlob& cert);
    int32_t GenFile(int32_t inPlainFileFd);
    int32_t RemoveDlpPermission(int outPlainFileFd);
    int32_t DlpFileRead(uint64_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid);
    int32_t DlpFileWrite(uint64_t offset, void* buf, uint32_t size);

    uint64_t GetFsContentSize() const;
    void SetOfflineAccess(bool flag, int32_t allowedOpenCount);
    int32_t ParseRawDlpHeader(uint64_t fileLen, uint32_t dlpHeaderSize);
    int32_t ParseEnterpriseFileId(uint64_t fileLen, uint32_t fileIdSize);
    int32_t ParseEnterpriseRawDlpHeader(uint64_t fileLen, uint32_t dlpHeaderSize);
    int32_t CheckDlpFile();
    int32_t HmacCheck();
    uint32_t GetOfflineCertSize(void);
    int32_t DoWriteHeaderAndContactAccount(int32_t inPlainFileFd, uint64_t fileLen);
    int32_t ProcessDlpFile();
    int32_t SetContactAccount(const std::string& contactAccount);
    int32_t Truncate(uint64_t size);
    int32_t setAlgType(int32_t inPlainFileFd, const std::string& realFileType);
    int32_t DoDlpHIAECryptOperation(struct DlpBlob& message1, struct DlpBlob& message2,
        uint64_t offset, bool isEncrypt);
    int32_t DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
                                                uint64_t inFileLen, bool isEncrypt);

private:
    bool IsValidEnterpriseDlpHeader(const struct DlpHeader& head, uint32_t dlpHeaderSize);
    bool IsValidDlpHeader(const struct DlpHeader& head) const;
    int32_t UpdateDlpFileContentSize();
    int32_t GetRawDlpHmac(void);
    int32_t DoWriteHmacAndCert(uint32_t hmacStrLen, std::string& hmacStr);
    int32_t DoHmacAndCrypty(int32_t inPlainFileFd, off_t fileLen);
    int32_t GenFileInRaw(int32_t inPlainFileFd);
    int32_t RemoveDlpPermissionInRaw(int32_t outPlainFileFd);
    int32_t DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size);
    int32_t WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size);
    int32_t WriteHmacProcess(void);
    int32_t WriteFileIdPlaintextProcess(void);
    int32_t WriteRawFileProperty();

    struct DlpHeader head_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_RAW_FILE_H */
