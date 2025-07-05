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

#ifndef INTERFACES_INNER_API_DLP_ZIP_FILE_H
#define INTERFACES_INNER_API_DLP_ZIP_FILE_H

#include "dlp_file.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class DlpZipFile : public DlpFile {
public:
    DlpZipFile(int32_t dlpFd, const std::string &workDir, int64_t index, const std::string &realType);
    ~DlpZipFile();
    int32_t UpdateCertAndText(const std::vector<uint8_t>& cert, struct DlpBlob certBlob);
    int32_t SetEncryptCert(const struct DlpBlob& cert);
    int32_t GenFile(int32_t inPlainFileFd);
    int32_t RemoveDlpPermission(int outPlainFileFd);
    int32_t DlpFileRead(uint64_t offset, void* buf, uint32_t size, bool& hasRead, int32_t uid);
    int32_t DlpFileWrite(uint64_t offset, void* buf, uint32_t size);
    uint64_t GetFsContentSize() const;
    int32_t CheckDlpFile();
    void SetOfflineAccess(bool flag);
    bool CleanTmpFile();
    int32_t HmacCheck();
    uint32_t GetOfflineCertSize(void);
    int32_t ProcessDlpFile();
    int32_t SetContactAccount(const std::string& contactAccount);
    int32_t Truncate(uint64_t size);
    int32_t DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset,
                                                uint64_t inFileLen, bool isEncrypt);
private:
    int32_t DoDlpContentCopyOperation(int32_t inFd, int32_t outFd, uint64_t inOffset, uint64_t inFileLen);
    int32_t UpdateDlpFileContentSize();
    bool ParseDlpInfo();
    bool ParseCert();
    bool ParseEncData();
    int32_t GenEncData(int32_t inPlainFileFd);
    int32_t GenFileInZip(int32_t inPlainFileFd);
    int32_t RemoveDlpPermissionInZip(int32_t outPlainFileFd);
    int32_t GetHmacVal(int32_t encFile, std::string& hmacStr);
    int32_t GenerateHmacVal(int32_t encFile, struct DlpBlob& out);
    int32_t AddGeneralInfoToBuff(int32_t encFile);
    int32_t DoDlpFileWrite(uint64_t offset, void* buf, uint32_t size);
    int32_t WriteFirstBlockData(uint64_t offset, void* buf, uint32_t size);
    std::string workDir_ = "";
    std::string dirIndex_;
    uint32_t certSize_;
    std::vector<std::string> extraInfo_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_ZIP_FILE_H */
