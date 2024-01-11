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

#ifndef INTERFACES_INNER_API_DLP_FILE_MANAGER_H
#define INTERFACES_INNER_API_DLP_FILE_MANAGER_H

#include <atomic>
#include <mutex>
#include <unordered_map>
#include <string>
#include "dlp_crypt.h"
#include "dlp_file.h"
#include "permission_policy.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpFileManager final {
public:
    static DlpFileManager& GetInstance();
    ~DlpFileManager() {};

    int32_t GenerateDlpFile(
        int32_t plainFileFd, int32_t dlpFileFd, const DlpProperty& property, std::shared_ptr<DlpFile>& filePtr,
        const std::string& workDir);
    int32_t OpenDlpFile(int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr, const std::string& workDir,
        const std::string& appId);
    int32_t CloseDlpFile(const std::shared_ptr<DlpFile>& dlpFile);
    int32_t RecoverDlpFile(std::shared_ptr<DlpFile>& file, int32_t plainFd) const;

private:
    DlpFileManager() {};
    DISALLOW_COPY_AND_MOVE(DlpFileManager);

    int32_t AddDlpFileNode(const std::shared_ptr<DlpFile>& filePtr);
    int32_t RemoveDlpFileNode(const std::shared_ptr<DlpFile>& filePtr);
    std::shared_ptr<DlpFile> GetDlpFile(int32_t dlpFd);
    int32_t GenerateCertData(const PermissionPolicy& policy, struct DlpBlob& certData) const;
    int32_t GenerateCertBlob(const std::vector<uint8_t>& cert, struct DlpBlob& certData) const;
    int32_t UpdateDlpFile(bool isNeedAdapter, uint32_t oldCertSize, const std::string& workDir,
        const std::vector<uint8_t>& cert, std::shared_ptr<DlpFile>& filePtr);
    int32_t PrepareDlpEncryptParms(PermissionPolicy& policy, struct DlpBlob& key,
        struct DlpUsageSpec& usage, struct DlpBlob& certData, struct DlpBlob& hmacKey) const;
    int32_t ParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr, const std::string& workDir, const std::string& appId);
    void FreeChiperBlob(struct DlpBlob& key, struct DlpBlob& certData,
        struct DlpUsageSpec& usage, struct DlpBlob& hmacKey) const;
    void CleanTempBlob(struct DlpBlob& key, struct DlpCipherParam* tagIv, struct DlpBlob& hmacKey) const;
    int32_t SetDlpFileParams(std::shared_ptr<DlpFile>& filePtr, const DlpProperty& property) const;
    std::mutex g_offlineLock_;
    OHOS::Utils::RWLock g_DlpMapLock_;
    std::atomic<int> index_ = 0;
    std::unordered_map<int32_t, std::shared_ptr<DlpFile>> g_DlpFileMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_MANAGER_H */
