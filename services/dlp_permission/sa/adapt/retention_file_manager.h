/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RETENTION_FILE_MANAGER_H
#define RETENTION_FILE_MANAGER_H

#include <mutex>
#include <map>

#include "file_operator.h"
#include "nlohmann/json.hpp"
#include "sandbox_json_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Json = nlohmann::json;

class RetentionFileManager {
public:
    explicit RetentionFileManager();
    virtual ~RetentionFileManager();
    static RetentionFileManager& GetInstance();

    int32_t AddSandboxInfo(const int32_t& appIndex, const uint32_t& tokenId, const std::string& bundleName,
        const int32_t& userId);
    int32_t DelSandboxInfo(uint32_t tokenId);
    bool CanUninstall(const uint32_t& tokenId);
    int32_t UpdateSandboxInfo(const std::set<std::string>& docUriSet, RetentionInfo& info, bool isRetention);
    int32_t RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex);
    int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention);
    bool HasRetentionSandboxInfo(const std::string& bundleName);
    int32_t ClearUnreservedSandbox();
    int32_t GetBundleNameSetByUserId(const int32_t userId, std::set<std::string>& bundleNameSet);
    int32_t RemoveRetentionInfoByUserId(const int32_t userId, const std::set<std::string>& bundleNameSet);
private:
    bool Init();
    int32_t UpdateFile(const int32_t& jsonRes);
    bool hasInit;
    std::shared_ptr<FileOperator> fileOperator_;
    std::recursive_mutex mutex_;
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // RETENTION_FILE_MANAGER_H