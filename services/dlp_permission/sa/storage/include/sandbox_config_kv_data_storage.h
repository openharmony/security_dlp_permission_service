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

#ifndef SANDBOX_CONFIG_KV_DATA_STORAGE_H
#define SANDBOX_CONFIG_KV_DATA_STORAGE_H

#include "dlp_kv_data_storage.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
typedef enum SandboxConfigOperationEnum : uint8_t {
    ADD,
    GET,
    CLEAN,
} SandboxConfigOperationEnum;

class SandboxConfigKvDataStorage  : public DlpKvDataStorage {
public:
    static SandboxConfigKvDataStorage& GetInstance();
    int32_t GetSandboxConfigFromDataStorage(int32_t userId, const std::string& bundleName,
        std::string& configInfo, const std::string tokenId);
    int32_t AddSandboxConfigIntoDataStorage(int32_t userId, const std::string& bundleName,
        const std::string& configInfo, const std::string tokenId);
    int32_t DeleteSandboxConfigFromDataStorage(int32_t userId, const std::string& bundleName,
        const std::string tokenId);
    int32_t GetKeyMapByUserId(int32_t userId, std::map<std::string, std::string>& keyMap);
    void SaveEntries(const std::vector<OHOS::DistributedKv::Entry>& allEntries,
        std::map<std::string, std::string>& infos) override;
private:
    SandboxConfigKvDataStorage() = delete;
    SandboxConfigKvDataStorage(const KvDataStorageOptions& options);
    ~SandboxConfigKvDataStorage() override;
    bool GenerateKey(int32_t userId, const std::string& bundleName, std::string& key, const std::string tokenId);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // SANDBOX_CONFIG_KV_DATA_STORAGE_H
