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

#include "sandbox_config_kv_data_storage.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
    "SandboxConfigKvDataStorage"};
static const std::string APP_CONFIG_STORE_ID = "sandbox_app_config_info";
static const std::string KEY_SEPATATOR = "_";
}

SandboxConfigKvDataStorage& SandboxConfigKvDataStorage::GetInstance()
{
    KvDataStorageOptions options = { .autoSync = false };
    static SandboxConfigKvDataStorage *instance = new (std::nothrow) SandboxConfigKvDataStorage(options);
    return *instance;
}

SandboxConfigKvDataStorage::SandboxConfigKvDataStorage(const KvDataStorageOptions &options)
    : DlpKvDataStorage(APP_CONFIG_STORE_ID, options)
{}

SandboxConfigKvDataStorage::~SandboxConfigKvDataStorage()
{}

int32_t SandboxConfigKvDataStorage::GetSandboxConfigFromDataStorage(const int32_t userId, const std::string& bundleName,
    std::string& configInfo)
{
    std::string key;
    bool res = GenerateKey(userId, bundleName, key);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    res = IsKeyExists(key);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "the key not exists.");
        return DLP_KV_GET_DATA_NOT_FOUND;
    }
    int32_t result = GetValueFromKvStore(key, configInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "failed to get config info by key, result %{public}d.", result);
    }
    return result;
}

int32_t SandboxConfigKvDataStorage::AddSandboxConfigIntoDataStorage(const int32_t userId, const std::string& bundleName,
    const std::string& configInfo)
{
    std::string key;
    bool res = GenerateKey(userId, bundleName, key);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t result = AddOrUpdateValue(key, configInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "failed to add config info, result = %{public}d", result);
    }
    return result;
}

int32_t SandboxConfigKvDataStorage::DeleteSandboxConfigFromDataStorage(const int32_t userId,
    const std::string& bundleName)
{
    std::string key;
    bool res = GenerateKey(userId, bundleName, key);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    res = IsKeyExists(key);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "the key not exists.");
        return DLP_OK;
    }
    int32_t ret = RemoveValueFromKvStore(key);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RemoveValueFromKvStore failed! ret = %{public}d.", ret);
    }
    return ret;
}

bool SandboxConfigKvDataStorage::GenerateKey(const int32_t userId, const std::string& bundleName, std::string& key)
{
    if (bundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "bundleName is empty");
        return false;
    }
    key = std::to_string(userId) + KEY_SEPATATOR + bundleName;
    return true;
}

int32_t SandboxConfigKvDataStorage::GetKeySetByUserId(const int32_t userId, std::set<std::string>& bundleNameSet)
{
    std::map<std::string, std::string> infos;
    int32_t res = LoadAllData(infos);
    if (res != DLP_OK) {
        return res;
    }
    for (auto it = infos.begin(); it != infos.end(); ++it) {
        std::string prefix = std::to_string(userId) + KEY_SEPATATOR;
        if (it->first.find(prefix) != std::string::npos) {
            std::string bundleName = it->first.substr(prefix.length(), it->first.length());
            bundleNameSet.emplace(bundleName);
        }
    }
    return DLP_OK;
}

void SandboxConfigKvDataStorage::SaveEntries(
    std::vector<OHOS::DistributedKv::Entry> allEntries, std::map<std::string, std::string> &infos)
{
    DLP_LOG_DEBUG(LABEL, "start, allEntries size is: %{public}zu", allEntries.size());
    for (auto const &item : allEntries) {
        infos.emplace(item.key.ToString(), item.value.ToString());
    }
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
