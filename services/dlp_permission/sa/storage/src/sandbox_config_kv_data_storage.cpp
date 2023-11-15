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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "SandboxConifgKvDataStorage"};
static const std::string APP_CONFIG_STORE_ID = "sandbox_app_config_info";
static const std::string KEY_SEPATATOR = "_";
}
SandboxConifgKvDataStorage::SandboxConifgKvDataStorage(const KvDataStorageOptions &options)
    : DlpKvDataStorage(APP_CONFIG_STORE_ID, options)
{}

SandboxConifgKvDataStorage::~SandboxConifgKvDataStorage()
{}

int32_t SandboxConifgKvDataStorage::GetSandboxConfigFromDataStorage(const int32_t userId, const std::string& bundleName, std::string& configInfo)
{
    std::string key;
    if(!generateKey(userId, bundleName, key)) {
        DLP_LOG_ERROR(LABEL,"generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t result = GetValueFromKvStore(key, configInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL,"failed to get config info by key, result %{public}d.", result);
    }

    return result;
}

int32_t SandboxConifgKvDataStorage::AddSandboxConfigIntoDataStorage(const int32_t userId, const std::string& bundleName,const std::string& configInfo)
{
    std::string key;
    if(!generateKey(userId, bundleName, key)) {
        DLP_LOG_ERROR(LABEL,"generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t result = AddValue(key, configInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL,"failed to add config info, result = %{public}d", result);
    }

    return result;
}

int32_t SandboxConifgKvDataStorage::SaveSandboxConfigIntoDataStorage(const int32_t userId, const std::string& bundleName,const std::string& configInfo)
{
    std::string key;
    if(!generateKey(userId, bundleName, key)) {
        DLP_LOG_ERROR(LABEL,"generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t result = SaveValue(key, configInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL,"failed to save config info, result = %{public}d", result);
    }

    return result;
}

int32_t SandboxConifgKvDataStorage::DeleteSandboxConfigFromDataStorage(const int32_t userId, const std::string& bundleName)
{
    std::string key;
    if(!generateKey(userId, bundleName, key)) {
        DLP_LOG_ERROR(LABEL,"generate key error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t ret = RemoveValueFromKvStore(key);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL,"RemoveValueFromKvStore failed! ret = %{public}d.", ret);
    }
    return ret;
}

bool SandboxConifgKvDataStorage::generateKey(const int32_t userId, const std::string& bundleName, std::string& key)
{
    if(bundleName.empty()) {
        DLP_LOG_ERROR(LABEL,"bundleName is empty");
        return false;
    }
    key = std::to_string(userId) + KEY_SEPATATOR + bundleName;
    return true;
}

void SandboxConifgKvDataStorage::SaveEntries(
    std::vector<OHOS::DistributedKv::Entry> allEntries, std::map<std::string, std::string> &infos)
{
    for (auto const &item : allEntries) {
        infos.emplace(item.key.ToString(), item.value.ToString());
    }
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
