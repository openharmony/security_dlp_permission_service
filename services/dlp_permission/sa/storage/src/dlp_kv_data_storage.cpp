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

#include "dlp_kv_data_storage.h"
#include <unistd.h>
#include "dlp_permission_log.h"
#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpKvDataStorage"};
static const int32_t MAX_TIMES = 10;
static const int32_t SLEEP_INTERVAL = 100 * 1000;
static const std::string KV_STORE_EL1_BASE_DIR = "/data/service/el1/public/database/";
static const std::string KV_STORE_EL2_BASE_DIR = "/data/service/el2/public/database/";
static const std::string DLP_KV_APP_ID = "dlp_permission_service_storage";

DlpKvDataStorage::DlpKvDataStorage(const std::string &storeId,
    const KvDataStorageOptions &options)
{
    appId_.appId = DLP_KV_APP_ID;
    storeId_.storeId = storeId;
    options_ = options;
    if (options_.area == DistributedKv::EL1) {
        baseDir_ = KV_STORE_EL1_BASE_DIR + DLP_KV_APP_ID;
    } else {
        baseDir_ = KV_STORE_EL2_BASE_DIR + DLP_KV_APP_ID;
    }
}

DlpKvDataStorage::~DlpKvDataStorage()
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
    }
}

void DlpKvDataStorage::TryTwice(const std::function<DistributedKv::Status()> &func) const
{
    OHOS::DistributedKv::Status status = func();
    if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
        status = func();
        DLP_LOG_ERROR(LABEL, "distribute database ipc error and try again, status = %{public}d", status);
    }
}

int32_t DlpKvDataStorage::LoadAllData(std::map<std::string, std::string> &infos)
{
    bool res = CheckKvStore();
    if (!res) {
        DLP_LOG_ERROR(LABEL, "kvStore is nullptr");
        return DLP_COMMON_CHECK_KVSTORE_ERROR;
    }
    OHOS::DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    std::vector<OHOS::DistributedKv::Entry> allEntries;
    TryTwice([this, &status, &allEntries] {
        status = GetEntries("", allEntries);
        return status;
    });
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        DLP_LOG_ERROR(LABEL, "get entries error: %{public}d", status);
        return DLP_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    infos.clear();
    SaveEntries(allEntries, infos);
    return ERR_OK;
}

OHOS::DistributedKv::Status DlpKvDataStorage::GetKvStore()
{
    OHOS::DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = options_.autoSync,
        .syncable = options_.autoSync,
        .securityLevel = options_.securityLevel,
        .area = options_.area,
        .kvStoreType = OHOS::DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = baseDir_,
    };
    OHOS::DistributedKv::Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    bool res = (status != OHOS::DistributedKv::Status::SUCCESS) || (kvStorePtr_ == nullptr);
    if (res) {
        DLP_LOG_ERROR(LABEL, "GetSingleKvStore failed! status %{public}d, kvStorePtr_ is nullptr", status);
        return status;
    }
    return status;
}

bool DlpKvDataStorage::CheckKvStore()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    OHOS::DistributedKv::Status status = OHOS::DistributedKv::Status::SUCCESS;
    while (tryTimes > 0) {
        status = GetKvStore();
        bool res = (status == OHOS::DistributedKv::Status::SUCCESS) && (kvStorePtr_ != nullptr);
        if (res) {
            return true;
        }
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }
    return false;
}

int32_t DlpKvDataStorage::AddOrUpdateValue(const std::string &key, const std::string &value)
{
    if (key.empty() || value.empty()) {
        DLP_LOG_ERROR(LABEL, "param is empty!");
        return DLP_KV_DATE_INFO_EMPTY_ERROR;
    }
    return PutValueToKvStore(key, value);
}

int32_t DlpKvDataStorage::RemoveValueFromKvStore(const std::string &keyStr)
{
    bool res = CheckKvStore();
    if (!res) {
        DLP_LOG_ERROR(LABEL, "kvStore is nullptr");
        return DLP_COMMON_CHECK_KVSTORE_ERROR;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Status status;
    OHOS::DistributedKv::Value value;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        // check exist
        status = kvStorePtr_->Get(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            DLP_LOG_ERROR(LABEL, "kvstore ipc error and try again, status = %{public}d", status);
            status = kvStorePtr_->Get(key, value);
        }
        if (status != OHOS::DistributedKv::Status::SUCCESS) {
            DLP_LOG_INFO(LABEL, "key does not exist in kvStore.");
            return DLP_OK;
        }
        // delete
        status = kvStorePtr_->Delete(key);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Delete(key);
            DLP_LOG_ERROR(LABEL, "kvstore ipc error and try to call again, status = %{public}d", status);
        }
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        DLP_LOG_ERROR(LABEL, "delete key from kvstore failed, status %{public}d.", status);
        return DLP_COMMON_DELETE_KEY_FROM_KVSTORE_ERROR;
    }
    DLP_LOG_DEBUG(LABEL, "delete key from kvStore succeed!");
    return DLP_OK;
}

int32_t DlpKvDataStorage::DeleteKvStore()
{
    bool res = CheckKvStore();
    if (!res) {
        DLP_LOG_ERROR(LABEL, "kvStore is nullptr");
        return DLP_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        dataManager_.CloseKvStore(this->appId_, this->storeId_);
        kvStorePtr_ = nullptr;
        status = dataManager_.DeleteKvStore(this->appId_, this->storeId_, baseDir_);
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        DLP_LOG_ERROR(LABEL, "error, status = %{public}d", status);
        return DLP_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    return DLP_OK;
}

int32_t DlpKvDataStorage::PutValueToKvStore(const std::string &keyStr, const std::string &valueStr)
{
    bool res = CheckKvStore();
    if (!res) {
        DLP_LOG_ERROR(LABEL, "kvStore is nullptr");
        return DLP_COMMON_CHECK_KVSTORE_ERROR;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value(valueStr);
    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Put(key, value);
        }
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        DLP_LOG_ERROR(LABEL, "put value to kvStore error, status = %{public}d", status);
        return DLP_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    return DLP_OK;
}

int32_t DlpKvDataStorage::GetValueFromKvStore(const std::string &keyStr, std::string &valueStr)
{
    bool res = CheckKvStore();
    if (!res) {
        DLP_LOG_ERROR(LABEL, "kvStore is nullptr");
        return DLP_COMMON_CHECK_KVSTORE_ERROR;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Get(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            DLP_LOG_ERROR(LABEL, "kvstore ipc error and try again, status = %{public}d", status);
            status = kvStorePtr_->Get(key, value);
        }
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        DLP_LOG_ERROR(LABEL, "get value from kvstore error, status %{public}d.", status);
        return DLP_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    valueStr = value.ToString();
    return DLP_OK;
}

OHOS::DistributedKv::Status DlpKvDataStorage::GetEntries(
    std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const
{
    OHOS::DistributedKv::Key allEntryKeyPrefix(subId);
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    OHOS::DistributedKv::Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    return status;
}

bool DlpKvDataStorage::IsKeyExists(const std::string keyStr)
{
    if (keyStr.empty()) {
        DLP_LOG_ERROR(LABEL, "param is empty!");
        return false;
    }
    std::string valueStr;
    bool res = GetValueFromKvStore(keyStr, valueStr) != DLP_OK;
    if (res) {
        return false;
    }
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
