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

#ifndef DLP_KV_DATA_STORAGE_H
#define DLP_KV_DATA_STORAGE_H

#include <map>
#include <string>
#include "distributed_kv_data_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct KvDataStorageOptions {
    bool autoSync = false;
    DistributedKv::SecurityLevel securityLevel = DistributedKv::SecurityLevel::S1;
    OHOS::DistributedKv::Area area = OHOS::DistributedKv::EL1;
    std::string baseDir;
};

class DlpKvDataStorage {
public:
    DlpKvDataStorage() = delete;
    DlpKvDataStorage(const std::string &storeId, const KvDataStorageOptions &options);
    virtual ~DlpKvDataStorage();
    void TryTwice(const std::function<DistributedKv::Status()> &func) const;
    int32_t LoadAllData(std::map<std::string, std::string> &infos);
    int32_t AddOrUpdateValue(const std::string &key, const std::string &value);
    int DeleteKvStore();
    bool IsKeyExists(const std::string keyStr);
    int32_t PutValueToKvStore(const std::string &keyStr, const std::string &valueStr);
    int32_t GetValueFromKvStore(const std::string &keyStr, std::string &valueStr);
    int32_t RemoveValueFromKvStore(const std::string &keyStr);
    virtual void SaveEntries(std::vector<OHOS::DistributedKv::Entry> allEntries,
        std::map<std::string, std::string> &infos) = 0;

protected:
    OHOS::DistributedKv::Status GetEntries(
        std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const;
    OHOS::DistributedKv::Status GetKvStore();
    bool CheckKvStore();
    OHOS::DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
    OHOS::DistributedKv::AppId appId_;
    OHOS::DistributedKv::StoreId storeId_;
    KvDataStorageOptions options_;
    std::string baseDir_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_KV_DATA_STORAGE_H
