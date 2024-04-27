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

#ifndef SANDBOX_JSON_MANAGER_H
#define SANDBOX_JSON_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "bundle_mgr_interface.h"
#include "i_json_operator.h"
#include "nlohmann/json.hpp"
#include "parcel.h"
#include "retention_sandbox_info.h"
#include "safe_map.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct RetentionInfo {
    int32_t appIndex = -1;
    uint32_t tokenId = 0;
    std::string bundleName = "";
    std::set<std::string> docUriSet;
    int32_t userId = -1;
};

class SandboxJsonManager : public IJsonOperator {
public:
    SandboxJsonManager();
    ~SandboxJsonManager();

    int32_t AddSandboxInfo(const int32_t& appIndex, const uint32_t& tokenId, const std::string& bundleName,
        const int32_t& userId);
    int32_t DelSandboxInfo(const uint32_t& tokenId);
    bool CanUninstall(const uint32_t& tokenId);
    int32_t UpdateRetentionState(const std::set<std::string>& docUriSet, RetentionInfo& info, bool isRetention);

    int32_t RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex);
    bool HasRetentionSandboxInfo(const std::string& bundleName);
    int32_t GetRetentionSandboxList(const std::string& bundleName,
        std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention);
    void RetentionInfoToJson(Json& json, const RetentionInfo& info) const;
    int32_t ClearUnreservedSandbox();
    Json ToJson() const override;
    void FromJson(const Json& jsonObject) override;
    std::string ToString() const override;
    int32_t GetBundleNameSetByUserId(const int32_t userId, std::set<std::string>& bundleNameSet);
    int32_t RemoveRetentionInfoByUserId(const int32_t userId, const std::set<std::string>& bundleNameSet);

private:
    bool InsertSandboxInfo(const std::set<std::string>& docUriSet, uint32_t tokenId, const std::string& bundleName,
        int32_t appIndex, int32_t userId);
    sptr<AppExecFwk::IBundleMgr> GetBundleMgr();
    bool GetUserIdByUid(int32_t& userId);
    bool CheckReInstall(const RetentionInfo& info, const int32_t userId);
    static bool CompareByTokenId(const RetentionInfo& info1, const RetentionInfo& info2);
    static bool CompareByBundleName(const RetentionInfo& info1, const RetentionInfo& info2);
    static bool UpdateDocUriSetByUnion(RetentionInfo& info, const std::set<std::string>& newSet);
    static bool UpdateDocUriSetByDifference(RetentionInfo& info, const std::set<std::string>& newSet);
    int32_t UpdateRetentionState(const std::set<std::string>& newSet, const RetentionInfo& info,
        bool (*compare)(const RetentionInfo& info1, const RetentionInfo& info2),
        bool (*update)(RetentionInfo& info, const std::set<std::string>& newSet));
    mutable std::mutex mutex_;
    std::vector<RetentionInfo> infoVec_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // SANDBOX_JSON_MANAGER_H
