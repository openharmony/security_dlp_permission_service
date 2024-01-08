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

#ifndef DLP_PERMISSION_SERIALIZER_H
#define DLP_PERMISSION_SERIALIZER_H

#include <string>
#include <vector>
#include "dlp_credential_client.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using unordered_json = nlohmann::ordered_json;
class DlpPermissionSerializer {
public:
    static DlpPermissionSerializer& GetInstance();
    DlpPermissionSerializer() = default;
    virtual ~DlpPermissionSerializer() = default;

    int32_t SerializeDlpPermission(const PermissionPolicy& policy, unordered_json& permInfoJson);
    int32_t DeserializeDlpPermission(const unordered_json& permJson, PermissionPolicy& policy);

    int32_t SerializeEncPolicyData(const DLP_EncPolicyData& encData, unordered_json& encDataJson);
    int32_t DeserializeEncPolicyData(const unordered_json& encDataJson, DLP_EncPolicyData& encData,
        bool isNeedAdapter);
    int32_t DeserializeEncPolicyDataByFirstVersion(const unordered_json& encDataJson,
        const unordered_json& offlineEncDataJson, DLP_EncPolicyData& encData, std::string ownerAccountId);
private:
    bool DeserializeEveryoneInfo(const unordered_json& policyJson, PermissionPolicy& policy);
    int32_t DeserializeAuthUserInfo(const unordered_json& accountInfoJson, AuthUserInfo& userInfo);
    int32_t DeserializeAuthUserList(const unordered_json& authUsersJson, std::vector<AuthUserInfo>& userList);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERIALIZER_H
