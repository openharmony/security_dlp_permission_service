/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DLP_TRANSPARENT_ENC_MANAGER_H
#define DLP_TRANSPARENT_ENC_MANAGER_H

#include <string>
#include <vector>
#include "nocopyable.h"
#include "dlp_permission.h"

#pragma pack(push, 1)
struct DockerPolicyPayload {
    bool is_encrypted;
    bool need_sandbox;
    char bundle_name[256];
    char mime_type[128];
    uint32_t permission;
};
#pragma pack(pop)

namespace OHOS {
namespace Security {
namespace DlpPermission {

struct DockerPolicyInfo {
    bool isEncrypted = false;
    bool needSandbox = false;
    std::string bundleName;
    std::string mimeType;
    uint32_t permission = 0;
};

namespace TestMock {
int32_t GetMockGetDockerPolicyResult();
DockerPolicyInfo GetMockDockerPolicyInfo();
bool IsDockerPolicyInfoSet();
}  // namespace TestMock

class DlpTransparentEncManager {
public:
    static DlpTransparentEncManager &GetInstance()
    {
        static DlpTransparentEncManager instance;
        return instance;
    }
    int32_t GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy)
    {
        if (TestMock::GetMockGetDockerPolicyResult() != DLP_OK) {
            return TestMock::GetMockGetDockerPolicyResult();
        }
        if (TestMock::IsDockerPolicyInfoSet()) {
            policy = TestMock::GetMockDockerPolicyInfo();
        }
        return DLP_OK;
    }
    int32_t SetControlledAppLists(const std::vector<std::string> &appLists,
        int32_t userId, bool userIdSet)
    {
        return DLP_OK;
    }
    int32_t GetControlledAppLists(std::vector<std::string> &appLists)
    {
        return DLP_OK;
    }
    int32_t ProcessPluginCommand(int32_t code, const std::string &message,
        std::string &result)
    {
        return DLP_OK;
    }

private:
    DlpTransparentEncManager() = default;
    ~DlpTransparentEncManager() = default;
    DISALLOW_COPY_AND_MOVE(DlpTransparentEncManager);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_TRANSPARENT_ENC_MANAGER_H
