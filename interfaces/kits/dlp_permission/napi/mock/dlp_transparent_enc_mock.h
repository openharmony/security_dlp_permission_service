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

#ifndef DLP_TRANSPARENT_ENC_MOCK_H
#define DLP_TRANSPARENT_ENC_MOCK_H

#include <cstdint>
#include <string>
#include <vector>

#include "dlp_transparent_enc_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

extern "C" {
int32_t DLP_SetControlledAppLists(int32_t userid, bool userIdSet, const char *const *appLists, uint32_t appListsLen);
int32_t DLP_GetControlledAppLists(char ***appLists, uint32_t *appListsLen);
int32_t DLP_FreeControlledAppLists(char ***appLists, uint32_t *appListsLen);
int32_t DLP_ProcessPluginCommand(int32_t code, const char *message, char **result, uint32_t *resultLen);
int32_t DLP_FreePluginCommandResult(char **result, uint32_t *resultLen);
int32_t DLP_GetDockerPolicy(const char *fileUri, DockerPolicyPayload **policy);
int32_t DLP_FreeDockerPolicy(DockerPolicyPayload **policy);
}

class DlpTransparentEncMock {
public:
    static DlpTransparentEncMock &GetInstance();
    int32_t SetControlledAppLists(int32_t userid, bool userIdSet, const std::vector<std::string> &appLists);
    int32_t GetControlledAppLists(std::vector<std::string> &appLists);
    int32_t ProcessPluginCommand(int32_t code, const std::string &message, std::string &result);
    int32_t GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy);
    void SetMockResult(int32_t result);
    void SetMockPluginCommandResult(const std::string &result);
    void SetMockControlledAppLists(const std::vector<std::string> &appLists);
    void SetMockDockerPolicyInfo(const DockerPolicyInfo &policy);

private:
    DlpTransparentEncMock() = default;
    ~DlpTransparentEncMock() = default;

    int32_t mockResult_ = 0;
    std::vector<std::string> controlledAppLists_;
    std::string pluginCommandResult_;
    DockerPolicyInfo dockerPolicyInfo_;
};

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // DLP_TRANSPARENT_ENC_MOCK_H