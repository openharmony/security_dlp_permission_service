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
#include <mutex>

#include "nocopyable.h"

#pragma pack(push, 1)
struct DockerPolicyPayload {
    bool is_encrypted;
    bool need_sandbox;
    char bundle_name[256];
    uint32_t mime_type;
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
    uint32_t mimeType = 0;
    uint32_t permission = 0;
};

class DlpTransparentEncManager {
public:
    static DlpTransparentEncManager &GetInstance();
    int32_t SetControlledAppLists(const std::vector<std::string> &appLists, int32_t userId, bool userIdSet);
    int32_t GetControlledAppLists(std::vector<std::string> &appLists);
    int32_t ProcessPluginCommand(int32_t code, const std::string &message, std::string &result);
    int32_t GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy);

private:
    DlpTransparentEncManager() = default;
    ~DlpTransparentEncManager();
    DISALLOW_COPY_AND_MOVE(DlpTransparentEncManager);
    int32_t LoadDlpCredentialService();
    void ResetFunctionPointers();
    template<typename FuncType>
    int32_t ResolveSymbol(FuncType &funcPtr, const char *symbol);
    void *credentialServiceHandle_ = nullptr;

    typedef int32_t (*SetControlledAppLists_Func)(int32_t userid, bool userIdSet, const char *const *appLists,
                                                  uint32_t appListsLen);
    typedef int32_t (*GetControlledAppLists_Func)(char ***appLists, uint32_t *appListsLen);
    typedef int32_t (*FreeControlledAppLists_Func)(char ***appLists, uint32_t *appListsLen);
    typedef int32_t (*ProcessPluginCommand_Func)(int32_t code, const char *message, char **result,
                                                  uint32_t *resultLen);
    typedef int32_t (*FreePluginCommandResult_Func)(char **result, uint32_t *resultLen);
    typedef int32_t (*GetDockerPolicy_Func)(const char *fileUri, DockerPolicyPayload **policy);
    typedef int32_t (*FreeDockerPolicy_Func)(DockerPolicyPayload **policy);
    SetControlledAppLists_Func setControlledAppListsFunc_ = nullptr;
    GetControlledAppLists_Func getControlledAppListsFunc_ = nullptr;
    FreeControlledAppLists_Func freeControlledAppListsFunc_ = nullptr;
    ProcessPluginCommand_Func processPluginCommandFunc_ = nullptr;
    FreePluginCommandResult_Func freePluginCommandResultFunc_ = nullptr;
    GetDockerPolicy_Func getDockerPolicyFunc_ = nullptr;
    FreeDockerPolicy_Func freeDockerPolicyFunc_ = nullptr;
    std::mutex mutex_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif /*  DLP_TRANSPARENT_ENC_MANAGER_H */