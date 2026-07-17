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

#include "dlp_transparent_enc_mock.h"
#include <cstdlib>
#include <cstring>
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

DlpTransparentEncMock &DlpTransparentEncMock::GetInstance()
{
    static DlpTransparentEncMock instance;
    return instance;
}

int32_t DlpTransparentEncMock::SetControlledAppLists(int32_t userid, bool userIdSet,
                                                     const std::vector<std::string> &appLists)
{
    (void)userid;
    (void)userIdSet;
    controlledAppLists_ = appLists;
    return mockResult_;
}

int32_t DlpTransparentEncMock::GetControlledAppLists(std::vector<std::string> &appLists)
{
    appLists = controlledAppLists_;
    return mockResult_;
}

int32_t DlpTransparentEncMock::ProcessPluginCommand(int32_t code, const std::string &message, std::string &result)
{
    (void)code;
    (void)message;
    result = pluginCommandResult_;
    return mockResult_;
}

int32_t DlpTransparentEncMock::GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy)
{
    (void)fileUri;
    policy = dockerPolicyInfo_;
    return mockResult_;
}

void DlpTransparentEncMock::SetMockResult(int32_t result)
{
    mockResult_ = result;
}

void DlpTransparentEncMock::SetMockPluginCommandResult(const std::string &result)
{
    pluginCommandResult_ = result;
}

void DlpTransparentEncMock::SetMockControlledAppLists(const std::vector<std::string> &appLists)
{
    controlledAppLists_ = appLists;
}

void DlpTransparentEncMock::SetMockDockerPolicyInfo(const DockerPolicyInfo &policy)
{
    dockerPolicyInfo_ = policy;
}

extern "C" {
void MockSetResult(int32_t result)
{
    DlpTransparentEncMock::GetInstance().SetMockResult(result);
}

void MockSetControlledAppListsData(const char *const *appLists, uint32_t appListsLen)
{
    std::vector<std::string> apps;
    if (appLists != nullptr) {
        for (uint32_t i = 0; i < appListsLen; i++) {
            if (appLists[i] != nullptr) {
                apps.push_back(std::string(appLists[i]));
            }
        }
    }
    DlpTransparentEncMock::GetInstance().SetMockControlledAppLists(apps);
}

void MockSetPluginCommandResultData(const char *result)
{
    DlpTransparentEncMock::GetInstance().SetMockPluginCommandResult(
        result != nullptr ? std::string(result) : "");
}

void MockSetDockerPolicyInfoData(bool isEncrypted, bool needSandbox,
    const char *bundleName, uint32_t mimeType, uint32_t permission)
{
    DockerPolicyInfo info;
    info.isEncrypted = isEncrypted;
    info.needSandbox = needSandbox;
    info.bundleName = bundleName != nullptr ? std::string(bundleName) : "";
    info.mimeType = mimeType;
    info.permission = permission;
    DlpTransparentEncMock::GetInstance().SetMockDockerPolicyInfo(info);
}

void MockResetAllState()
{
    DlpTransparentEncMock::GetInstance().SetMockResult(0);
    DlpTransparentEncMock::GetInstance().SetMockControlledAppLists({});
    DlpTransparentEncMock::GetInstance().SetMockPluginCommandResult("");
    DockerPolicyInfo emptyInfo;
    DlpTransparentEncMock::GetInstance().SetMockDockerPolicyInfo(emptyInfo);
}

int32_t DLP_SetControlledAppLists(int32_t userid, bool userIdSet, const char *const *appLists, uint32_t appListsLen)
{
    if (appLists == nullptr || appListsLen == 0) {
        return -1;
    }
    std::vector<std::string> appListVec;
    for (uint32_t i = 0; i < appListsLen; i++) {
        if (appLists[i] != nullptr) {
            appListVec.push_back(std::string(appLists[i]));
        }
    }
    return DlpTransparentEncMock::GetInstance().SetControlledAppLists(userid, userIdSet, appListVec);
}

int32_t DLP_GetControlledAppLists(char ***appLists, uint32_t *appListsLen)
{
    if (appLists == nullptr || appListsLen == nullptr) {
        return -1;
    }

    std::vector<std::string> appListVec;
    int32_t ret = DlpTransparentEncMock::GetInstance().GetControlledAppLists(appListVec);
    if (ret != 0) {
        return ret;
    }

    if (appListVec.empty()) {
        *appLists = nullptr;
        *appListsLen = 0;
        return 0;
    }

    *appLists = static_cast<char **>(malloc(sizeof(char *) * appListVec.size()));
    if (*appLists == nullptr) {
        return -1;
    }

    for (size_t i = 0; i < appListVec.size(); i++) {
        (*appLists)[i] = strdup(appListVec[i].c_str());
        if ((*appLists)[i] == nullptr) {
            for (size_t j = 0; j < i; j++) {
                free((*appLists)[j]);
            }
            free(*appLists);
            *appLists = nullptr;
            return -1;
        }
    }
    *appListsLen = static_cast<uint32_t>(appListVec.size());

    return 0;
}

int32_t DLP_FreeControlledAppLists(char ***appLists, uint32_t *appListsLen)
{
    if (appLists == nullptr || appListsLen == nullptr || *appLists == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < *appListsLen; i++) {
        if ((*appLists)[i] != nullptr) {
            free((*appLists)[i]);
            (*appLists)[i] = nullptr;
        }
    }

    free(*appLists);
    *appLists = nullptr;
    *appListsLen = 0;

    return 0;
}

int32_t DLP_ProcessPluginCommand(int32_t code, const char *message, char **result, uint32_t *resultLen)
{
    if (message == nullptr || result == nullptr || resultLen == nullptr) {
        return -1;
    }

    std::string resultStr;
    int32_t ret = DlpTransparentEncMock::GetInstance().ProcessPluginCommand(code, std::string(message), resultStr);
    if (ret != 0) {
        return ret;
    }

    if (resultStr.empty()) {
        *result = nullptr;
        *resultLen = 0;
        return 0;
    }

    *result = strdup(resultStr.c_str());
    if (*result == nullptr) {
        return -1;
    }
    *resultLen = static_cast<uint32_t>(resultStr.size());

    return 0;
}

int32_t DLP_FreePluginCommandResult(char **result, uint32_t *resultLen)
{
    if (result == nullptr || resultLen == nullptr || *result == nullptr) {
        return -1;
    }

    free(*result);
    *result = nullptr;
    *resultLen = 0;

    return 0;
}

int32_t DLP_GetDockerPolicy(const char *fileUri, DockerPolicyPayload **policy)
{
    if (fileUri == nullptr || policy == nullptr) {
        return -1;
    }

    DockerPolicyInfo policyInfo;
    int32_t ret = DlpTransparentEncMock::GetInstance().GetDockerPolicy(std::string(fileUri), policyInfo);
    if (ret != 0) {
        return ret;
    }

    *policy = static_cast<DockerPolicyPayload *>(malloc(sizeof(DockerPolicyPayload)));
    if (*policy == nullptr) {
        return -1;
    }

    (*policy)->is_encrypted = policyInfo.isEncrypted;
    (*policy)->need_sandbox = policyInfo.needSandbox;
    (*policy)->mime_type = policyInfo.mimeType;
    (*policy)->permission = policyInfo.permission;
    if (policyInfo.bundleName.size() >= sizeof((*policy)->bundle_name)) {
        free(*policy);
        *policy = nullptr;
        return -1;
    }

    if (strcpy_s((*policy)->bundle_name, sizeof((*policy)->bundle_name), policyInfo.bundleName.c_str()) != EOK) {
        free(*policy);
        *policy = nullptr;
        return -1;
    }

    return 0;
}

int32_t DLP_FreeDockerPolicy(DockerPolicyPayload **policy)
{
    if (policy == nullptr || *policy == nullptr) {
        return -1;
    }

    free(*policy);
    *policy = nullptr;

    return 0;
}
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS