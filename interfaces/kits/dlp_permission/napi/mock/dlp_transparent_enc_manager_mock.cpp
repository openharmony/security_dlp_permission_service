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

#include "dlp_transparent_enc_manager.h"

#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

DlpTransparentEncManager &DlpTransparentEncManager::GetInstance()
{
    static DlpTransparentEncManager instance;
    return instance;
}

DlpTransparentEncManager::~DlpTransparentEncManager()
{
    credentialServiceHandle_ = nullptr;
    ResetFunctionPointers();
}

void DlpTransparentEncManager::ResetFunctionPointers()
{
    setControlledAppListsFunc_ = nullptr;
    getControlledAppListsFunc_ = nullptr;
    freeControlledAppListsFunc_ = nullptr;
    processPluginCommandFunc_ = nullptr;
    freePluginCommandResultFunc_ = nullptr;
    getDockerPolicyFunc_ = nullptr;
    freeDockerPolicyFunc_ = nullptr;
}

int32_t DlpTransparentEncManager::LoadDlpCredentialService()
{
    return DLP_OK;
}

int32_t DlpTransparentEncManager::SetControlledAppLists(
    const std::vector<std::string> &appLists, int32_t userId, bool userIdSet)
{
    return DLP_OK;
}

int32_t DlpTransparentEncManager::GetControlledAppLists(std::vector<std::string> &appLists)
{
    return DLP_OK;
}

int32_t DlpTransparentEncManager::ProcessPluginCommand(
    int32_t code, const std::string &message, std::string &result)
{
    return DLP_OK;
}

int32_t DlpTransparentEncManager::GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy)
{
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS