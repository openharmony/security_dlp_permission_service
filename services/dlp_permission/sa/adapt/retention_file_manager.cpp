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

#include "retention_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "RetentionFileManager" };
const std::string PATH_SEPARATOR = "/";
const std::string USER_INFO_BASE = "/data/service/el1/public/dlp_permission_service";
const std::string DLP_RETENTION_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "retention_sandbox_info.json";
}

RetentionFileManager::RetentionFileManager()
    : hasInit(false),
      fileOperator_(std::make_shared<FileOperator>()),
      sandboxJsonManager_(std::make_shared<SandboxJsonManager>())
{
    Init();
}

RetentionFileManager::~RetentionFileManager() {}

RetentionFileManager& RetentionFileManager::GetInstance()
{
    static RetentionFileManager instance;
    return instance;
}

bool RetentionFileManager::HasRetentionSandboxInfo(const std::string& bundleName)
{
    return sandboxJsonManager_->HasRetentionSandboxInfo(bundleName);
}

bool RetentionFileManager::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (fileOperator_->IsExistFile(DLP_RETENTION_JSON_PATH)) {
        std::string constraintsConfigStr;
        if (fileOperator_->GetFileContentByPath(DLP_RETENTION_JSON_PATH, constraintsConfigStr) != DLP_OK) {
            return false;
        }
        if (constraintsConfigStr.empty()) {
            hasInit = true;
            return true;
        }
        Json callbackInfoJson = Json::parse(constraintsConfigStr, nullptr, false);
        if (callbackInfoJson.is_discarded()) {
            DLP_LOG_ERROR(LABEL, "callbackInfoJson is discarded");
            return false;
        }
        sandboxJsonManager_->FromJson(callbackInfoJson);
    } else {
        if (fileOperator_->InputFileByPathAndContent(DLP_RETENTION_JSON_PATH, "") != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "InputFileByPathAndContent failed!");
            return false;
        }
    }
    hasInit = true;
    return true;
}

int32_t RetentionFileManager::UpdateFile(const int32_t& jsonRes)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsonRes == DLP_FILE_NO_NEED_UPDATE) {
        return DLP_OK;
    }
    if (jsonRes != DLP_OK) {
        return jsonRes;
    }
    std::string jsonStr = sandboxJsonManager_->ToString();
    if (fileOperator_->InputFileByPathAndContent(DLP_RETENTION_JSON_PATH, jsonStr) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "InputFileByPathAndContent failed!");
        return DLP_INSERT_FILE_ERROR;
    }
    return DLP_OK;
}

int32_t RetentionFileManager::AddSandboxInfo(const int32_t& appIndex, const uint32_t& tokenId,
    const std::string& bundleName, const int32_t& userId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->AddSandboxInfo(appIndex, tokenId, bundleName, userId);
    return UpdateFile(res);
}

int32_t RetentionFileManager::DelSandboxInfo(uint32_t tokenId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->DelSandboxInfo(tokenId);
    return UpdateFile(res);
}

bool RetentionFileManager::CanUninstall(const uint32_t& tokenId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    return sandboxJsonManager_->CanUninstall(tokenId);
}

int32_t RetentionFileManager::UpdateSandboxInfo(const std::set<std::string>& docUriSet, RetentionInfo& info,
    bool isRetention)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->UpdateRetentionState(docUriSet, info, isRetention);
    return UpdateFile(res);
}

int32_t RetentionFileManager::RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->RemoveRetentionState(bundleName, appIndex);
    return UpdateFile(res);
}

int32_t RetentionFileManager::ClearUnreservedSandbox()
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->ClearUnreservedSandbox();
    return UpdateFile(res);
}

int32_t RetentionFileManager::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    return sandboxJsonManager_->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec, isRetention);
}

int32_t RetentionFileManager::GetBundleNameSetByUserId(const int32_t userId, std::set<std::string>& bundleNameSet)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    return sandboxJsonManager_->GetBundleNameSetByUserId(userId, bundleNameSet);
}

int32_t RetentionFileManager::RemoveRetentionInfoByUserId(const int32_t userId,
    const std::set<std::string>& bundleNameSet)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = sandboxJsonManager_->RemoveRetentionInfoByUserId(userId, bundleNameSet);
    return UpdateFile(res);
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
