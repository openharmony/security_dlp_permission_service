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

#include "visit_record_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "VisitRecordFileManager" };
const std::string PATH_SEPARATOR = "/";
const std::string USER_INFO_BASE = "/data/service/el1/public/dlp_permission_service";
const std::string DLP_VISIT_RECORD_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "dlp_file_visit_record_info.json";
}

VisitRecordFileManager::VisitRecordFileManager()
    : hasInit(false),
      fileOperator_(std::make_shared<FileOperator>()),
      visitRecordJsonManager_(std::make_shared<VisitRecordJsonManager>())
{
    Init();
}

VisitRecordFileManager::~VisitRecordFileManager() {}

VisitRecordFileManager& VisitRecordFileManager::GetInstance()
{
    static VisitRecordFileManager instance;
    return instance;
}

bool VisitRecordFileManager::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (hasInit) {
        return true;
    }
    if (fileOperator_->IsExistFile(DLP_VISIT_RECORD_JSON_PATH)) {
        std::string constraintsConfigStr;
        if (fileOperator_->GetFileContentByPath(DLP_VISIT_RECORD_JSON_PATH, constraintsConfigStr) != DLP_OK) {
            return false;
        }
        if (!constraintsConfigStr.empty()) {
            Json callbackInfoJson = Json::parse(constraintsConfigStr, nullptr, false);
            if (callbackInfoJson.is_discarded()) {
                DLP_LOG_ERROR(LABEL, "callbackInfoJson is discarded");
                return false;
            }
            visitRecordJsonManager_->FromJson(callbackInfoJson);
        }
    }
    hasInit = true;
    return true;
}

int32_t VisitRecordFileManager::UpdateFile(const int32_t& jsonRes)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsonRes == DLP_FILE_NO_NEED_UPDATE) {
        return DLP_OK;
    }
    if (jsonRes != DLP_OK) {
        return jsonRes;
    }
    std::string jsonStr = visitRecordJsonManager_->ToString();
    if (fileOperator_->InputFileByPathAndContent(DLP_VISIT_RECORD_JSON_PATH, jsonStr) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "InputFileByPathAndContent failed!");
        return DLP_INSERT_FILE_ERROR;
    }
    return DLP_OK;
}

int32_t VisitRecordFileManager::AddVisitRecord(const std::string& bundleName, const int32_t& userId,
    const std::string& docUri)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = visitRecordJsonManager_->AddVisitRecord(bundleName, userId, docUri);
    return UpdateFile(res);
}

int32_t VisitRecordFileManager::GetVisitRecordList(const std::string& bundleName, const int32_t& userId,
    std::vector<VisitedDLPFileInfo>& infoVec)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = visitRecordJsonManager_->GetVisitRecordList(bundleName, userId, infoVec);
    return UpdateFile(res);
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
