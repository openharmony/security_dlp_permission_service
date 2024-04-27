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

#include "visit_record_json_manager.h"

#include "dlp_permission_log.h"
#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Json = nlohmann::json;
using namespace OHOS;
namespace {
const std::string BUNDLENAME = "bundleName";
const std::string DOCURI = "docUri";
const std::string USERID = "userId";
const std::string TIMESTAMP = "timestamp";
const std::string RECORDLIST = "recordList";
static const uint32_t MAX_RETENTION_SIZE = 1024;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "VisitRecordJsonManager" };
}

VisitRecordJsonManager::VisitRecordJsonManager()
{
    infoList_.clear();
}

VisitRecordJsonManager::~VisitRecordJsonManager()
{
    infoList_.clear();
}

int32_t VisitRecordJsonManager::AddVisitRecord(const std::string& bundleName, const int32_t& userId,
    const std::string& docUri, int64_t timestamp)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infoList_.size() > MAX_RETENTION_SIZE) {
        DLP_LOG_ERROR(LABEL, "size bigger than MAX_RETENTION_SIZE");
        return DLP_JSON_UPDATE_ERROR;
    }
    for (auto iter = infoList_.begin(); iter != infoList_.end(); ++iter) {
        if (iter->bundleName == bundleName && iter->userId == userId && iter->docUri == docUri) {
            infoList_.erase(iter);
            break;
        }
    }
    VisitRecordInfo info;
    info.bundleName = bundleName;
    info.userId = userId;
    info.docUri = docUri;
    info.timestamp = timestamp;
    infoList_.emplace_back(info);
    return DLP_OK;
}

int32_t VisitRecordJsonManager::AddVisitRecord(const std::string& bundleName, const int32_t& userId,
    const std::string& docUri)
{
    int64_t time =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AddVisitRecord(bundleName, userId, docUri, time);
}

int32_t VisitRecordJsonManager::GetVisitRecordList(const std::string& bundleName, const int32_t& userId,
    std::vector<VisitedDLPFileInfo>& infoVec)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infoList_.empty()) {
        return DLP_FILE_NO_NEED_UPDATE;
    }
    bool isFind = false;
    for (auto iter = infoList_.begin(); iter != infoList_.end();) {
        if (iter->bundleName == bundleName && iter->userId == userId) {
            VisitedDLPFileInfo info;
            info.docUri = iter->docUri;
            info.visitTimestamp = iter->timestamp;
            infoVec.emplace_back(info);
            iter = infoList_.erase(iter);
            isFind = true;
        } else {
            ++iter;
        }
    }
    if (!isFind) {
        DLP_LOG_INFO(LABEL, "not find bundleName:%{public}s,userId:%{public}d", bundleName.c_str(), userId);
        return DLP_FILE_NO_NEED_UPDATE;
    }
    return DLP_OK;
}


void VisitRecordJsonManager::VisitRecordInfoToJson(Json& json, const VisitRecordInfo& info) const
{
    json = Json { { BUNDLENAME, info.bundleName },
        { USERID, info.userId },
        { DOCURI, info.docUri },
        { TIMESTAMP, info.timestamp } };
}

bool VisitRecordJsonManager::VisitRecordInfoFromJson(const Json& json, VisitRecordInfo& info) const
{
    std::string bundleName = "";
    std::string docUri = "";
    int32_t userId = -1;
    int64_t timestamp = -1;
    if (json.contains(BUNDLENAME) && json.at(BUNDLENAME).is_string()) {
        json.at(BUNDLENAME).get_to(bundleName);
    }
    if (json.contains(DOCURI) && json.at(DOCURI).is_string()) {
        json.at(DOCURI).get_to(docUri);
    }
    if (json.contains(USERID) && json.at(USERID).is_number()) {
        json.at(USERID).get_to(userId);
    }
    if (json.contains(TIMESTAMP) && json.at(TIMESTAMP).is_number()) {
        json.at(TIMESTAMP).get_to(timestamp);
    }
    if (bundleName.empty() || userId < 0 || docUri.empty() || timestamp < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return false;
    }
    info.bundleName = bundleName;
    info.userId = userId;
    info.docUri = docUri;
    info.timestamp = timestamp;
    return true;
}

Json VisitRecordJsonManager::ToJson() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    Json jsonObject;
    for (auto iter = infoList_.begin(); iter != infoList_.end(); ++iter) {
        Json infoJson;
        VisitRecordInfoToJson(infoJson, *iter);
        jsonObject[RECORDLIST].push_back(infoJson);
    }
    return jsonObject;
}

void VisitRecordJsonManager::FromJson(const Json& jsonObject)
{
    if (jsonObject.is_null() || jsonObject.is_discarded()) {
        DLP_LOG_ERROR(LABEL, "json error");
        return;
    }
    if (!jsonObject.contains(RECORDLIST)) {
        DLP_LOG_ERROR(LABEL, "jsonObject not contains RECORDLIST");
        return;
    }
    for (const auto& json : jsonObject[RECORDLIST]) {
        VisitRecordInfo info;
        if (VisitRecordInfoFromJson(json, info)) {
            AddVisitRecord(info.bundleName, info.userId, info.docUri);
        }
    }
}

std::string VisitRecordJsonManager::ToString() const
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (infoList_.empty()) {
            return "";
        }
    }
    auto jsonObject = ToJson();
    return jsonObject.dump();
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
