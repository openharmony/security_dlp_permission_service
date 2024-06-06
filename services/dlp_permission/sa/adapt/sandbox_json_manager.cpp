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

#include "sandbox_json_manager.h"

#include "appexecfwk_errors.h"
#include "bundle_mgr_client.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "i_json_operator.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using Json = nlohmann::json;
using namespace OHOS;
namespace {
const std::string APPINDEX = "appIndex";
const std::string BUNDLENAME = "bundleName";
const std::string DOCURISET = "docUriSet";
const std::string USERID = "userId";
const std::string TOKENID = "tokenId";
const std::string DLPFILEACCESS = "dlpFileAccess";
static const uint32_t MAX_RETENTION_SIZE = 1024;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "SandboxJsonManager" };
}

SandboxJsonManager::SandboxJsonManager()
{
    infoVec_.clear();
}

SandboxJsonManager::~SandboxJsonManager()
{
    infoVec_.clear();
}

bool SandboxJsonManager::HasRetentionSandboxInfo(const std::string& bundleName)
{
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->bundleName == bundleName && iter->userId == userId) {
            return true;
        }
    }
    return false;
}

int32_t SandboxJsonManager::AddSandboxInfo(const RetentionInfo& retentionInfo)
{
    if (InsertSandboxInfo(retentionInfo)) {
        return DLP_OK;
    }
    return DLP_INSERT_FILE_ERROR;
}

bool SandboxJsonManager::CanUninstall(const uint32_t& tokenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == tokenId) {
            if (iter->docUriSet.empty()) {
                return true;
            }
            return false;
        }
    }
    return true;
}

int32_t SandboxJsonManager::DelSandboxInfo(const uint32_t& tokenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == tokenId) {
            if (iter->docUriSet.empty()) {
                infoVec_.erase(iter);
                return DLP_OK;
            }
            DLP_LOG_ERROR(LABEL, "docUriset not empty tokenId:%{public}d", tokenId);
            return DLP_RETENTION_SERVICE_ERROR;
        }
    }
    DLP_LOG_ERROR(LABEL, "docUri not exist tokenId:%{public}d", tokenId);
    return DLP_RETENTION_SERVICE_ERROR;
}

int32_t SandboxJsonManager::UpdateRetentionState(const std::set<std::string>& docUriSet, RetentionInfo& info,
    bool isRetention)
{
    if (docUriSet.empty()) {
        return DLP_OK;
    }
    if (isRetention) {
        if (info.tokenId == 0) {
            DLP_LOG_ERROR(LABEL, "tokenId==0");
            return DLP_RETENTION_UPDATE_ERROR;
        }
        return UpdateRetentionState(docUriSet, info, CompareByTokenId, UpdateDocUriSetByUnion);
    }
    if (info.bundleName.empty() && info.tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "tokenId==0 and bundleName empty");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    GetUserIdByUid(info.userId);
    if (info.tokenId == 0) {
        return UpdateRetentionState(docUriSet, info, CompareByBundleName, ClearDocUriSet);
    }
    return UpdateRetentionState(docUriSet, info, CompareByTokenId, ClearDocUriSet);
}

bool SandboxJsonManager::CompareByTokenId(const RetentionInfo& info1, const RetentionInfo& info2)
{
    return info1.tokenId == info2.tokenId;
}

bool SandboxJsonManager::CompareByBundleName(const RetentionInfo& info1, const RetentionInfo& info2)
{
    return info1.bundleName == info2.bundleName && info1.userId == info2.userId;
}

bool SandboxJsonManager::UpdateDocUriSetByUnion(RetentionInfo& info, const std::set<std::string>& newSet)
{
    std::set<std::string> temp;
    std::set_union(info.docUriSet.begin(), info.docUriSet.end(), newSet.begin(), newSet.end(),
        std::insert_iterator<std::set<std::string>>(temp, temp.begin()));
    if (temp.size() > MAX_RETENTION_SIZE) {
        DLP_LOG_ERROR(LABEL, "size bigger than MAX_RETENTION_SIZE");
        return false;
    }
    bool isUpdate = info.docUriSet.size() != temp.size();
    info.docUriSet = temp;
    return isUpdate;
}

bool SandboxJsonManager::ClearDocUriSet(RetentionInfo& info, const std::set<std::string>& newSet)
{
    if (info.docUriSet.empty()) {
        DLP_LOG_INFO(LABEL, "docUriSet size=0 ");
        return false;
    }
    info.docUriSet.clear();
    return true;
}

int32_t SandboxJsonManager::UpdateRetentionState(const std::set<std::string>& newSet, const RetentionInfo& info,
    bool (*compare)(const RetentionInfo& info1, const RetentionInfo& info2),
    bool (*update)(RetentionInfo& info, const std::set<std::string>& newSet))
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool isUpdate = false;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (!compare(*iter, info)) {
            continue;
        }
        if (update(*iter, newSet)) {
            isUpdate = true;
        }
    }
    if (!isUpdate) {
        DLP_LOG_ERROR(LABEL, "not update : %{public}s", info.bundleName.c_str());
        return DLP_FILE_NO_NEED_UPDATE;
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex)
{
    bool hasBundleName = false;
    {
        int32_t userId;
        if (!GetUserIdByForegroundAccount(&userId)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
            if (iter->bundleName == bundleName && iter->userId == userId) {
                if (appIndex != -1 && iter->appIndex != appIndex) {
                    ++iter;
                    continue;
                }
                iter = infoVec_.erase(iter);
                hasBundleName = true;
            } else {
                ++iter;
            }
        }
    }

    if (!hasBundleName) {
        DLP_LOG_ERROR(LABEL, "failed to find bundleName : %{public}s", bundleName.c_str());
        return DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infoVec_.empty()) {
        return DLP_OK;
    }

    int32_t userId;
    if (!GetUserIdByUid(userId)) {
        return DLP_RETENTION_SERVICE_ERROR;
    }
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->bundleName != bundleName || iter->userId != userId) {
            continue;
        }
        if (isRetention && iter->docUriSet.empty()) {
            continue;
        }
        if (!isRetention && !iter->docUriSet.empty()) {
            continue;
        }
        RetentionSandBoxInfo info;
        info.bundleName_ = bundleName;
        info.appIndex_ = iter->appIndex;
        info.docUriSet_ = iter->docUriSet;
        info.dlpFileAccess_ = iter->dlpFileAccess;
        retentionSandBoxInfoVec.push_back(info);
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::ClearUnreservedSandbox()
{
    DLP_LOG_INFO(LABEL, "ClearUnreservedSandbox called");
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool isChanged = false;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
        if (!iter->docUriSet.empty() || iter->userId != userId) {
            ++iter;
            continue;
        }
        int32_t res = bundleMgrClient.UninstallSandboxApp(iter->bundleName, iter->appIndex, iter->userId);
        if (res != DLP_OK && res != ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO) {
            DLP_LOG_ERROR(LABEL, "uninstall sandbox %{public}s fail, index=%{public}d, error=%{public}d",
                iter->bundleName.c_str(), iter->appIndex, res);
            ++iter;
            continue;
        }
        DLP_LOG_DEBUG(LABEL, "uninstall sandbox %{public}s success, index=%{public}d, error=%{public}d",
            iter->bundleName.c_str(), iter->appIndex, res);
        iter = infoVec_.erase(iter);
        isChanged = true;
    }
    if (!isChanged) {
        DLP_LOG_INFO(LABEL, "do not need update");
        return DLP_FILE_NO_NEED_UPDATE;
    }
    return DLP_OK;
}

bool SandboxJsonManager::GetUserIdByUid(int32_t& userId)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    return GetUserIdFromUid(uid, &userId) == 0;
}

int32_t SandboxJsonManager::GetBundleNameSetByUserId(const int32_t userId, std::set<std::string>& bundleNameSet)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (infoVec_.empty()) {
        return DLP_OK;
    }
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->userId == userId) {
            bundleNameSet.emplace(iter->bundleName);
        }
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::RemoveRetentionInfoByUserId(const int32_t userId,
    const std::set<std::string>& bundleNameSet)
{
    bool isNeedUpdate = false;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
        if ((iter->userId != userId) ||
            ((bundleNameSet.count(iter->bundleName) == 0) && !CheckReInstall(*iter, userId))) {
            ++iter;
            continue;
        }
        int32_t res = bundleMgrClient.UninstallSandboxApp(iter->bundleName, iter->appIndex, iter->userId);
        if (res != DLP_OK && res != ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO) {
            DLP_LOG_ERROR(LABEL, "uninstall sandbox %{public}s fail, index=%{public}d, error=%{public}d",
                iter->bundleName.c_str(), iter->appIndex, res);
            ++iter;
            continue;
        }
        DLP_LOG_DEBUG(LABEL, "uninstall sandbox %{public}s success, index=%{public}d, error=%{public}d",
            iter->bundleName.c_str(), iter->appIndex, res);
        iter = infoVec_.erase(iter);
        isNeedUpdate = true;
    }
    if (!isNeedUpdate) {
        DLP_LOG_INFO(LABEL, "do not need update");
        return DLP_FILE_NO_NEED_UPDATE;
    }
    return DLP_OK;
}

bool SandboxJsonManager::CheckReInstall(const RetentionInfo& info, const int32_t userId)
{
    uint32_t tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, info.bundleName, info.appIndex);
    if (tokenId == info.tokenId) {
        return false;
    }
    DLP_LOG_ERROR(LABEL, "GetHapTokenID not equal %{public}s,%{public}d", info.bundleName.c_str(), info.appIndex);
    return true;
}

bool SandboxJsonManager::InsertSandboxInfo(const RetentionInfo& info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == info.tokenId) {
            DLP_LOG_ERROR(LABEL, "docUri exist tokenId:%{public}d,bundleName:%{public}s,int32_t:%{public}d",
                info.tokenId, info.bundleName.c_str(), info.appIndex);
            return false;
        }
    }
    infoVec_.push_back(info);
    return true;
}

void SandboxJsonManager::RetentionInfoToJson(Json& json, const RetentionInfo& info) const
{
    json = Json { { APPINDEX, info.appIndex },
        { TOKENID, info.tokenId },
        { BUNDLENAME, info.bundleName },
        { USERID, info.userId },
        { DLPFILEACCESS, info.dlpFileAccess },
        { DOCURISET, info.docUriSet } };
}

Json SandboxJsonManager::ToJson() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    Json jsonObject;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        Json infoJson;
        RetentionInfoToJson(infoJson, *iter);
        jsonObject["retention"].push_back(infoJson);
    }
    return jsonObject;
}

void SandboxJsonManager::FromJson(const Json& jsonObject)
{
    if (jsonObject.is_null() || jsonObject.is_discarded()) {
        DLP_LOG_ERROR(LABEL, "json error");
        return;
    }
    for (auto& retentionJson : jsonObject["retention"]) {
        RetentionInfo info;
        if (!retentionJson.contains(APPINDEX) || !retentionJson.at(APPINDEX).is_number() ||
            !retentionJson.contains(BUNDLENAME) || !retentionJson.at(BUNDLENAME).is_string() ||
            !retentionJson.contains(DOCURISET) || !retentionJson.at(DOCURISET).is_array() ||
            !retentionJson.contains(TOKENID) || !retentionJson.at(TOKENID).is_number() ||
            !retentionJson.contains(DLPFILEACCESS) || !retentionJson.at(DLPFILEACCESS).is_number() ||
            !retentionJson.contains(USERID) || !retentionJson.at(USERID).is_number()) {
            DLP_LOG_ERROR(LABEL, "json contains error");
        }
        retentionJson.at(APPINDEX).get_to(info.appIndex);
        retentionJson.at(BUNDLENAME).get_to(info.bundleName);
        retentionJson.at(DOCURISET).get_to(info.docUriSet);
        retentionJson.at(TOKENID).get_to(info.tokenId);
        retentionJson.at(DLPFILEACCESS).get_to(info.dlpFileAccess);
        retentionJson.at(USERID).get_to(info.userId);
        if (info.bundleName.empty() || info.appIndex < 0 || info.userId < 0 || info.tokenId == 0) {
            DLP_LOG_ERROR(LABEL, "param is invalid");
            return;
        }
        InsertSandboxInfo(info);
    }
}

std::string SandboxJsonManager::ToString() const
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (infoVec_.empty()) {
            return "";
        }
    }
    auto jsonObject = ToJson();
    return jsonObject.dump();
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
