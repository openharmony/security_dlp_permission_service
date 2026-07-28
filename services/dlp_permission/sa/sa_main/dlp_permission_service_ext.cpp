/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "dlp_permission_service.h"
#include "accesstoken_kit.h"
#include "dlp_credential.h"
#include "dlp_feature_info.h"
#include "dlp_kv_data_storage.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_service_common.h"
#include "dlp_sandbox_change_callback_manager.h"
#include "dlp_sandbox_info.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "parameters.h"
#include "permission_manager_adapter.h"
#include "retention_file_manager.h"
#include "sandbox_config_kv_data_storage.h"
#include "visit_record_file_manager.h"
#include "critical_helper.h"
#include "alg_utils.h"
#include "string_ex.h"
#include "account_adapt.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
namespace {
constexpr const int32_t EDM_UID = 3057;
static const uint32_t ENABLE_VALUE_TRUE = 1;
static const uint32_t MAX_FILE_RECORD_SIZE = 1024;
static const uint32_t MAX_APPID_LIST_SIZE = 250;
static const uint32_t MAX_MASKINFO_SIZE = 128;
static const uint32_t MAX_ACCOUNT_SIZE = 1024;
static const uint32_t MAX_FILEID_SIZE = 1024;
static const uint32_t MAX_ENTERPRISEPOLICY_SIZE = 1024 * 1024 * 4;
static const uint32_t MAX_CLASSIFICATION_LABEL_SIZE = 255;
static const char *FEATURE_INFO_DATA_FILE_PATH =
    "/data/service/el1/public/dlp_permission_service/dlp_feature_info.txt";

static void ClearKvStorage()
{
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        DLP_LOG_ERROR(LABEL, "get userID fail");
        return;
    }
    std::map<std::string, std::string> keyMap;
    SandboxConfigKvDataStorage::GetInstance().GetKeyMapByUserId(userId, keyMap);
    for (auto iter = keyMap.begin(); iter != keyMap.end(); iter++) {
        AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userId, iter->first, 0);
        if (tokenId == 0 || std::to_string(tokenId) != iter->second) {
            SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(userId,
                iter->first, iter->second);
        }
    }
}
}

int32_t DlpPermissionService::ClearUnreservedSandbox()
{
    CriticalHelper criticalHelper("ClearUnreservedSandbox");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::AccessTokenID bmsToken =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId(FOUNDATION_SERVICE_NAME);
    if (callingToken != bmsToken) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::lock_guard<std::mutex> lock(observer->GetTerminalMutex());
    ClearKvStorage();
    RetentionFileManager::GetInstance().ClearUnreservedSandbox();
    return DLP_OK;
}

bool DlpPermissionService::GetCallerBundleName(const uint32_t tokenId, std::string& bundleName)
{
    HapTokenInfo tokenInfo;
    auto result = AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo);
    if (result != RET_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "token:0x%{public}x, result:%{public}d", tokenId, result);
        return false;
    }
    if (tokenInfo.bundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "bundlename is empty");
        return false;
    }
    bundleName = tokenInfo.bundleName;
    return true;
}

int32_t DlpPermissionService::GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec)
{
    CriticalHelper criticalHelper("GetDLPFileVisitRecord");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool sandboxFlag;
    if (PermissionManagerAdapter::CheckSandboxFlagWithService(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }

    std::string callerBundleName;
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetCallerBundleName(tokenId, callerBundleName)) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t userId = GetCallingUserId();
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "get userId error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t result = DLP_OK;
    {
        std::lock_guard<std::mutex> lock(observer->GetTerminalMutex());
        result = VisitRecordFileManager::GetInstance().GetVisitRecordList(callerBundleName, userId, infoVec);
    }
    if (infoVec.size() > MAX_FILE_RECORD_SIZE) {
        DLP_LOG_ERROR(LABEL, "listNum larger than 1024");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return result;
}

int32_t DlpPermissionService::SetMDMPolicy(const std::vector<std::string>& appIdList)
{
    CriticalHelper criticalHelper("SetMDMPolicy");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (appIdList.empty() || !ValidateStringList(appIdList, MAX_APPID_SIZE)) {
        DLP_LOG_ERROR(LABEL, "appIdList is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    int32_t res = DlpCredential::GetInstance().SetMDMPolicy(appIdList);
    return res;
}

int32_t DlpPermissionService::GetMDMPolicy(std::vector<std::string>& appIdList)
{
    CriticalHelper criticalHelper("GetMDMPolicy");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    int32_t res = DlpCredential::GetInstance().GetMDMPolicy(appIdList);
    if (appIdList.size() > MAX_APPID_LIST_SIZE) {
        DLP_LOG_ERROR(LABEL, "appIdList larger than limit");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionService::RemoveMDMPolicy()
{
    CriticalHelper criticalHelper("RemoveMDMPolicy");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    int32_t res = DlpCredential::GetInstance().RemoveMDMPolicy();
    return res;
}

int32_t DlpPermissionService::SetSandboxAppConfig(const std::string& configInfo)
{
    CriticalHelper criticalHelper("SetSandboxAppConfig");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (configInfo.size() >= OHOS::DistributedKv::Entry::MAX_VALUE_LENGTH) {
        DLP_LOG_ERROR(LABEL, "configInfo is too long");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    std::string temp = configInfo;
    int32_t res = SandboxConfigOperate(temp, SandboxConfigOperationEnum::ADD);
    return res;
}

int32_t DlpPermissionService::CleanSandboxAppConfig()
{
    CriticalHelper criticalHelper("CleanSandboxAppConfig");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool sandboxFlag;
    if (PermissionManagerAdapter::CheckSandboxFlagWithService(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a sandbox app");
        return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
    }
    std::string emptyStr = "";
    int32_t res = SandboxConfigOperate(emptyStr, SandboxConfigOperationEnum::CLEAN);
    return res;
}

int32_t DlpPermissionService::GetSandboxAppConfig(std::string& configInfo)
{
    CriticalHelper criticalHelper("GetSandboxAppConfig");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = SandboxConfigOperate(configInfo, SandboxConfigOperationEnum::GET);
    return res;
}

int32_t DlpPermissionService::SetDlpFeature(const uint32_t dlpFeatureInfo, bool& statusSetInfo)
{
    CriticalHelper criticalHelper("SetDlpFeature");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    statusSetInfo = false;
    std::string appId;
    if (!PermissionManagerAdapter::CheckPermissionAndGetAppId(appId)) {
        return DLP_SERVICE_ERROR_NOT_SYSTEM_APP;
    }

    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    int32_t res = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    DLP_LOG_INFO(LABEL, "SaveDlpFeatureInfoToFile res is: %{public}d", res);
    if (res == DLP_OK) {
        statusSetInfo = true;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::CheckIfEnterpriseAccount()
{
    int32_t userId;
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "GetForegroundOsAccountLocalId failed %{public}d", res);
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    AccountSA::OsAccountInfo osAccountInfo;
    res = OHOS::AccountSA::OsAccountManager::QueryOsAccountById(userId, osAccountInfo);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "QueryOsAccountById failed %{public}d", res);
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    AccountSA::DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        DLP_LOG_INFO(LABEL, "AccountName empty, ForegroundOsAccoun is personal account");
        return DLP_PARSE_ERROR_ACCOUNT_PERSONAL;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::IsDLPFeatureProvided(bool& isProvideDLPFeature)
{
    CriticalHelper criticalHelper("IsDLPFeatureProvided");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (CheckIfEnterpriseAccount() != DLP_OK) {
        isProvideDLPFeature = false;
        return DLP_OK;
    }
    uint32_t dlpFeature = 0;
    std::string value = OHOS::system::GetParameter(DLP_ENABLE, "");
    if (HcIsFileExist(FEATURE_INFO_DATA_FILE_PATH)) {
        DLP_LOG_INFO(LABEL, "feature info file exist");
        if (DlpFeatureInfo::GetDlpFeatureInfoFromFile(FEATURE_INFO_DATA_FILE_PATH, dlpFeature) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "GetDlpFeatureInfoFromFile failed");
            isProvideDLPFeature = (value == TRUE_VALUE);
            return DLP_OK;
        }
        if (dlpFeature != ENABLE_VALUE_TRUE) {
            DLP_LOG_ERROR(LABEL, "DlpFeatureInfo is false");
            isProvideDLPFeature = false;
            return DLP_OK;
        }
        isProvideDLPFeature = true;
        return DLP_OK;
    }
    DLP_LOG_DEBUG(LABEL, "feature info file not exist!");
    isProvideDLPFeature = (value == TRUE_VALUE);
    return DLP_OK;
}

int32_t DlpPermissionService::SandConfigOperateCheck(SandboxConfigOperationEnum operationEnum, std::string& bundleName,
    int32_t& userId, AccessToken::AccessTokenID& originalTokenId)
{
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    bool result = GetCallerBundleName(tokenId, bundleName);
    if (!result) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    userId = GetCallingUserId();
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "get userId error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    originalTokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, 0);
    if (originalTokenId == 0) {
        DLP_LOG_ERROR(LABEL, "Get normal tokenId error.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (operationEnum == ADD && originalTokenId != tokenId) {
        int32_t uid = IPCSkeleton::GetCallingUid();
        DlpSandboxInfo info;
        result = observer->GetSandboxInfo(uid, info);
        if (!result) {
            DLP_LOG_ERROR(LABEL, "Can not found sandbox info, tokenId=%{public}u", tokenId);
            return DLP_SERVICE_ERROR_VALUE_INVALID;
        }
        if (info.hasRead) {
            DLP_LOG_ERROR(LABEL, "Sandbox has read dlp file, tokenId=%{public}u", tokenId);
            return DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR;
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionService::SandboxConfigOperate(std::string& configInfo, SandboxConfigOperationEnum operationEnum)
{
    std::string callerBundleName;
    int32_t userId;
    AccessTokenID originalTokenId;
    int32_t res = SandConfigOperateCheck(operationEnum, callerBundleName, userId, originalTokenId);
    if (res != DLP_OK) {
        return res;
    }
    res = DlpCredential::GetInstance().CheckMdmPermission(callerBundleName, userId);
    if (res != DLP_OK) {
        return res;
    }
    switch (operationEnum) {
        case ADD:
            res = SandboxConfigKvDataStorage::GetInstance().AddSandboxConfigIntoDataStorage(userId, callerBundleName,
                configInfo, std::to_string(originalTokenId));
            break;
        case GET:
            res = SandboxConfigKvDataStorage::GetInstance().GetSandboxConfigFromDataStorage(userId, callerBundleName,
                configInfo, std::to_string(originalTokenId));
            break;
        case CLEAN:
            res = SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(userId,
                callerBundleName, std::to_string(originalTokenId));
            break;
        default:
            res = DLP_SERVICE_ERROR_VALUE_INVALID;
            DLP_LOG_ERROR(LABEL, "enter default case");
            break;
    }
    return res;
}

int32_t DlpPermissionService::SetReadFlag(uint32_t uid)
{
    CriticalHelper criticalHelper("SetReadFlag");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    DlpSandboxInfo info;
    observer->GetSandboxInfo(uid, info);
    int32_t res = RetentionFileManager::GetInstance().UpdateReadFlag(info.tokenId);
    if (res != 0) {
        return res;
    }
    observer->UpdateReadFlag(uid);
    return DLP_OK;
}

int DlpPermissionService::Dump(int fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        return ERR_INVALID_VALUE;
    }

    dprintf(fd, "DlpPermission Dump:\n");
    std::string arg0 = (args.size() == 0) ? "" : Str16ToStr8(args.at(0));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help\n");
        dprintf(fd, "      -d: default dump\n");
    } else if (arg0.compare("-d") == 0 || arg0.compare("") == 0) {
        auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
        if (observer == nullptr) {
            return ERR_INVALID_VALUE;
        }
        observer->DumpSandbox(fd);
    }

    return ERR_OK;
}

int DlpPermissionService::SetEnterprisePolicy(const std::string& policy)
{
    CriticalHelper criticalHelper("SetEnterprisePolicy");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !(appIdentifier == MDM_APPIDENTIFIER)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (policy.size() > MAX_ENTERPRISEPOLICY_SIZE) {
        DLP_LOG_ERROR(LABEL, "Enterprise policy is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = DlpCredential::GetInstance().SetEnterprisePolicy(policy);
    return res;
}

static bool CheckFileInfo(const FileInfo& fileInfo)
{
    return (fileInfo.accountName.size() <= MAX_ACCOUNT_SIZE &&
        fileInfo.fileId.size() <= MAX_FILEID_SIZE &&
        fileInfo.maskInfo.size() <= MAX_MASKINFO_SIZE);
}

int DlpPermissionService::SetFileInfo(const std::string& uri, const FileInfo& fileInfo)
{
    CriticalHelper criticalHelper("SetFileInfo");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !(appIdentifier == MDM_APPIDENTIFIER)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (uri.empty() || uri.size() > MAX_URI_SIZE) {
        DLP_LOG_ERROR(LABEL, "uri is invalid");
        return DLP_SERVICE_ERROR_URI_EMPTY;
    }
    if (!CheckFileInfo(fileInfo)) {
        DLP_LOG_ERROR(LABEL, "fileInfo is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    FileInfo maskFileInfo;
    maskFileInfo.isNotOwnerAndReadOnce = fileInfo.isNotOwnerAndReadOnce;
    maskFileInfo.isWatermark = fileInfo.isWatermark;
    maskFileInfo.accountName = fileInfo.accountName;
    maskFileInfo.fileId = fileInfo.fileId;
    if (maskFileInfo.isWatermark) {
        std::unique_lock<std::mutex> lock(waterMarkInfoMutex_);
        maskFileInfo.maskInfo = waterMarkInfo_.maskInfo;
    }
    bool res = observer->AddUriAndFileInfo(uri, maskFileInfo);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "AddUriAndFileInfo error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::QueryOpenedEnterpriseDlpFiles(const std::string& label,
    std::vector<std::string>& resultUris)
{
    CriticalHelper criticalHelper("QueryOpenedEnterpriseDlpFiles");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (label.size() > MAX_CLASSIFICATION_LABEL_SIZE) {
        DLP_LOG_ERROR(LABEL, "label is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        DLP_LOG_ERROR(LABEL, "Failed to get appIdentifier.");
        return DLP_PARSE_ERROR_BMS_ERROR;
    }
    observer->GetSandboxInfosByClassificationLabel(label, appIdentifier, resultUris);
    DLP_LOG_INFO(LABEL, "QueryOpenedEnterpriseDlpFiles label:%{private}s, count:%{public}zu", label.c_str(),
        resultUris.size());
    return DLP_OK;
}

int32_t DlpPermissionService::CloseOpenedEnterpriseDlpFiles(const std::string& label)
{
    CriticalHelper criticalHelper("CloseOpenedEnterpriseDlpFiles");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (label.size() > MAX_CLASSIFICATION_LABEL_SIZE) {
        DLP_LOG_ERROR(LABEL, "label is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        DLP_LOG_ERROR(LABEL, "Failed to get appIdentifier.");
        return DLP_PARSE_ERROR_BMS_ERROR;
    }
    std::vector<DlpSandboxInfo> appInfos;
    observer->GetNeededDelEnterpriseSandbox(label, appIdentifier, appInfos);
    DLP_LOG_INFO(LABEL, "CloseOpenedEnterpriseDlpFiles label:%{private}s, count:%{public}zu", label.c_str(),
        appInfos.size());
    bool allUninstalled = true;
    for (const auto& appInfo : appInfos) {
        DeleteDlpSandboxInfo(appInfo.bundleName, appInfo.appIndex, appInfo.userId);
        if (appInfo.bundleName == HIPREVIEW_HIGH) {
            UninstallDlpSandboxApp(HIPREVIEW_LOW, appInfo.bindAppIndex, appInfo.userId);
        }
        allUninstalled = (UninstallDlpSandboxApp(appInfo.bundleName, appInfo.appIndex, appInfo.userId) == DLP_OK) &&
            allUninstalled;
        RetentionFileManager::GetInstance().RemoveRetentionState(appInfo.bundleName, appInfo.appIndex);
        DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(appInfo);
    }
    return allUninstalled ? DLP_OK : DLP_PARSE_ERROR_BMS_ERROR;
}

int32_t DlpPermissionService::SetEnterpriseInfos(const std::string& uri, const std::string& fileId,
    DLPFileAccess dlpFileAccess, const std::string& classificationLabel, const std::string& appIdentifier)
{
    CriticalHelper criticalHelper("SetEnterpriseInfos");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (uri.empty() || uri.size() > MAX_URI_SIZE ||
        fileId.size() > MAX_FILEID_SIZE || appIdentifier.size() > MAX_APPID_SIZE ||
        classificationLabel.size() > MAX_CLASSIFICATION_LABEL_SIZE ||
        dlpFileAccess > DLPFileAccess::FULL_CONTROL || dlpFileAccess <= DLPFileAccess::NO_PERMISSION) {
        DLP_LOG_ERROR(LABEL, "input param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.classificationLabel = classificationLabel;
    enterpriseInfo.dlpFileAccess = dlpFileAccess;
    enterpriseInfo.fileId = fileId;
    enterpriseInfo.appIdentifier = appIdentifier;

    bool res = observer->AddUriAndEnterpriseInfo(uri, enterpriseInfo);
    if (!res) {
        DLP_LOG_ERROR(LABEL, "AddUriAndEnterpriseInfo error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    DLP_LOG_INFO(LABEL, "SetEnterpriseInfos success with uri: %{private}s", uri.c_str());
    return DLP_OK;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
