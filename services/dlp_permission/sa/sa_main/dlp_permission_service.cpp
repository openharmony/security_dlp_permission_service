/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <chrono>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "app_mgr_client.h"
#include "bundle_manager_adapter.h"
#include "bundle_mgr_client.h"
#include "config_policy_utils.h"
#include "dlp_credential_client.h"
#include "dlp_credential.h"
#include "dlp_kv_data_storage.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_mgr_client.h"
#include "dlp_sandbox_change_callback_manager.h"
#include "dlp_sandbox_info.h"
#include "file_operator.h"
#include "hap_token_info.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "open_dlp_file_callback_manager.h"
#if defined(DLP_DEBUG_ENABLE) && DLP_DEBUG_ENABLE == 1
#include "parameter.h"
#endif
#include "parameters.h"
#include "param_wrapper.h"
#include "permission_policy.h"
#include "system_ability_definition.h"
#include "visit_record_file_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionService" };
constexpr const int32_t EDM_UID = 3057;
static const std::string ALLOW_ABILITY[] = {"com.ohos.dlpmanager"};
static const std::string ALLOW_ACTION[] = {"ohos.want.action.CREATE_FILE"};
static const std::string DLP_MANAGER = "com.ohos.dlpmanager";
static const std::chrono::seconds SLEEP_TIME(120);
static const int REPEAT_TIME = 5;
static const std::string DLP_CONFIG = "etc/dlp_permission/dlp_config.json";
static const std::string SUPPORT_FILE_TYPE = "support_file_type";
static const std::string DEAULT_DLP_CONFIG = "/system/etc/dlp_config.json";
static const std::string DLP_ENABEL = "const.dlp.dlp_enable";
static const std::string TRUE_VALUE = "true";
static const std::string FALSE_VALUE = "false";
}
REGISTER_SYSTEM_ABILITY_BY_ID(DlpPermissionService, SA_ID_DLP_PERMISSION_SERVICE, true);

DlpPermissionService::DlpPermissionService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    thread_ = nullptr;
    DLP_LOG_INFO(LABEL, "DlpPermissionService()");
}

DlpPermissionService::~DlpPermissionService()
{
    DLP_LOG_INFO(LABEL, "~DlpPermissionService()");
    UnregisterAppStateObserver();
    iAppMgr_ = nullptr;
    appStateObserver_ = nullptr;
}

void DlpPermissionService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        DLP_LOG_INFO(LABEL, "DlpPermissionService has already started!");
        return;
    }
    DLP_LOG_INFO(LABEL, "DlpPermissionService is starting");
    if (!RegisterAppStateObserver()) {
        DLP_LOG_ERROR(LABEL, "Failed to register app state observer!");
        return;
    }
    dlpEventSubSubscriber_ = std::make_shared<DlpEventSubSubscriber>();
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(this);
    if (!ret) {
        DLP_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    DLP_LOG_INFO(LABEL, "Congratulations, DlpPermissionService start successfully!");
}

void DlpPermissionService::OnStop()
{
    DLP_LOG_INFO(LABEL, "Stop service");
}

bool DlpPermissionService::RegisterAppStateObserver()
{
    if (appStateObserver_ != nullptr) {
        DLP_LOG_INFO(LABEL, "AppStateObserver instance already create");
        return true;
    }
    appStateObserver_ = new (std::nothrow) AppStateObserver();
    if (appStateObserver_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to create AppStateObserver instance");
        return false;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get system ability manager");
        appStateObserver_ = nullptr;
        return false;
    }
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppMgr_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get ability manager service");
        appStateObserver_ = nullptr;
        return false;
    }
    int32_t result = iAppMgr_->RegisterApplicationStateObserver(appStateObserver_);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Failed to Register app state observer");
        iAppMgr_ = nullptr;
        appStateObserver_ = nullptr;
        return false;
    }
    return true;
}

void DlpPermissionService::UnregisterAppStateObserver()
{
    if (iAppMgr_ != nullptr && appStateObserver_ != nullptr) {
        iAppMgr_->UnregisterApplicationStateObserver(appStateObserver_);
    }
}

int32_t DlpPermissionService::GenerateDlpCertificate(
    const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!policyParcel->policyParams_.IsValid()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    unordered_json jsonObj;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeDlpPermission(policyParcel->policyParams_, jsonObj);
    if (res != DLP_OK) {
        return res;
    }

    return DlpCredential::GetInstance().GenerateDlpCertificate(
        jsonObj.dump(), policyParcel->policyParams_.ownerAccountId_,
        policyParcel->policyParams_.ownerAccountType_, callback);
}

int32_t DlpPermissionService::ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
    const std::string& appId, const bool& offlineAccess)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    return DlpCredential::GetInstance().ParseDlpCertificate(certParcel, callback, appId, offlineAccess);
}

bool DlpPermissionService::InsertDlpSandboxInfo(DlpSandboxInfo& sandboxInfo, bool hasRetention)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return false;
    }

    AppExecFwk::BundleInfo info;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    if (bundleMgrClient.GetSandboxBundleInfo(sandboxInfo.bundleName, sandboxInfo.appIndex, sandboxInfo.userId, info) !=
        DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        if (hasRetention) {
            RetentionFileManager::GetInstance().ClearUnreservedSandbox();
        }
        return false;
    }
    sandboxInfo.uid = info.uid;
    sandboxInfo.tokenId = AccessToken::AccessTokenKit::GetHapTokenID(sandboxInfo.userId, sandboxInfo.bundleName,
        sandboxInfo.appIndex);
    appStateObserver_->AddDlpSandboxInfo(sandboxInfo);
    return true;
}

int32_t DlpPermissionService::InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess,
    int32_t userId, SandboxInfo &sandboxInfo, const std::string& uri)
{
    if (bundleName.empty() || dlpFileAccess > FULL_CONTROL || dlpFileAccess <= NO_PERMISSION) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::vector<RetentionSandBoxInfo> infoVec;
    auto res = RetentionFileManager::GetInstance().GetRetentionSandboxList(bundleName, infoVec, true);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetRetentionSandboxList fail bundleName:%{public}s,uri:%{public}s, error=%{public}d",
            bundleName.c_str(), uri.c_str(), res);
        return res;
    }
    bool isNeedInstall = true;
    int32_t appIndex = -1;
    for (auto iter = infoVec.begin(); iter != infoVec.end(); ++iter) {
        auto setIter = iter->docUriSet_.find(uri);
        if (setIter != iter->docUriSet_.end()) {
            appIndex = iter->appIndex_;
            isNeedInstall = false;
            break;
        }
    }
    if (isNeedInstall) {
        AppExecFwk::BundleMgrClient bundleMgrClient;
        DLPFileAccess permForBMS = (dlpFileAccess == READ_ONLY) ? READ_ONLY : CONTENT_EDIT;
        int32_t bundleClientRes = bundleMgrClient.InstallSandboxApp(bundleName, permForBMS, userId, appIndex);
        if (bundleClientRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "install sandbox %{public}s fail, error=%{public}d", bundleName.c_str(),
                bundleClientRes);
            return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
        }
    }
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.dlpFileAccess = dlpFileAccess;
    dlpSandboxInfo.bundleName = bundleName;
    dlpSandboxInfo.userId = userId;
    dlpSandboxInfo.appIndex = appIndex;
    dlpSandboxInfo.pid = pid;
    dlpSandboxInfo.uri = uri;
    dlpSandboxInfo.timeStamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    if (!InsertDlpSandboxInfo(dlpSandboxInfo, !isNeedInstall)) {
        return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
    }
    sandboxInfo.appIndex = appIndex;
    sandboxInfo.tokenId = dlpSandboxInfo.tokenId;
    VisitRecordFileManager::GetInstance().AddVisitRecord(bundleName, userId, uri);
    return DLP_OK;
}

uint32_t DlpPermissionService::DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return 0;
    }

    AppExecFwk::BundleMgrClient bundleMgrClient;
    AppExecFwk::BundleInfo info;
    int32_t result = bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        return 0;
    }

    return appStateObserver_->EraseDlpSandboxInfo(info.uid);
}

int32_t DlpPermissionService::UninstallDlpSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    AppExecFwk::BundleMgrClient bundleMgrClient;
    int32_t res = bundleMgrClient.UninstallSandboxApp(bundleName, appIndex, userId);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "uninstall sandbox %{public}s fail, index=%{public}d, error=%{public}d",
            bundleName.c_str(), appIndex, res);
        return DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (bundleName.empty() || appIndex < 0 || userId < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    uint32_t tokenId = DeleteDlpSandboxInfo(bundleName, appIndex, userId);
    if (tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "DeleteDlpSandboxInfo sandbox %{public}s fail, index=%{public}d", bundleName.c_str(),
            appIndex);
        return DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL;
    }
    if (RetentionFileManager::GetInstance().CanUninstall(tokenId)) {
        return UninstallDlpSandboxApp(bundleName, appIndex, userId);
    }
    return DLP_OK;
}

static bool CheckAllowAbilityList(const AAFwk::Want& want)
{
    std::string bundleName = want.GetBundle();
    std::string actionName = want.GetAction();
    DLP_LOG_DEBUG(LABEL, "CheckAllowAbilityList %{public}s %{public}s", bundleName.c_str(), actionName.c_str());
    bool bundleCheck = std::any_of(std::begin(ALLOW_ABILITY), std::end(ALLOW_ABILITY),
        [bundleName](const std::string& bundle) { return bundle == bundleName; });
    bool actionCheck = std::any_of(std::begin(ALLOW_ACTION), std::end(ALLOW_ACTION),
        [actionName](const std::string& action) { return action == actionName; });
    return actionCheck || bundleCheck;
}

int32_t DlpPermissionService::GetSandboxExternalAuthorization(
    int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& authType)
{
    if (sandboxUid < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (appStateObserver_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    bool isSandbox = false;

    appStateObserver_->IsInDlpSandbox(isSandbox, sandboxUid);
    if (isSandbox && !CheckAllowAbilityList(want)) {
        authType = DENY_START_ABILITY;
    } else {
        authType = ALLOW_START_ABILITY;
    }

    return DLP_OK;
}

int32_t DlpPermissionService::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    if (tokenId == 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    return appStateObserver_->QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

static ActionFlags GetDlpActionFlag(DLPFileAccess dlpFileAccess)
{
    switch (dlpFileAccess) {
        case READ_ONLY: {
            return ACTION_VIEW;
        }
        case CONTENT_EDIT: {
            return static_cast<ActionFlags>(ACTION_VIEW | ACTION_SAVE | ACTION_SAVE_AS | ACTION_EDIT |
            ACTION_SCREEN_CAPTURE | ACTION_SCREEN_SHARE | ACTION_SCREEN_RECORD | ACTION_COPY);
        }
        case FULL_CONTROL: {
            return static_cast<ActionFlags>(ACTION_VIEW | ACTION_SAVE | ACTION_SAVE_AS | ACTION_EDIT |
                ACTION_SCREEN_CAPTURE | ACTION_SCREEN_SHARE | ACTION_SCREEN_RECORD | ACTION_COPY | ACTION_PRINT |
                ACTION_EXPORT | ACTION_PERMISSION_CHANGE);
        }
        default:
            return ACTION_INVALID;
    }
}

int32_t DlpPermissionService::QueryDlpFileAccess(DLPPermissionInfoParcel& permInfoParcel)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    DLPFileAccess dlpFileAccess = NO_PERMISSION;
    int32_t res = appStateObserver_->QueryDlpFileAccessByUid(dlpFileAccess, uid);
    permInfoParcel.permInfo_.dlpFileAccess = dlpFileAccess;
    permInfoParcel.permInfo_.flags = GetDlpActionFlag(dlpFileAccess);
    return res;
}

int32_t DlpPermissionService::IsInDlpSandbox(bool& inSandbox)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    return appStateObserver_->IsInDlpSandbox(inSandbox, uid);
}

void DlpPermissionService::GetCfgFilesList(std::vector<std::string> &cfgFilesList)
{
    CfgFiles *cfgFiles = GetCfgFiles(DLP_CONFIG.c_str()); // need free
    if (cfgFiles != nullptr) {
        for (auto &cfgPath : cfgFiles->paths) {
            if (cfgPath != nullptr) {
                cfgFilesList.emplace_back(cfgPath);
            }
        }
        FreeCfgFiles(cfgFiles); // free memory
    }
    std::reverse(cfgFilesList.begin(), cfgFilesList.end()); // priority from low to high, need reverse
}

void DlpPermissionService::GetConfigFileValue(const std::string &cfgFile, std::vector<std::string> &typeList)
{
    std::string content;
    (void)FileOperator().GetFileContentByPath(cfgFile, content);
    if (content.empty()) {
        return ;
    }
    auto jsonObj = nlohmann::json::parse(content, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_WARN(LABEL, "JsonObj is discarded");
        return ;
    }
    if (jsonObj.find(SUPPORT_FILE_TYPE) != jsonObj.end() && jsonObj.at(SUPPORT_FILE_TYPE).is_array()
        && !jsonObj.at(SUPPORT_FILE_TYPE).empty() && jsonObj.at(SUPPORT_FILE_TYPE).at(0).is_string()) {
        typeList = jsonObj.at(SUPPORT_FILE_TYPE).get<std::vector<std::string>>();
    }
}

std::vector<std::string> DlpPermissionService::InitConfig()
{
    static std::vector<std::string> typeList;
    static bool cfgInit = true;
    std::lock_guard<std::mutex> lock(mutex_);
    if (cfgInit) {
        cfgInit = false;
        std::vector<std::string> cfgFilesList;
        GetCfgFilesList(cfgFilesList);
        for (const auto &cfgFile : cfgFilesList) {
            GetConfigFileValue(cfgFile, typeList);
            if (!typeList.empty()) {
                break;
            }
        }
        if (typeList.empty()) {
            DLP_LOG_INFO(LABEL, "get config value failed, use default file path");
            GetConfigFileValue(DEAULT_DLP_CONFIG, typeList);
            if (typeList.empty()) {
                DLP_LOG_ERROR(LABEL, "support file type list is empty");
            }
        }
    }
    return typeList;
}

int32_t DlpPermissionService::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    supportFileType = InitConfig();
    return DLP_OK;
}

int32_t DlpPermissionService::RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject> &callback)
{
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    DLP_LOG_INFO(LABEL, "GetCallingRealPid,%{public}d", pid);
    return DlpSandboxChangeCallbackManager::GetInstance().AddCallback(pid, callback);
}

int32_t DlpPermissionService::UnRegisterDlpSandboxChangeCallback(bool &result)
{
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    DLP_LOG_INFO(LABEL, "GetCallingRealPid,%{public}d", pid);
    return DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(pid, result);
}

int32_t DlpPermissionService::RegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    std::string callerBundleName;
    if (!GetCallerBundleName(IPCSkeleton::GetCallingTokenID(), callerBundleName)) {
        DLP_LOG_ERROR(LABEL, "get callerBundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    if (GetUserIdFromUid(uid, &userId) != 0) {
        DLP_LOG_ERROR(LABEL, "GetUserIdFromUid error");
        return false;
    }
    int32_t pid = IPCSkeleton::GetCallingRealPid();

    DLP_LOG_INFO(LABEL, "CallingPid: %{public}d, userId: %{public}d, CallingBundle: %{public}s", pid, userId,
        callerBundleName.c_str());

    int res = OpenDlpFileCallbackManager::GetInstance().AddCallback(pid, userId, callerBundleName, callback);
    if (res != DLP_OK) {
        return res;
    }
    appStateObserver_->AddCallbackListener(pid);
    return DLP_OK;
}

int32_t DlpPermissionService::UnRegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback)
{
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    int32_t res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(pid, callback);
    appStateObserver_->RemoveCallbackListener(pid);
    return res;
}

int32_t DlpPermissionService::GetDlpGatheringPolicy(bool& isGathering)
{
    isGathering = isGathering_;
#if defined(DLP_DEBUG_ENABLE) && DLP_DEBUG_ENABLE == 1
    const char* PARAM_KEY = "dlp.permission.gathering.policy";
    const int32_t VALUE_MAX_LEN = 32;
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(PARAM_KEY, "false", value, VALUE_MAX_LEN - 1);
    if (ret <= 0) {
        DLP_LOG_WARN(LABEL, "Failed to get parameter, %{public}s", PARAM_KEY);
        return DLP_OK;
    }

    std::string tmp(value);
    if (tmp == "true") {
        isGathering = true;
    }

    if (tmp == "false") {
        isGathering = false;
    }
#endif
    return DLP_OK;
}

int32_t DlpPermissionService::SetRetentionState(const std::vector<std::string>& docUriVec)
{
    if (docUriVec.empty()) {
        DLP_LOG_ERROR(LABEL, "get docUriVec empty");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    RetentionInfo info;
    info.tokenId = IPCSkeleton::GetCallingTokenID();
    std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
    return RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
}

int32_t DlpPermissionService::CancelRetentionState(const std::vector<std::string>& docUriVec)
{
    if (docUriVec.empty()) {
        DLP_LOG_ERROR(LABEL, "get docUriVec empty");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    RetentionInfo info;
    info.tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetCallerBundleName(info.tokenId, info.bundleName)) {
        DLP_LOG_ERROR(LABEL, "get callerBundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool isInSandbox = false;
    IsInDlpSandbox(isInSandbox);
    if (!isInSandbox) {
        info.tokenId = 0;
    }
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(terminalMutex_);
        std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
        res = RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, false);
        if (isInSandbox) {
            return res;
        }
        std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
        int32_t getRes = RetentionFileManager::GetInstance().GetRetentionSandboxList(info.bundleName,
            retentionSandBoxInfoVec, false);
        if (getRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "getRes != DLP_OK");
            return getRes;
        }
        if (!retentionSandBoxInfoVec.empty()) {
            if (!RemoveRetentionInfo(retentionSandBoxInfoVec, info)) {
                return DLP_SERVICE_ERROR_VALUE_INVALID;
            }
        }
    }
    return res;
}

bool DlpPermissionService::RemoveRetentionInfo(std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec,
    RetentionInfo& info)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    if (GetUserIdFromUid(uid, &userId) != 0) {
        DLP_LOG_ERROR(LABEL, "get GetUserIdFromUid error");
        return false;
    }
    for (auto iter = retentionSandBoxInfoVec.begin(); iter != retentionSandBoxInfoVec.end(); ++iter) {
        if (appStateObserver_->CheckSandboxInfo(info.bundleName, iter->appIndex_, userId)) {
            continue;
        }
        DeleteDlpSandboxInfo(info.bundleName, iter->appIndex_, userId);
        UninstallDlpSandboxApp(info.bundleName, iter->appIndex_, userId);
        RetentionFileManager::GetInstance().RemoveRetentionState(info.bundleName, iter->appIndex_);
    }
    return true;
}

void DlpPermissionService::StartTimer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    repeatTime_ = REPEAT_TIME;
    if (thread_ != nullptr && !thread_->joinable()) { // avoid double assign to an active thread
        DLP_LOG_ERROR(LABEL, "thread is active");
        return;
    }
    thread_ = std::make_shared<std::thread>(&DlpPermissionService::TerminalService, this);
    thread_->detach();
    return;
}

void DlpPermissionService::TerminalService()
{
    DLP_LOG_DEBUG(LABEL, "enter");
    int32_t remainingTime = repeatTime_.load();
    while (remainingTime > 0) {
        std::this_thread::sleep_for(SLEEP_TIME);
        repeatTime_--;
        remainingTime = repeatTime_.load();
        DLP_LOG_DEBUG(LABEL, "repeatTime_ %{public}d", remainingTime);
    }
    std::lock_guard<std::mutex> lock(terminalMutex_);
    appStateObserver_->ExitSaAfterAllDlpManagerDie();
}

int32_t DlpPermissionService::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    std::string callerBundleName;
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    GetCallerBundleName(tokenId, callerBundleName);
    bool isNeedTimer = true;
    if (callerBundleName == DLP_MANAGER) {
        callerBundleName = bundleName;
        isNeedTimer = false;
    }
    if (callerBundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "get bundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto res =
        RetentionFileManager::GetInstance().GetRetentionSandboxList(callerBundleName, retentionSandBoxInfoVec, true);
    if (!isNeedTimer) {
        return res;
    }
    return res;
}

int32_t DlpPermissionService::ClearUnreservedSandbox()
{
    std::lock_guard<std::mutex> lock(terminalMutex_);
    RemoveUninstallInfo();
    RetentionFileManager::GetInstance().ClearUnreservedSandbox();
    return DLP_OK;
}

void DlpPermissionService::RemoveUninstallInfo()
{
    int32_t userId;
    if (!GetUserIdByActiveAccount(&userId)) {
        DLP_LOG_ERROR(LABEL, "get userID fail");
        return;
    }
    std::set<std::string> kvBundleNameSet;
    std::set<std::string> retentionBundleNameSet;
    std::set<std::string> retentionUninstallBundleNameSet;
    SandboxConfigKvDataStorage::GetInstance().GetKeySetByUserId(userId, kvBundleNameSet);
    RetentionFileManager::GetInstance().GetBundleNameSetByUserId(userId, retentionBundleNameSet);
    std::set<std::string> bundleNameSet;
    std::set_union(std::begin(kvBundleNameSet), std::end(kvBundleNameSet), std::begin(retentionBundleNameSet),
        std::end(retentionBundleNameSet), std::inserter(bundleNameSet, std::begin(bundleNameSet)));
    if (bundleNameSet.size() == 0) {
        return;
    }
    AppExecFwk::BundleInfo bundleInfo;
    for (auto it = bundleNameSet.begin(); it != bundleNameSet.end(); ++it) {
        int32_t res = BundleManagerAdapter::GetInstance().GetBundleInfoV9(*it,
            AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
        DLP_LOG_DEBUG(LABEL, "GetBundleInfo %{public}s, res:%{public}d", it->c_str(), res);
        if (res != ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
            continue;
        }
        if (kvBundleNameSet.count(*it) != 0) {
            SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(userId, *it);
        }
        if (retentionBundleNameSet.count(*it) != 0) {
            retentionUninstallBundleNameSet.emplace(*it);
        }
    }
    RetentionFileManager::GetInstance().RemoveRetentionInfoByUserId(userId, retentionUninstallBundleNameSet);
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
        std::lock_guard<std::mutex> lock(terminalMutex_);
        result = VisitRecordFileManager::GetInstance().GetVisitRecordList(callerBundleName, userId, infoVec);
    }
    return result;
}

int32_t DlpPermissionService::SetMDMPolicy(const std::vector<std::string>& appIdList)
{
    if (appIdList.empty()) {
        DLP_LOG_ERROR(LABEL, "get appIdList empty");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    return DlpCredential::GetInstance().SetMDMPolicy(appIdList);
}

int32_t DlpPermissionService::GetMDMPolicy(std::vector<std::string>& appIdList)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    return DlpCredential::GetInstance().GetMDMPolicy(appIdList);
}

int32_t DlpPermissionService::RemoveMDMPolicy()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != EDM_UID) {
        DLP_LOG_ERROR(LABEL, "invalid caller");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    return DlpCredential::GetInstance().RemoveMDMPolicy();
}

int32_t DlpPermissionService::SetSandboxAppConfig(const std::string& configInfo)
{
    if (configInfo.size() >= OHOS::DistributedKv::Entry::MAX_VALUE_LENGTH) {
        DLP_LOG_ERROR(LABEL, "configInfo is too long");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    std::string temp = configInfo;
    return SandboxConfigOperate(temp, SandboxConfigOperationEnum::ADD);
}

int32_t DlpPermissionService::CleanSandboxAppConfig()
{
    std::string emptyStr = "";
    return SandboxConfigOperate(emptyStr, SandboxConfigOperationEnum::CLEAN);
}

int32_t DlpPermissionService::GetSandboxAppConfig(std::string& configInfo)
{
    return SandboxConfigOperate(configInfo, SandboxConfigOperationEnum::GET);
}

int32_t DlpPermissionService::IsDLPFeatureProvided(bool& isProvideDLPFeature)
{
    std::string value = OHOS::system::GetParameter(DLP_ENABEL, "");
    if (value == TRUE_VALUE) {
        isProvideDLPFeature = true;
        return DLP_OK;
    }
    if (value == FALSE_VALUE) {
        isProvideDLPFeature = false;
        return DLP_OK;
    }
    isProvideDLPFeature = false;
    return DLP_OK;
}

int32_t DlpPermissionService::SandboxConfigOperate(std::string& configInfo, SandboxConfigOperationEnum operationEnum)
{
    std::string callerBundleName;
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    bool result = GetCallerBundleName(tokenId, callerBundleName);
    if (!result) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t userId = GetCallingUserId();
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "get userId error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = DlpCredential::GetInstance().CheckMdmPermission(callerBundleName, userId);
    if (res != DLP_OK) {
        return res;
    }
    switch (operationEnum) {
        case ADD:
            res = SandboxConfigKvDataStorage::GetInstance().AddSandboxConfigIntoDataStorage(userId, callerBundleName,
                configInfo);
            break;
        case GET:
            res = SandboxConfigKvDataStorage::GetInstance().GetSandboxConfigFromDataStorage(userId, callerBundleName,
                configInfo);
            break;
        case CLEAN:
            res = SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(userId,
                callerBundleName);
            break;
        default:
            DLP_LOG_ERROR(LABEL, "enter default case");
            break;
    }
    return res;
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
        if (appStateObserver_ != nullptr) {
            appStateObserver_->DumpSandbox(fd);
        } else {
            return ERR_INVALID_VALUE;
        }
    }

    return ERR_OK;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
