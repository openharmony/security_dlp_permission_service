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
#include <unistd.h>
#include "accesstoken_kit.h"
#include "access_token_adapter.h"
#include "account_adapt.h"
#include "appexecfwk_errors.h"
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
#include "dlp_dfx_define.h"
#include "dlp_permission_service_common.h"
#include "file_operator.h"
#include "file_uri.h"
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
#include "os_account_manager.h"
#include "permission_manager_adapter.h"
#include "alg_utils.h"
#include "dlp_feature_info.h"
#include "image_source_native_impl.h"
#include "pixelmap_native_impl.h"
#include "directory_ex.h"
#include "ohos_account_kits.h"
#include "dlp_ability_stub.h"
#include "dlp_ability_adapter.h"
#include "critical_handler.h"
#include "critical_helper.h"
#include "account_status_listener.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;
namespace {
constexpr const int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
static const std::string ALLOW_ACTION[] = {"ohos.want.action.CREATE_FILE"};
static const std::string DLP_MANAGER = "com.ohos.dlpmanager";
static const std::string SETTINGS_BUNDLE_NAME = "com.huawei.hmos.settings";
static const std::string DLP_CONFIG = "etc/dlp_permission/dlp_config.json";
static const std::string SUPPORT_FILE_TYPE = "support_file_type";
static const std::string DEAULT_DLP_CONFIG = "/system/etc/dlp_config.json";
static const std::string DEVELOPER_MODE = "const.security.developermode.state";
static const std::string FALSE_VALUE = "false";
static const std::string SEPARATOR = "_";
static const std::string PASTEBOARD_SERVICE_NAME = "pasteboard_service";
static const std::string DISTRIBUTED_DATA_NAME = "distributeddata";
static const uint32_t MAX_SUPPORT_FILE_TYPE_NUM = 1024;
static const uint32_t MAX_RETENTION_SIZE = 1024;
static const uint32_t MAX_BUNDLENAME_SIZE = 1024;
static const uint32_t MAX_CERT_SIZE = 1024 * 1024 * 40 * 2;
static const int32_t HIPREVIEW_SANDBOX_LOW_BOUND = 1000;
static const int32_t LIBCESFWK_SERVICES_ID = 3299;
constexpr int32_t PARSE_WAIT_TIME_OUT = 5;
static AccountListenerCallback *g_accountListenerCallback = nullptr;
static const std::vector<std::string> SANDBOX_WHITELIST = { HIPREVIEW_LOW, SETTINGS_BUNDLE_NAME };
}
REGISTER_SYSTEM_ABILITY_BY_ID(DlpPermissionService, SA_ID_DLP_PERMISSION_SERVICE, true);

DlpPermissionService::DlpPermissionService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    DLP_LOG_INFO(LABEL, "DlpPermissionService()");
}

DlpPermissionService::~DlpPermissionService()
{
    DLP_LOG_INFO(LABEL, "~DlpPermissionService()");
    sptr<AppExecFwk::IAppMgr> appMgr;
    sptr<AppStateObserver> observer;
    {
        std::unique_lock<std::shared_mutex> lock(serviceMemberMutex_);
        appMgr = iAppMgr_;
        observer = appStateObserver_;
        iAppMgr_ = nullptr;
        appStateObserver_ = nullptr;
    }
    if (appMgr != nullptr && observer != nullptr) {
        appMgr->UnregisterApplicationStateObserver(observer);
    }
    std::unique_lock<std::shared_mutex> lock(dlpSandboxDataMutex_);
    dlpSandboxData_.clear();
}

static bool IsSaCall()
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::TypeATokenTypeEnum res = Security::AccessToken::AccessTokenKit::GetTokenType(callingToken);
    return (res == Security::AccessToken::TOKEN_NATIVE);
}

sptr<AppStateObserver> DlpPermissionService::GetAppStateObserver(CurrentTaskState taskState)
{
    sptr<AppStateObserver> observer;
    {
        std::shared_lock<std::shared_mutex> lock(serviceMemberMutex_);
        observer = appStateObserver_;
    }
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetAppStateObserver observer is nullptr");
        return observer;
    }
    observer->PostDelayUnloadTask(taskState);
    return observer;
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
    bool ret = Publish(this);
    if (!ret) {
        DLP_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    if (!AddSystemAbilityListener(LIBCESFWK_SERVICES_ID)) {
        DLP_LOG_ERROR(LABEL, "add common event system ability listener failed");
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    (void)NotifyProcessIsActive();
    DLP_LOG_INFO(LABEL, "Congratulations, DlpPermissionService start successfully!");
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer != nullptr) {
        observer->PostDelayUnloadTask(CurrentTaskState::IDLE);
    }
    DLP_LOG_INFO(LABEL, "DlpPermissionService set timer to destroy itself!");
}

void DlpPermissionService::OnStop()
{
    DLP_LOG_INFO(LABEL, "Stop service");
    dlpEventSubSubscriber_ = nullptr;
    (void)NotifyProcessIsStop();
    UnRegisterAccountMonitor();
    HcFree(g_accountListenerCallback);
    g_accountListenerCallback = nullptr;
}

void DlpPermissionService::UnregisterAccount()
{
    DLP_LOG_INFO(LABEL, "UnregisterAccount Start.");
    DelSandboxInfoByAccount(false);
}

void DlpPermissionService::RegisterAccount()
{
    DLP_LOG_INFO(LABEL, "RegisterAccount Start.");
    DelSandboxInfoByAccount(true);
}

void DlpPermissionService::DelWaterMarkInfo()
{
    std::unique_lock<std::mutex> lock(waterMarkInfoMutex_);
    waterMarkInfo_.accountAndUserId = "";
    DLP_LOG_DEBUG(LABEL, "Clear watermark info.");
}

void DlpPermissionService::DelSandboxInfoByAccount(bool isRegister)
{
    DLP_LOG_INFO(LABEL, "DelSandboxInfoByAccount");
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        return;
    }
    int32_t foregroundUserId = 0;
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundUserId);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "GetForegroundOsAccountLocalId failed");
        return;
    }
    std::string localAccount = "";
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (accountInfo.first) {
        localAccount = accountInfo.second.name_;
    }
    std::unordered_map<int32_t, DlpSandboxInfo> sandboxInfo;
    observer->GetDelSandboxInfo(sandboxInfo);
    for (const auto& entry : sandboxInfo) {
        const DlpSandboxInfo& sandboxInfoEntry = entry.second;
        std::string bundleName = sandboxInfoEntry.bundleName;
        int32_t appIndex = sandboxInfoEntry.appIndex;
        int32_t userId = sandboxInfoEntry.userId;
        std::string accountName = sandboxInfoEntry.accountName;
        if (!isRegister && (userId != foregroundUserId || accountName == "")) {
            continue;
        }
        if (isRegister &&
            (userId != foregroundUserId || accountName == "" || accountName == localAccount)) {
            continue;
        }
        DeleteDlpSandboxInfo(bundleName, appIndex, userId);
        if (bundleName == HIPREVIEW_HIGH) {
            int32_t bindAppIndex = sandboxInfoEntry.bindAppIndex;
            if (UninstallDlpSandboxApp(HIPREVIEW_LOW, bindAppIndex, userId) != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "UninstallDlpSandboxApp failed, bindAppIndex=%d",  bindAppIndex);
            } else {
                DLP_LOG_INFO(LABEL, "UninstallDlpSandboxApp success, bindAppIndex=%d", bindAppIndex);
            }
        }
        UninstallDlpSandboxApp(bundleName, appIndex, userId);
        RetentionFileManager::GetInstance().RemoveRetentionState(bundleName, appIndex);
        DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(sandboxInfoEntry);
    }
    DelWaterMarkInfo();
}

int32_t DlpPermissionService::InitAccountListenerCallback()
{
    DLP_LOG_INFO(LABEL, "Init AccountListenerCallback Start.");
    if (g_accountListenerCallback != nullptr) {
        return DLP_SUCCESS;
    }
    g_accountListenerCallback = (AccountListenerCallback *)HcMalloc(sizeof(AccountListenerCallback), 0);
    if (g_accountListenerCallback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate AccountListenerCallback memory failed!");
        return DLP_ERROR;
    }
    g_accountListenerCallback->registerAccount = std::bind(&DlpPermissionService::RegisterAccount, this);
    g_accountListenerCallback->unregisterAccount = std::bind(&DlpPermissionService::UnregisterAccount, this);
    return DLP_SUCCESS;
}

void DlpPermissionService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    DLP_LOG_INFO(LABEL, "OnAddSystemAbility systemAbilityId %{public}d", systemAbilityId);
    if (systemAbilityId == LIBCESFWK_SERVICES_ID) {
        if (InitAccountListenerCallback() != DLP_SUCCESS) {
            DLP_LOG_ERROR(LABEL, "Init the account listener callback failed!");
            return;
        }
        if (RegisterAccountEventMonitor(g_accountListenerCallback) != DLP_SUCCESS) {
            DLP_LOG_ERROR(LABEL, "Register the monitor of account status commom event failed!");
            return;
        }
    }
}

bool DlpPermissionService::RegisterAppStateObserver()
{
    if (appStateObserver_ != nullptr) {
        DLP_LOG_INFO(LABEL, "AppStateObserver instance already create");
        return true;
    }
    sptr<AppStateObserver> tempAppStateObserver = new (std::nothrow) AppStateObserver();
    if (tempAppStateObserver == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to create AppStateObserver instance");
        return false;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get system ability manager");
        return false;
    }
    auto obj = samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID);
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(obj);
    if (iAppMgr_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get ability manager service");
        return false;
    }
    int32_t result = iAppMgr_->RegisterApplicationStateObserver(tempAppStateObserver);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Failed to Register app state observer");
        iAppMgr_ = nullptr;
        return false;
    }
    sptr<AppExecFwk::AppMgrProxy> proxy = new (std::nothrow)AppExecFwk::AppMgrProxy(obj);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to create AppMgrProxy instance");
        iAppMgr_->UnregisterApplicationStateObserver(tempAppStateObserver);
        iAppMgr_ = nullptr;
        return false;
    }
    appStateObserver_ = tempAppStateObserver;
    appStateObserver_->SetAppProxy(proxy);
    return true;
}

int32_t DlpPermissionService::GenerateDlpCertificate(
    const sptr<DlpPolicyParcel>& policyParcel, const sptr<IDlpPermissionCallback>& callback)
{
    CriticalHelper criticalHelper("GenerateDlpCertificate");
    auto observer = GetAppStateObserver(CurrentTaskState::LONG_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (!PermissionManagerAdapter::CheckSystemAppAndPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !(appIdentifier == MDM_APPIDENTIFIER)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!policyParcel->policyParams_.IsValid()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    policyParcel->policyParams_.SetDebug(OHOS::system::GetBoolParameter(DEVELOPER_MODE, false));
    unordered_json jsonObj;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeDlpPermission(
        policyParcel->policyParams_, jsonObj);
    if (res != DLP_OK) {
        return res;
    }
    res = DlpCredential::GetInstance().GenerateDlpCertificate(
        jsonObj.dump(), policyParcel->policyParams_.ownerAccountId_,
        policyParcel->policyParams_.ownerAccountType_, callback);
    return res;
}

static bool GetApplicationInfo(std::string appId, AppExecFwk::ApplicationInfo& applicationInfo)
{
    size_t pos = appId.find_last_of(SEPARATOR);
    if (pos > appId.length()) {
        DLP_LOG_ERROR(LABEL, "AppId=%{private}s pos=%{public}zu can not find bundleName", appId.c_str(), pos);
        return false;
    }
    std::string bundleName = appId.substr(0, pos);

    int32_t userId = GetCallingUserId();
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "Get userId error.");
        return false;
    }
    if (!BundleManagerAdapter::GetInstance().GetApplicationInfo(bundleName,
        OHOS::AppExecFwk::ApplicationFlag::GET_ALL_APPLICATION_INFO, userId, applicationInfo)) {
        DLP_LOG_ERROR(LABEL, "Get applicationInfo error bundleName=%{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

int32_t DlpPermissionService::ParseDlpCertificate(const sptr<CertParcel>& certParcel,
    const sptr<IDlpPermissionCallback>& callback, const std::string& appId, bool offlineAccess)
{
    CriticalHelper criticalHelper("ParseDlpCertificate");
    auto observer = GetAppStateObserver(CurrentTaskState::LONG_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifierForCalling error");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (!PermissionManagerAdapter::CheckSystemAppAndPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !(appIdentifier == MDM_APPIDENTIFIER)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    if (callback == nullptr || certParcel->cert.size() > MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Callback is null or cert is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (appId.empty() || appId.size() > MAX_APPID_SIZE) {
        DLP_LOG_ERROR(LABEL, "AppId is invalid");
        return DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED;
    }
    int32_t ret = PermissionManagerAdapter::CheckAuthPolicy(appId, certParcel->realFileType,
        certParcel->allowedOpenCount);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "CheckAuthPolicy error");
        return ret;
    }
    AppExecFwk::ApplicationInfo applicationInfo;
    if (!GetApplicationInfo(appId, applicationInfo)) {
        DLP_LOG_ERROR(LABEL, "Permission check fail.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    ret = DlpCredential::GetInstance().ParseDlpCertificate(
        certParcel, callback, appId, offlineAccess, applicationInfo);
    return ret;
}

static int32_t ConcatAccountAndUserId(std::string& accountAndUserId)
{
    int32_t userId = GetCallingUserId();
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "Get userId error.");
        return DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL;
    }
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        DLP_LOG_ERROR(LABEL, "Get accountInfo error.");
        return DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL;
    }
    accountAndUserId = accountInfo.second.name_ + std::to_string(userId);
    return DLP_OK;
}

int32_t DlpPermissionService::CheckWaterMarkInfo()
{
    std::string accountAndUserId;
    int32_t ret = ConcatAccountAndUserId(accountAndUserId);
    if (ret != DLP_OK) {
        return DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL;
    }
    if (waterMarkInfo_.accountAndUserId == accountAndUserId) {
        return DLP_OK;
    }
    DLP_LOG_INFO(LABEL, "Change account or has not watermark");
    return DLP_SERVICE_ERROR_VALUE_INVALID;
}

static int32_t ReceiveCallback(int32_t errCode, uint64_t reqId, uint8_t *outData, uint32_t outDataLen)
{
    (void)errCode;
    DLP_LOG_INFO(LABEL, "Enter receive data callback.");
    return DLP_OK;
}

static int32_t GetPixelmapFromFd(WaterMarkInfo& waterMarkInfo)
{
    if (waterMarkInfo.waterMarkFd < 0) {
        DLP_LOG_ERROR(LABEL, "unexpect watermark.");
        return DLP_IPC_CALLBACK_ERROR;
    }

    OH_ImageSourceNative *source = nullptr;
    OH_DecodingOptions *decodingOpts = nullptr;
    OH_PixelmapNative *resPixelmap = nullptr;
    Image_ErrorCode err = IMAGE_BAD_PARAMETER;

    do {
        err = OH_ImageSourceNative_CreateFromFd(waterMarkInfo.waterMarkFd, &source);
        if (err != IMAGE_SUCCESS) {
            break;
        }
        err = OH_DecodingOptions_Create(&decodingOpts);
        if (err != IMAGE_SUCCESS) {
            break;
        }
        err = OH_ImageSourceNative_CreatePixelmapUsingAllocator(
            source, decodingOpts, IMAGE_ALLOCATOR_TYPE_DMA, &resPixelmap);
        if (err != IMAGE_SUCCESS) {
            break;
        }
        waterMarkInfo.waterMarkImg = resPixelmap->GetInnerPixelmap();
        DLP_LOG_INFO(LABEL, "watermark pixelmap size: %{public}d", waterMarkInfo.waterMarkImg->GetCapacity());
    } while (0);
    if (waterMarkInfo.waterMarkFd >= 0) {
        close(waterMarkInfo.waterMarkFd);
        waterMarkInfo.waterMarkFd = -1;
    }
    if (resPixelmap) {
        delete resPixelmap;
    }
    if (decodingOpts) {
        OH_DecodingOptions_Release(decodingOpts);
    }
    if (source) {
        OH_ImageSourceNative_Release(source);
        if (source) {
            delete source;
            source = nullptr;
        }
    }
    return err == IMAGE_SUCCESS ? DLP_OK : DLP_CREATE_PIXELMAP_ERROR;
}

static int32_t SetWatermarkToRS(const std::string &name, std::shared_ptr<Media::PixelMap> watermarkImg)
{
    Rosen::SaSurfaceWatermarkMaxSize pixelmapSize =
        Rosen::SaSurfaceWatermarkMaxSize::SA_WATER_MARK_MIDDLE_SIZE;
    auto &rs = Rosen::RSInterfaces::GetInstance();
    bool res = rs.SetWatermark(name, watermarkImg, pixelmapSize);
    if (!res) {
        DLP_LOG_WARN(LABEL, "SetWatermark to RS failed, will try again");
        res = rs.SetWatermark(name, watermarkImg, pixelmapSize);
    }
    if (!res) {
        DLP_LOG_ERROR(LABEL, "SetWatermark to RS failed again");
        return DLP_SET_WATERMARK_TO_RS_ERROR;
    }
    DLP_LOG_INFO(LABEL, "Set watermark to RS success");
    return DLP_OK;
}

int32_t DlpPermissionService::ChangeWaterMarkInfo()
{
    std::string accountAndUserId;
    int32_t res = ConcatAccountAndUserId(accountAndUserId);
    if (res != DLP_OK) {
        return DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL;
    }

    if (!waterMarkInfo_.waterMarkImg || waterMarkInfo_.maskInfo.empty()) {
        DLP_LOG_ERROR(LABEL, "SetWaterMark params are invalid");
        return DLP_SET_WATERMARK_ERROR;
    }
    res = SetWatermarkToRS(waterMarkInfo_.maskInfo, waterMarkInfo_.waterMarkImg);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SetWatermarkToRS failed");
        return DLP_SET_WATERMARK_TO_RS_ERROR;
    }
    waterMarkInfo_.waterMarkImg = nullptr;
    waterMarkInfo_.accountAndUserId = accountAndUserId;
    return DLP_OK;
}

int32_t DlpPermissionService::GetWaterMark(const bool waterMarkConfig,
    const sptr<IDlpPermissionCallback>& callback)
{
    std::unique_lock<std::mutex> lock(waterMarkInfoMutex_);
    CriticalHelper criticalHelper("GetWaterMark");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (callback == nullptr || !waterMarkConfig) {
        DLP_LOG_ERROR(LABEL, "GetWaterMark callback is null or no watermarkConfig");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = CheckWaterMarkInfo();
    if (res == DLP_OK) {
        return DLP_OK;
    }

    int32_t userId = GetCallingUserId();
    auto wmInfo = std::make_shared<WaterMarkInfo>();
    ReceiveDataCallback recvCallback = ReceiveCallback;
    DlpAbilityAdapter dlpAbilityAdapter(recvCallback);
    dlpAbilityAdapter.HandleGetWaterMark(userId, wmInfo, waterMarkInfoCv_);

    waterMarkInfoCv_.wait_for(lock, std::chrono::seconds(PARSE_WAIT_TIME_OUT));
    if (wmInfo->waterMarkFd < 0) {
        DLP_LOG_ERROR(LABEL, "Get watermark fd failed.");
        return DLP_IPC_CALLBACK_ERROR;
    }
    waterMarkInfo_.waterMarkFd = wmInfo->waterMarkFd;
    waterMarkInfo_.maskInfo = wmInfo->maskInfo;
    res = GetPixelmapFromFd(waterMarkInfo_);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetPixelmapFromFd failed.");
        return DLP_CREATE_PIXELMAP_ERROR;
    }

    res = ChangeWaterMarkInfo();
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Change watermark info failed.");
        return res;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::GetDomainAccountNameInfo(std::string& accountNameInfo)
{
    CriticalHelper criticalHelper("GetDomainAccountNameInfo");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string appIdentifier;
    if (!PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier)) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifierForCalling error");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !(appIdentifier == MDM_APPIDENTIFIER)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

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
    accountNameInfo = domainInfo.accountName_;
    return DLP_OK;
}

int32_t DlpPermissionService::GetAbilityInfos(const AAFwk::Want& want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    CriticalHelper criticalHelper("GetAbilityInfos");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE) &&
        !PermissionManagerAdapter::CheckPermission(PERMISSION_ENTERPRISE_ACCESS_DLP_FILE) &&
        !IsSaCall()) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    int32_t ret = BundleManagerAdapter::GetInstance().GetAbilityInfosV9(want, flags, userId, abilityInfos);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "GetAbilityInfosV9 failed %{public}d", ret);
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::SetWaterMark(const int32_t pid)
{
    std::unique_lock<std::mutex> lock(waterMarkInfoMutex_);
    CriticalHelper criticalHelper("SetWaterMark");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    bool sandboxFlag;
    if (PermissionManagerAdapter::CheckSandboxFlagWithService(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a non-sandbox app");
        return DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR;
    }
    if (waterMarkInfo_.maskInfo.empty()) {
        DLP_LOG_ERROR(LABEL, "No watermark.");
        return DLP_SET_WATERMARK_ERROR;
    }
    int32_t ret = static_cast<int32_t>(Rosen::WindowManagerLite::
        GetInstance().SetProcessWatermark(pid, waterMarkInfo_.maskInfo, true));
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "SetProcessWatermark failed! errcode: %{public}d", ret);
        return DLP_SET_WATERMARK_ERROR;
    }
    return DLP_OK;
}

static void FillSandboxInfoFromFileInfo(DlpSandboxInfo& sandboxInfo, const FileInfo& fileInfo)
{
    if (fileInfo.accountName != "") {
        sandboxInfo.accountName = fileInfo.accountName;
    }
    sandboxInfo.isReadOnce = fileInfo.isNotOwnerAndReadOnce;
    sandboxInfo.isWatermark = fileInfo.isWatermark;
    sandboxInfo.accountAndUserId = fileInfo.accountName + std::to_string(sandboxInfo.userId);
    sandboxInfo.maskInfo = fileInfo.maskInfo;
    sandboxInfo.fileId = fileInfo.fileId;
    DLP_LOG_INFO(LABEL, "isNotOwnerAndReadOnce=%{public}d, isWatermark=%{public}d",
        fileInfo.isNotOwnerAndReadOnce, fileInfo.isWatermark);
}

static void FillSandboxInfoFromEnterpriseFileInfo(DlpSandboxInfo& sandboxInfo, const EnterpriseInfo& enterpriseInfo)
{
    sandboxInfo.fileId = enterpriseInfo.fileId;
    sandboxInfo.appIdentifier = enterpriseInfo.appIdentifier;
    sandboxInfo.classificationLabel = enterpriseInfo.classificationLabel;
    DLP_LOG_DEBUG(LABEL, "label=%s",
        enterpriseInfo.classificationLabel.c_str());
}

bool DlpPermissionService::InsertDlpSandboxInfo(DlpSandboxInfo& sandboxInfo, bool hasRetention)
{
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return false;
    }
    AppExecFwk::BundleInfo info;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    int32_t res = bundleMgrClient.GetSandboxBundleInfo(sandboxInfo.bundleName, sandboxInfo.appIndex,
        sandboxInfo.userId, info);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail appIndex=%{public}d, res = %{public}d",
            sandboxInfo.appIndex, res);
        int32_t isNotMatch = res == ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO ? 1 : 0;
        if (hasRetention) {
            DLP_LOG_INFO(LABEL,
                "APP is sandboxInfo.bundleName :%{public}s, isNotMatch=%{public}d",
                sandboxInfo.bundleName.c_str(), isNotMatch);
            RetentionFileManager::GetInstance().ClearUnreservedSandbox(isNotMatch);
        }
        return false;
    }
    sandboxInfo.uid = info.uid;
    sandboxInfo.tokenId = AccessToken::AccessTokenKit::GetHapTokenID(sandboxInfo.userId, sandboxInfo.bundleName,
        sandboxInfo.appIndex);
    observer->AddDlpSandboxInfo(sandboxInfo);
    SetHasBackgroundTask(true);
    VisitRecordFileManager::GetInstance().AddVisitRecord(sandboxInfo.bundleName, sandboxInfo.userId, sandboxInfo.uri);
    return true;
}

static bool FindMatchingSandbox(const RetentionSandBoxInfo& info, const GetAppIndexParams& params)
{
    if (params.isReadOnly && !params.isNotOwnerAndReadOnce && !info.isReadOnce_ &&
        info.dlpFileAccess_ == DLPFileAccess::READ_ONLY) {
        DLP_LOG_INFO(LABEL, "FindMatchingSandbox is success in first stage");
        return true;
    }
    if (params.isReadOnly) {
        return false;
    }
    auto setIter = info.docUriSet_.find(params.uri);
    if (setIter != info.docUriSet_.end()) {
        DLP_LOG_INFO(LABEL, "FindMatchingSandbox is success in second stage");
        return true;
    }
    return false;
}

static int32_t GetAppIndexFromRetentionInfo(const GetAppIndexParams& params,
    DlpSandboxInfo& dlpSandBoxInfo, bool& isNeedInstall)
{
    DLP_LOG_INFO(LABEL, "GetAppIndexFromRetentionInfo");
    std::vector<RetentionSandBoxInfo> infoVec;
    auto res = RetentionFileManager::GetInstance().GetRetentionSandboxList(params.bundleName, infoVec, true);
    DLP_LOG_INFO(LABEL, "GetRetentionSandboxList success, size=%zu", infoVec.size());
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetRetentionSandboxList fail bundleName:%{public}s, error=%{public}d",
            params.bundleName.c_str(), res);
        return res;
    }
    for (const auto& info: infoVec) {
        DLP_LOG_INFO(LABEL, "FindMatchingSandbox enter");
        if (FindMatchingSandbox(info, params)) {
            DLP_LOG_INFO(LABEL, "FindMatchingSandbox is success");
            dlpSandBoxInfo.appIndex = info.appIndex_;
            dlpSandBoxInfo.bindAppIndex = info.bindAppIndex_;
            dlpSandBoxInfo.hasRead = info.hasRead_;
            isNeedInstall = false;
            break;
        }
    }
    return DLP_OK;
}

static int32_t CheckWithInstallDlpSandbox(const std::string& bundleName, const std::string& uri,
    DLPFileAccess dlpFileAccess)
{
    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    if (bundleName.empty() || bundleName.size() > MAX_BUNDLENAME_SIZE || uri.size() > MAX_URI_SIZE ||
        dlpFileAccess > DLPFileAccess::FULL_CONTROL || dlpFileAccess <= DLPFileAccess::NO_PERMISSION) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

static void FillDlpSandboxInfo(DlpSandboxInfo& dlpSandboxInfo, const std::string& bundleName,
    DLPFileAccess dlpFileAccess, int32_t userId, const std::string& uri)
{
    DLP_LOG_INFO(LABEL,
        "bundleName :%{public}s, dlpFileAccess=%{public}d, userId:%{public}d",
        bundleName.c_str(), dlpFileAccess, userId);
    dlpSandboxInfo.bundleName = bundleName;
    dlpSandboxInfo.dlpFileAccess = dlpFileAccess;
    dlpSandboxInfo.userId = userId;
    dlpSandboxInfo.pid = IPCSkeleton::GetCallingRealPid();
    dlpSandboxInfo.uri = uri;
    dlpSandboxInfo.timeStamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

int32_t DlpPermissionService::InstallSandboxApp(const std::string& bundleName, DLPFileAccess dlpFileAccess,
    int32_t userId, DlpSandboxInfo& dlpSandboxInfo)
{
    AppExecFwk::BundleMgrClient bundleMgrClient;
    DLPFileAccess permForBMS =
        (dlpFileAccess == DLPFileAccess::READ_ONLY) ? DLPFileAccess::READ_ONLY : DLPFileAccess::CONTENT_EDIT;
    int32_t bundleClientRes = bundleMgrClient.InstallSandboxApp(bundleName,
        static_cast<int32_t>(permForBMS), userId, dlpSandboxInfo.appIndex);
    if (bundleClientRes != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "install sandbox %{public}s fail, %{public}d", bundleName.c_str(), bundleClientRes);
        return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
    }
    DLP_LOG_INFO(LABEL, "InstallSandboxApp success");
    return DLP_OK;
}

static void previewBindInstall(DlpSandboxInfo& sandboxInfo, int32_t userId, DLPFileAccess dlpFileAccess)
{
    if (sandboxInfo.bindAppIndex <= HIPREVIEW_SANDBOX_LOW_BOUND && sandboxInfo.appIndex > HIPREVIEW_SANDBOX_LOW_BOUND) {
        AppExecFwk::BundleMgrClient bundleMgrClient;
        DLPFileAccess permForBMS =
            (dlpFileAccess == DLPFileAccess::READ_ONLY) ? DLPFileAccess::READ_ONLY : DLPFileAccess::CONTENT_EDIT;
        int32_t bundleClientRes = bundleMgrClient.InstallSandboxApp(
            HIPREVIEW_LOW, static_cast<int32_t>(permForBMS), userId, sandboxInfo.bindAppIndex);
        if (bundleClientRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "install sandbox %{public}s fail, %{public}d", HIPREVIEW_LOW, bundleClientRes);
        } else {
            DLP_LOG_INFO(LABEL, "install sandbox %s success, appIndex: %d",
                HIPREVIEW_LOW, sandboxInfo.bindAppIndex);
        }
    } else {
        DLP_LOG_ERROR(LABEL, "previewBindInstall failed, bindAppIndex higher or appindex lower than low bound");
    }
}
 
static int32_t InstallDlpSandboxExecute(bool& isNeedInstall, DLPFileAccess& dlpFileAccess,
    const std::string& bundleName, int32_t& userId, DlpSandboxInfo& dlpSandboxInfo)
{
    DLP_LOG_INFO(LABEL, "InstallDlpSandbox %s, isNeedInstall=%d", bundleName.c_str(), isNeedInstall);
    if (isNeedInstall) {
        AppExecFwk::BundleMgrClient bundleMgrClient;
        DLPFileAccess permForBMS =
            (dlpFileAccess == DLPFileAccess::READ_ONLY) ? DLPFileAccess::READ_ONLY : DLPFileAccess::CONTENT_EDIT;
        int32_t bundleClientRes = bundleMgrClient.InstallSandboxApp(bundleName,
            static_cast<int32_t>(permForBMS), userId, dlpSandboxInfo.appIndex);
        if (bundleClientRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "install sandbox %{public}s fail, %{public}d", bundleName.c_str(), bundleClientRes);
            return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
        }
    }
    if (bundleName == HIPREVIEW_HIGH) {
        previewBindInstall(dlpSandboxInfo, userId, dlpFileAccess);
        DLP_LOG_INFO(LABEL,
            "InstallDlpSandbox %s, index %d, bindindex %d",
            bundleName.c_str(), dlpSandboxInfo.appIndex, dlpSandboxInfo.bindAppIndex);
    }
    return DLP_OK;
}

void DlpPermissionService::UpdateSandboxInstallResult(SandboxInfo& sandboxInfo, const DlpSandboxInfo& dlpSandboxInfo)
{
    sandboxInfo.appIndex = dlpSandboxInfo.appIndex;
    sandboxInfo.bindAppIndex = dlpSandboxInfo.bindAppIndex;
    sandboxInfo.tokenId = dlpSandboxInfo.tokenId;
    std::unique_lock<std::shared_mutex> lock(dlpSandboxDataMutex_);
    if (dlpSandboxData_.find(dlpSandboxInfo.uid) == dlpSandboxData_.end()) {
        dlpSandboxData_.insert(std::make_pair(dlpSandboxInfo.uid, dlpSandboxInfo.dlpFileAccess));
    }
}

int32_t DlpPermissionService::HandleEnterpriseInstallDlpSandbox(SandboxInfo& sandboxInfo,
    InputSandboxInfo& inputSandboxInfo, const EnterpriseInfo& enterpriseInfo)
{
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (observer->GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, enterpriseInfo)) {
        DLP_LOG_INFO(LABEL, "enterprise dlp file already opened, return install result directly");
        return DLP_OK;
    }

    bool isReadOnly = inputSandboxInfo.dlpFileAccess == DLPFileAccess::READ_ONLY;
    bool isNeedInstall = true;
    DlpSandboxInfo dlpSandboxInfo;
    int32_t res = DLP_OK;

    GetAppIndexParams params = {inputSandboxInfo.bundleName, isReadOnly, inputSandboxInfo.uri, false};
    res = GetAppIndexFromRetentionInfo(params, dlpSandboxInfo, isNeedInstall);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetAppIndexFromRetentionInfo fail, %{public}d", res);
        return res;
    }

    if (isNeedInstall && isReadOnly) {
        observer->GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo,
            dlpSandboxInfo);
        isNeedInstall = (dlpSandboxInfo.appIndex != -1) ? false : true;
    }

    res = InstallDlpSandboxExecute(isNeedInstall, inputSandboxInfo.dlpFileAccess,
        inputSandboxInfo.bundleName, inputSandboxInfo.userId, dlpSandboxInfo);
    if (res != DLP_OK) {
        observer->EraseEnterpriseInfoByUri(inputSandboxInfo.path, enterpriseInfo.fileId);
        return res;
    }

    FillDlpSandboxInfo(dlpSandboxInfo, inputSandboxInfo.bundleName, inputSandboxInfo.dlpFileAccess,
        inputSandboxInfo.userId, inputSandboxInfo.uri);
    FillSandboxInfoFromEnterpriseFileInfo(dlpSandboxInfo, enterpriseInfo);
    if (!InsertDlpSandboxInfo(dlpSandboxInfo, !isNeedInstall)) {
        UninstallDlpSandboxApp(inputSandboxInfo.bundleName, dlpSandboxInfo.appIndex, inputSandboxInfo.userId);
        observer->EraseEnterpriseInfoByUri(inputSandboxInfo.path, enterpriseInfo.fileId);
        return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
    }
    observer->UpdateEnterpriseUidByUri(inputSandboxInfo.path, enterpriseInfo.fileId, dlpSandboxInfo.uid);
    UpdateSandboxInstallResult(sandboxInfo, dlpSandboxInfo);
    return DLP_OK;
}

int32_t DlpPermissionService::HandleInstallDlpSandbox(SandboxInfo& sandboxInfo,
    InputSandboxInfo& inputSandboxInfo, const FileInfo& fileInfo)
{
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (observer->GetOpeningSandboxInfo(inputSandboxInfo.bundleName, inputSandboxInfo.uri,
        inputSandboxInfo.userId, sandboxInfo, fileInfo.fileId)) {
        DLP_LOG_INFO(LABEL, "GetOpeningSandboxInfo success");
        return DLP_OK;
    }
    bool isReadOnly = inputSandboxInfo.dlpFileAccess == DLPFileAccess::READ_ONLY;
    bool isNeedInstall = true;
    DlpSandboxInfo dlpSandboxInfo;
    GetAppIndexParams params = {inputSandboxInfo.bundleName, isReadOnly, inputSandboxInfo.uri,
        fileInfo.isNotOwnerAndReadOnce};
    int32_t res = GetAppIndexFromRetentionInfo(params, dlpSandboxInfo, isNeedInstall);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetAppIndexFromRetentionInfo fail, %{public}d", res);
        return res;
    }
    if (isNeedInstall && isReadOnly && !fileInfo.isNotOwnerAndReadOnce) {
        observer->GetOpeningReadOnlySandbox(inputSandboxInfo.bundleName, inputSandboxInfo.userId,
            dlpSandboxInfo.appIndex, dlpSandboxInfo.bindAppIndex);
        isNeedInstall = (dlpSandboxInfo.appIndex != -1) ? false : true;
    }

    res = InstallDlpSandboxExecute(isNeedInstall, inputSandboxInfo.dlpFileAccess,
        inputSandboxInfo.bundleName, inputSandboxInfo.userId, dlpSandboxInfo);
    if (res != DLP_OK) {
        return res;
    }
    FillDlpSandboxInfo(dlpSandboxInfo, inputSandboxInfo.bundleName, inputSandboxInfo.dlpFileAccess,
        inputSandboxInfo.userId, inputSandboxInfo.uri);
    FillSandboxInfoFromFileInfo(dlpSandboxInfo, fileInfo);
    if (!InsertDlpSandboxInfo(dlpSandboxInfo, !isNeedInstall)) {
        return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
    }
    UpdateSandboxInstallResult(sandboxInfo, dlpSandboxInfo);
    return DLP_OK;
}

int32_t DlpPermissionService::InstallDlpSandbox(const std::string& bundleName, DLPFileAccess dlpFileAccess,
    int32_t userId, SandboxInfo& sandboxInfo, const std::string& uri)
{
    CriticalHelper criticalHelper("InstallDlpSandbox");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!AccessTokenAdapter::IsSystemApp()) {
        return DLP_SERVICE_ERROR_NOT_SYSTEM_APP;
    }
    if (userId < 0) {
        DLP_LOG_ERROR(LABEL, "Invalid userId");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = CheckWithInstallDlpSandbox(bundleName, uri, dlpFileAccess);
    if (res != DLP_OK) {
        return res;
    }
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();
    InputSandboxInfo inputSandboxInfo = {bundleName, dlpFileAccess, userId, uri, path};

    EnterpriseInfo enterpriseInfo;
    if (observer->GetEnterpriseInfoByUri(path, enterpriseInfo)) {
        return HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo, enterpriseInfo);
    }

    FileInfo fileInfo;
    observer->GetFileInfoByUri(path, fileInfo);
    return HandleInstallDlpSandbox(sandboxInfo, inputSandboxInfo, fileInfo);
}

uint32_t DlpPermissionService::DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return 0;
    }
    AppExecFwk::BundleMgrClient bundleMgrClient;
    AppExecFwk::BundleInfo info;
    int32_t result = bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        return 0;
    }

    std::unique_lock<std::shared_mutex> lock(dlpSandboxDataMutex_);
    auto it = dlpSandboxData_.find(info.uid);
    if (it != dlpSandboxData_.end()) {
        dlpSandboxData_.erase(info.uid);
    }

    return observer->EraseDlpSandboxInfo(info.uid);
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
    CriticalHelper criticalHelper("UninstallDlpSandbox");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!AccessTokenAdapter::IsSystemApp()) {
        return DLP_SERVICE_ERROR_NOT_SYSTEM_APP;
    }
    if (!PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    if (bundleName.empty() || bundleName.size() > MAX_BUNDLENAME_SIZE || appIndex < 0 || userId < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    uint32_t tokenId = DeleteDlpSandboxInfo(bundleName, appIndex, userId);
    if (tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "DeleteDlpSandboxInfo sandbox %{public}s fail, index=%{public}d", bundleName.c_str(),
            appIndex);
        return DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL;
    }
    RetentionFileManager::GetInstance().SetInitStatus(tokenId);
    if (RetentionFileManager::GetInstance().CanUninstall(tokenId)) {
        if (bundleName == HIPREVIEW_HIGH) {
            DlpSandboxInfo sandboxInfo;
            observer->GetSandboxInfoByAppIndex(HIPREVIEW_HIGH, appIndex, sandboxInfo);
            int32_t bindAppIndex = sandboxInfo.bindAppIndex;
            (void)UninstallDlpSandboxApp(HIPREVIEW_LOW, bindAppIndex, userId);
        }
        return UninstallDlpSandboxApp(bundleName, appIndex, userId);
    }
    return DLP_OK;
}

static bool CheckAllowAbilityList(const AAFwk::Want& want)
{
    std::string bundleName = want.GetBundle();
    std::string actionName = want.GetAction();
    DLP_LOG_DEBUG(LABEL, "CheckAllowAbilityList %{public}s %{public}s", bundleName.c_str(), actionName.c_str());
    bool bundleCheck = (bundleName == DLP_MANAGER) &&
        BundleManagerAdapter::GetInstance().CheckHapPermission(bundleName, PERMISSION_ACCESS_DLP_FILE);
    bool actionCheck = std::any_of(std::begin(ALLOW_ACTION), std::end(ALLOW_ACTION),
        [actionName](const std::string& action) { return action == actionName; });
    return actionCheck || bundleCheck;
}

int32_t DlpPermissionService::GetSandboxExternalAuthorization(
    int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& authType)
{
    CriticalHelper criticalHelper("GetSandboxExternalAuthorization");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!IsSaCall() && !PermissionManagerAdapter::CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        DLP_LOG_ERROR(LABEL, "Caller is not SA or has no ACCESS_DLP_FILE permission");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    const std::string& bundleName = want.GetBundle();
    if (sandboxUid < 0 || bundleName.size() > MAX_BUNDLENAME_SIZE) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool isSandbox = false;

    observer->IsInDlpSandbox(isSandbox, sandboxUid);

    std::unique_lock<std::shared_mutex> lock(dlpSandboxDataMutex_);
    auto it = dlpSandboxData_.find(sandboxUid);
    DLP_LOG_INFO(LABEL, "GetSandboxExternalAuthorization bundleName=%s", bundleName.c_str());
    if (isSandbox && it != dlpSandboxData_.end() &&
        std::find(SANDBOX_WHITELIST.begin(), SANDBOX_WHITELIST.end(), bundleName) != SANDBOX_WHITELIST.end()) {
        authType = SandBoxExternalAuthorType::ALLOW_START_ABILITY;
        return DLP_OK;
    }

    if (isSandbox && it != dlpSandboxData_.end() && dlpSandboxData_[sandboxUid] != DLPFileAccess::READ_ONLY) {
        authType = SandBoxExternalAuthorType::ALLOW_START_ABILITY;
        return DLP_OK;
    }

    if (isSandbox && !CheckAllowAbilityList(want)) {
        authType = SandBoxExternalAuthorType::DENY_START_ABILITY;
    } else {
        authType = SandBoxExternalAuthorType::ALLOW_START_ABILITY;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    CriticalHelper criticalHelper("QueryDlpFileCopyableByTokenId");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::AccessTokenID pasteboardToken =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId(PASTEBOARD_SERVICE_NAME);
    Security::AccessToken::AccessTokenID distributeddataToken =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId(DISTRIBUTED_DATA_NAME);
    if (callingToken != pasteboardToken && callingToken != distributeddataToken) {
        DLP_LOG_ERROR(LABEL, "Caller is not pasteboard or distributeddata");
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    if (tokenId == 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = observer->QueryDlpFileCopyableByTokenId(copyable, tokenId);
    return res;
}

static ActionFlags GetDlpActionFlag(DLPFileAccess dlpFileAccess)
{
    switch (dlpFileAccess) {
        case DLPFileAccess::READ_ONLY: {
            return ACTION_VIEW;
        }
        case DLPFileAccess::CONTENT_EDIT: {
            return static_cast<ActionFlags>(ACTION_VIEW | ACTION_SAVE | ACTION_SAVE_AS | ACTION_EDIT |
            ACTION_SCREEN_CAPTURE | ACTION_SCREEN_SHARE | ACTION_SCREEN_RECORD | ACTION_COPY);
        }
        case DLPFileAccess::FULL_CONTROL: {
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
    CriticalHelper criticalHelper("QueryDlpFileAccess");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool sandboxFlag;
    if (PermissionManagerAdapter::CheckSandboxFlagWithService(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a non-sandbox app");
        return DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    DLPFileAccess dlpFileAccess = DLPFileAccess::NO_PERMISSION;
    int32_t res = observer->QueryDlpFileAccessByUid(dlpFileAccess, uid);
    permInfoParcel.permInfo_.dlpFileAccess = dlpFileAccess;
    permInfoParcel.permInfo_.flags = GetDlpActionFlag(dlpFileAccess);
    return res;
}

int32_t DlpPermissionService::IsInDlpSandbox(bool& inSandbox)
{
    CriticalHelper criticalHelper("IsInDlpSandbox");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t res = observer->IsInDlpSandbox(inSandbox, uid);
    return res;
}

void DlpPermissionService::GetCfgFilesList(std::vector<std::string>& cfgFilesList)
{
    CfgFiles *cfgFiles = GetCfgFiles(DLP_CONFIG.c_str()); // need free
    if (cfgFiles != nullptr) {
        for (auto& cfgPath : cfgFiles->paths) {
            if (cfgPath != nullptr) {
                cfgFilesList.emplace_back(cfgPath);
            }
        }
        FreeCfgFiles(cfgFiles); // free memory
    }
    std::reverse(cfgFilesList.begin(), cfgFilesList.end()); // priority from low to high, need reverse
}

void DlpPermissionService::GetConfigFileValue(const std::string& cfgFile, std::vector<std::string>& typeList)
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
    auto result = jsonObj.find(SUPPORT_FILE_TYPE);
    if (result != jsonObj.end() && result->is_array() && !result->empty() &&
        std::all_of(result->begin(), result->end(), [](const auto& item) { return item.is_string(); })) {
        typeList = result->get<std::vector<std::string>>();
    }
}

void DlpPermissionService::InitConfig(std::vector<std::string>& typeList)
{
    static std::vector<std::string> typeListTemp;
    static bool cfgInit = true;
    std::lock_guard<std::mutex> lock(mutex_);
    if (cfgInit) {
        cfgInit = false;
        std::vector<std::string> cfgFilesList;
        GetCfgFilesList(cfgFilesList);
        for (const auto& cfgFile : cfgFilesList) {
            GetConfigFileValue(cfgFile, typeListTemp);
            if (!typeListTemp.empty()) {
                typeList = typeListTemp;
                return;
            }
        }
        DLP_LOG_INFO(LABEL, "get config value failed, use default file path");
        GetConfigFileValue(DEAULT_DLP_CONFIG, typeListTemp);
        if (typeListTemp.empty()) {
            DLP_LOG_ERROR(LABEL, "support file type list is empty");
        }
    }
    typeList = typeListTemp;
}

int32_t DlpPermissionService::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    CriticalHelper criticalHelper("GetDlpSupportFileType");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    InitConfig(supportFileType);
    if (supportFileType.size() > MAX_SUPPORT_FILE_TYPE_NUM) {
        DLP_LOG_ERROR(LABEL, "listNum larger than 1024");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject>& callback)
{
    CriticalHelper criticalHelper("RegisterDlpSandboxChangeCallback");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!PermissionManagerAdapter::CheckSystemAppAndPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    DLP_LOG_INFO(LABEL, "GetCallingRealPid,%{public}d", pid);
    int32_t res = DlpSandboxChangeCallbackManager::GetInstance().AddCallback(pid, callback);
    return res;
}

int32_t DlpPermissionService::UnRegisterDlpSandboxChangeCallback(bool& result)
{
    CriticalHelper criticalHelper("UnRegisterDlpSandboxChangeCallback");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!PermissionManagerAdapter::CheckSystemAppAndPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    DLP_LOG_INFO(LABEL, "GetCallingRealPid,%{public}d", pid);
    int32_t res = DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(pid, result);
    return res;
}

int32_t DlpPermissionService::RegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback)
{
    CriticalHelper criticalHelper("RegisterOpenDlpFileCallback");
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
    if (!GetCallerBundleName(IPCSkeleton::GetCallingTokenID(), callerBundleName)) {
        DLP_LOG_ERROR(LABEL, "get callerBundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    if (GetUserIdFromUid(uid, &userId) != 0) {
        DLP_LOG_ERROR(LABEL, "GetUserIdFromUid error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t pid = IPCSkeleton::GetCallingRealPid();

    DLP_LOG_INFO(LABEL, "CallingPid: %{public}d, userId: %{public}d, CallingBundle: %{public}s", pid, userId,
        callerBundleName.c_str());

    int res = OpenDlpFileCallbackManager::GetInstance().AddCallback(pid, userId, callerBundleName, callback);
    if (res != DLP_OK) {
        return res;
    }
    observer->AddCallbackListener(pid);
    SetHasBackgroundTask(true);
    return DLP_OK;
}

int32_t DlpPermissionService::UnRegisterOpenDlpFileCallback(const sptr<IRemoteObject>& callback)
{
    CriticalHelper criticalHelper("UnRegisterOpenDlpFileCallback");
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
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    int32_t res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(pid, callback);
    if (res == DLP_OK) {
        observer->RemoveCallbackListener(pid);
    }
    return res;
}

int32_t DlpPermissionService::GetDlpGatheringPolicy(bool& isGathering)
{
    CriticalHelper criticalHelper("GetDlpGatheringPolicy");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!PermissionManagerAdapter::CheckSystemAppAndPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    isGathering = true;
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
    CriticalHelper criticalHelper("SetRetentionState");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool sandboxFlag;
    if (PermissionManagerAdapter::CheckSandboxFlagWithService(GetCallingTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (!sandboxFlag) {
        DLP_LOG_ERROR(LABEL, "Forbid called by a non-sandbox app");
        return DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR;
    }
    if (docUriVec.empty() || !ValidateStringList(docUriVec, MAX_URI_SIZE)) {
        DLP_LOG_ERROR(LABEL, "docUriVec is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    RetentionInfo info;
    info.tokenId = IPCSkeleton::GetCallingTokenID();
    std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
    int32_t uid = IPCSkeleton::GetCallingUid();
    DlpSandboxInfo sandboxInfo;
    bool result = observer->GetSandboxInfo(uid, sandboxInfo);
    if (!result) {
        DLP_LOG_ERROR(LABEL, "Can not found sandbox info");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    info.hasRead = sandboxInfo.hasRead;
    int32_t res = RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
    return res;
}

int32_t DlpPermissionService::CancelRetentionState(const std::vector<std::string>& docUriVec)
{
    CriticalHelper criticalHelper("CancelRetentionState");
    auto observer = GetAppStateObserver(CurrentTaskState::SHORT_TASK);
    if (observer == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (docUriVec.empty() || !ValidateStringList(docUriVec, MAX_URI_SIZE)) {
        DLP_LOG_ERROR(LABEL, "docUriVec is invalid.");
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
        std::lock_guard<std::mutex> lock(observer->GetTerminalMutex());
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
    auto observer = GetAppStateObserver(CurrentTaskState::IDLE);
    if (observer == nullptr) {
        DLP_LOG_ERROR(LABEL, "observer is nullptr");
        return false;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    if (GetUserIdFromUid(uid, &userId) != 0) {
        DLP_LOG_ERROR(LABEL, "get GetUserIdFromUid error");
        return false;
    }
    for (auto iter = retentionSandBoxInfoVec.begin(); iter != retentionSandBoxInfoVec.end(); ++iter) {
        if (observer->CheckSandboxInfo(info.bundleName, iter->appIndex_, userId)) {
            continue;
        }
        if (info.bundleName == HIPREVIEW_HIGH) {
            if (UninstallDlpSandboxApp(HIPREVIEW_LOW, iter->bindAppIndex_, userId) != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "UninstallDlpSandboxApp failed, bindAppIndex=%d", iter->bindAppIndex_);
            } else {
                DLP_LOG_INFO(LABEL, "UninstallDlpSandboxApp success, bindAppIndex=%d", iter->bindAppIndex_);
            }
        }
        DeleteDlpSandboxInfo(info.bundleName, iter->appIndex_, userId);
        UninstallDlpSandboxApp(info.bundleName, iter->appIndex_, userId);
        RetentionFileManager::GetInstance().RemoveRetentionState(info.bundleName, iter->appIndex_);
    }
    return true;
}

int32_t DlpPermissionService::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    CriticalHelper criticalHelper("GetRetentionSandboxList");
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
    if (bundleName.size() > MAX_BUNDLENAME_SIZE) {
        DLP_LOG_ERROR(LABEL, "bundleName is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::string callerBundleName;
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    GetCallerBundleName(tokenId, callerBundleName);
    if (callerBundleName == DLP_MANAGER &&
        BundleManagerAdapter::GetInstance().CheckHapPermission(callerBundleName, PERMISSION_ACCESS_DLP_FILE)) {
        callerBundleName = bundleName;
    }
    if (callerBundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "get bundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res =
        RetentionFileManager::GetInstance().GetRetentionSandboxList(callerBundleName, retentionSandBoxInfoVec, true);
    if (retentionSandBoxInfoVec.size() > MAX_RETENTION_SIZE) {
        DLP_LOG_ERROR(LABEL, "size larger than 1024");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
