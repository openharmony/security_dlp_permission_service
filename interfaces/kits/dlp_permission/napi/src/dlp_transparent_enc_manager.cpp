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

#include <dlfcn.h>
#include <cstring>

#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                      "DlpTransparentEncManager"};
constexpr size_t SIZE_64_BIT = 8;
static const std::string DLP_CREDENTIAL_TRANSPARENT_ENC_32_PATH = "/system/lib/libdlp_transparent_enc_sdk.z.so";
static const std::string DLP_CREDENTIAL_TRANSPARENT_ENC_64_PATH = "/system/lib64/libdlp_transparent_enc_sdk.z.so";
}  // namespace

DlpTransparentEncManager &DlpTransparentEncManager::GetInstance()
{
    static DlpTransparentEncManager instance;
    return instance;
}

DlpTransparentEncManager::~DlpTransparentEncManager()
{
    if (credentialServiceHandle_ != nullptr) {
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
        setControlledAppListsFunc_ = nullptr;
        getControlledAppListsFunc_ = nullptr;
        freeControlledAppListsFunc_ = nullptr;
    }
}

int32_t DlpTransparentEncManager::LoadDlpCredentialService()
{
    if (credentialServiceHandle_ != nullptr) {
        return DLP_OK;
    }

    if (sizeof(void *) == SIZE_64_BIT) {
        credentialServiceHandle_ = dlopen(DLP_CREDENTIAL_TRANSPARENT_ENC_64_PATH.c_str(), RTLD_LAZY);
    } else {
        credentialServiceHandle_ = dlopen(DLP_CREDENTIAL_TRANSPARENT_ENC_32_PATH.c_str(), RTLD_LAZY);
    }

    if (credentialServiceHandle_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlopen dlptransparentsdk failed, error: %{public}s", dlerror());
        return DLP_ERROR_DLOPEN;
    }

    setControlledAppListsFunc_ = reinterpret_cast<SetControlledAppLists_Func>(
        dlsym(credentialServiceHandle_, "DLP_SetControlledAppLists"));
    if (setControlledAppListsFunc_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlsym DLP_SetControlledAppLists failed, error: %{public}s", dlerror());
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
        return DLP_ERROR_DLSYM;
    }

    getControlledAppListsFunc_ = reinterpret_cast<GetControlledAppLists_Func>(
        dlsym(credentialServiceHandle_, "DLP_GetControlledAppLists"));
    if (getControlledAppListsFunc_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlsym DLP_GetControlledAppLists failed, error: %{public}s", dlerror());
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
        setControlledAppListsFunc_ = nullptr;
        return DLP_ERROR_DLSYM;
    }

    freeControlledAppListsFunc_ = reinterpret_cast<FreeControlledAppLists_Func>(
        dlsym(credentialServiceHandle_, "DLP_FreeControlledAppLists"));
    if (freeControlledAppListsFunc_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlsym DLP_FreeControlledAppLists failed, error: %{public}s", dlerror());
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
        setControlledAppListsFunc_ = nullptr;
        getControlledAppListsFunc_ = nullptr;
        return DLP_ERROR_DLSYM;
    }

    return DLP_OK;
}

int32_t DlpTransparentEncManager::SetControlledAppLists(const std::vector<std::string> &appLists, int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = LoadDlpCredentialService();
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "LoadDlpCredentialService failed, ret = %{public}d", ret);
        return ret;
    }

    if (setControlledAppListsFunc_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "setControlledAppListsFunc_ is nullptr");
        return DLP_ERROR_DLSYM;
    }

    std::vector<const char *> appListPtrs;
    for (const auto &app : appLists) {
        appListPtrs.push_back(app.c_str());
    }

    ret = setControlledAppListsFunc_(userId, appListPtrs.data(), static_cast<uint32_t>(appListPtrs.size()));
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_SetControlledAppLists failed, ret = %{public}d", ret);
        return ret;
    }

    DLP_LOG_INFO(LABEL, "SetControlledAppLists success");
    return DLP_OK;
}

int32_t DlpTransparentEncManager::GetControlledAppLists(std::vector<std::string> &appLists)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    DLP_LOG_INFO(LABEL, "GetControlledAppLists enter");
    int32_t ret = LoadDlpCredentialService();
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "LoadDlpCredentialService failed, ret = %{public}d", ret);
        return ret;
    }

    if (getControlledAppListsFunc_ == nullptr || freeControlledAppListsFunc_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "getControlledAppListsFunc_ or freeControlledAppListsFunc_ is nullptr");
        return DLP_ERROR_DLSYM;
    }

    char **appListPtrs = nullptr;
    uint32_t appListsLen = 0;
    ret = getControlledAppListsFunc_(&appListPtrs, &appListsLen);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_GetControlledAppLists failed, ret = %{public}d", ret);
        return ret;
    }

    if (appListPtrs != nullptr && appListsLen > 0) {
        for (uint32_t i = 0; i < appListsLen; i++) {
            if (appListPtrs[i] != nullptr) {
                appLists.push_back(std::string(appListPtrs[i]));
            }
        }
        freeControlledAppListsFunc_(&appListPtrs, &appListsLen);
    }

    DLP_LOG_INFO(LABEL, "GetControlledAppLists success, size = %{public}zu", appLists.size());
    return DLP_OK;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS