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

#ifdef DLP_FUZZ_TDD_TEST
#include "dlfcn_mock.h"
#endif
#include <dlfcn.h>
#include <cstring>

#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpTransparentEncManager"
};
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (credentialServiceHandle_ != nullptr) {
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
    }
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

template<typename FuncType>
int32_t DlpTransparentEncManager::ResolveSymbol(FuncType &funcPtr, const char *symbol)
{
    funcPtr = reinterpret_cast<FuncType>(dlsym(credentialServiceHandle_, symbol));
    if (funcPtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlsym %{public}s failed, error: %{public}s", symbol, dlerror());
        dlclose(credentialServiceHandle_);
        credentialServiceHandle_ = nullptr;
        ResetFunctionPointers();
        return DLP_ERROR_DLSYM;
    }
    return DLP_OK;
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

    int32_t ret = ResolveSymbol(setControlledAppListsFunc_, "DLP_SetControlledAppLists");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(getControlledAppListsFunc_, "DLP_GetControlledAppLists");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(freeControlledAppListsFunc_, "DLP_FreeControlledAppLists");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(processPluginCommandFunc_, "DLP_ProcessPluginCommand");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(freePluginCommandResultFunc_, "DLP_FreePluginCommandResult");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(getDockerPolicyFunc_, "DLP_GetDockerPolicy");
    if (ret != DLP_OK) {
        return ret;
    }
    ret = ResolveSymbol(freeDockerPolicyFunc_, "DLP_FreeDockerPolicy");
    if (ret != DLP_OK) {
        return ret;
    }
    return DLP_OK;
}

int32_t DlpTransparentEncManager::SetControlledAppLists(const std::vector<std::string> &appLists,
    int32_t userId, bool userIdSet)
{
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
    }

    std::vector<const char *> appListPtrs;
    for (const auto &app : appLists) {
        appListPtrs.push_back(app.c_str());
    }

    int32_t ret = setControlledAppListsFunc_(userId, userIdSet, appListPtrs.data(),
        static_cast<uint32_t>(appListPtrs.size()));
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_SetControlledAppLists failed, ret = %{public}d", ret);
        return ret;
    }

    DLP_LOG_INFO(LABEL, "SetControlledAppLists success");
    return DLP_OK;
}

int32_t DlpTransparentEncManager::GetControlledAppLists(std::vector<std::string> &appLists)
{
    DLP_LOG_INFO(LABEL, "GetControlledAppLists enter");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int32_t ret = LoadDlpCredentialService();
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "LoadDlpCredentialService failed, ret = %{public}d", ret);
            return ret;
        }
        if (getControlledAppListsFunc_ == nullptr || freeControlledAppListsFunc_ == nullptr) {
            DLP_LOG_ERROR(LABEL, "getControlledAppListsFunc_ or freeControlledAppListsFunc_ is nullptr");
            return DLP_ERROR_DLSYM;
        }
    }

    char **appListPtrs = nullptr;
    uint32_t appListsLen = 0;
    int32_t ret = getControlledAppListsFunc_(&appListPtrs, &appListsLen);
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

int32_t DlpTransparentEncManager::ProcessPluginCommand(int32_t code,
    const std::string &message, std::string &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int32_t ret = LoadDlpCredentialService();
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "LoadDlpCredentialService failed, ret = %{public}d", ret);
            return ret;
        }
        if (processPluginCommandFunc_ == nullptr || freePluginCommandResultFunc_ == nullptr) {
            DLP_LOG_ERROR(LABEL, "processPluginCommandFunc_ or freePluginCommandResultFunc_ is nullptr");
            return DLP_ERROR_DLSYM;
        }
    }

    char *resultPtr = nullptr;
    uint32_t resultLen = 0;
    int32_t ret = processPluginCommandFunc_(code, message.c_str(), &resultPtr, &resultLen);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_ProcessPluginCommand failed, ret = %{public}d", ret);
        return ret;
    }

    if (resultPtr != nullptr && resultLen > 0) {
        result = std::string(resultPtr, resultLen);
        freePluginCommandResultFunc_(&resultPtr, &resultLen);
    }

    DLP_LOG_INFO(LABEL, "ProcessPluginCommand success");
    return DLP_OK;
}

int32_t DlpTransparentEncManager::GetDockerPolicy(const std::string &fileUri, DockerPolicyInfo &policy)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int32_t ret = LoadDlpCredentialService();
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "LoadDlpCredentialService failed, ret = %{public}d", ret);
            return ret;
        }
        if (getDockerPolicyFunc_ == nullptr || freeDockerPolicyFunc_ == nullptr) {
            DLP_LOG_ERROR(LABEL, "getDockerPolicyFunc_ or freeDockerPolicyFunc_ is nullptr");
            return DLP_ERROR_DLSYM;
        }
    }

    DockerPolicyPayload *policyPtr = nullptr;
    int32_t ret = getDockerPolicyFunc_(fileUri.c_str(), &policyPtr);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "DLP_GetDockerPolicy failed, ret = %{public}d", ret);
        return ret;
    }

    if (policyPtr != nullptr) {
        policy.isEncrypted = policyPtr->is_encrypted;
        policy.needSandbox = policyPtr->need_sandbox;
        policy.bundleName = std::string(policyPtr->bundle_name);
        policy.mimeType = policyPtr->mime_type;
        policy.permission = policyPtr->permission;
        freeDockerPolicyFunc_(&policyPtr);
    }

    DLP_LOG_INFO(LABEL, "GetDockerPolicy success");
    return DLP_OK;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
