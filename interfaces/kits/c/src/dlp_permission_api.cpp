/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlp_permission_api.h"

#include <string>
#include "securec.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"

using namespace OHOS::Security::DlpPermission;

namespace {
static const char *DLP_FILE_SUFFIX = ".dlp";
static const uint32_t MAX_FILE_NAME_LEN = 256;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionCapi"};
static const std::unordered_map<int32_t, DLP_ErrCode> NATIVE_CODE_TO_C_CODE_MAP = {
    { DLP_OK, ERR_OH_SUCCESS },

    // ERR_OH_INVALID_PARAMETER
    { DLP_SERVICE_ERROR_VALUE_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_VALUE_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_DIGEST_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_FD_ERROR, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_PTR_NULL, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_ACCOUNT_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_FUSE_ERROR_VALUE_INVALID, ERR_OH_INVALID_PARAMETER },
    { DLP_FUSE_ERROR_DLP_FILE_NULL, ERR_OH_INVALID_PARAMETER },
    { DLP_KV_DATE_INFO_EMPTY_ERROR, ERR_OH_INVALID_PARAMETER },
    { DLP_RETENTION_ERROR_VALUE_INVALID, ERR_OH_INVALID_PARAMETER },

    // ERR_OH_API_ONLY_FOR_SANDBOX
    { DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR, ERR_OH_API_ONLY_FOR_SANDBOX },

    // ERR_OH_API_NOT_FOR_SANDBOX
    { DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR, ERR_OH_API_NOT_FOR_SANDBOX },

    // ERR_OH_SYSTEM_SERVICE_EXCEPTION
    { DLP_NAPI_ERROR_NATIVE_BINDING_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_APPOBSERVER_NULL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_APPOBSERVER_ERROR, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_SERVICE_NOT_EXIST, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_CRYPT_FAIL, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_QUERY_DISTRIBUTE_DATA_ERROR, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_COMMON_CHECK_KVSTORE_ERROR, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_COMMON_DELETE_KEY_FROM_KVSTORE_ERROR, ERR_OH_SYSTEM_SERVICE_EXCEPTION },
    { DLP_CREDENTIAL_ERROR_VALUE_INVALID, ERR_OH_SYSTEM_SERVICE_EXCEPTION },

    // ERR_OH_OUT_OF_MEMORY
    { DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, ERR_OH_OUT_OF_MEMORY },
    { DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, ERR_OH_OUT_OF_MEMORY },
    { DLP_FUSE_ERROR_MEMORY_OPERATE_FAIL, ERR_OH_OUT_OF_MEMORY },

    // ERR_OH_APPLICATION_NOT_AUTHORIZED
    { DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED, ERR_OH_APPLICATION_NOT_AUTHORIZED},
};
} // namespace

static DLP_ErrCode ConvertApiResult(int32_t result)
{
    auto iter = NATIVE_CODE_TO_C_CODE_MAP.find(result);
    if (iter != NATIVE_CODE_TO_C_CODE_MAP.end()) {
        return iter->second;
    }
    return ERR_OH_SYSTEM_SERVICE_EXCEPTION;
}

DLP_ErrCode OH_DLP_GetDlpPermissionInfo(DLP_FileAccess *dlpFileAccess, uint32_t *flag)
{
    if (dlpFileAccess == nullptr || flag == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid parameter.");
        return ERR_OH_INVALID_PARAMETER;
    }

    DLPPermissionInfo info = {};
    int32_t result = DlpPermissionKit::QueryDlpFileAccess(info);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "query dlpFileAccess error.");
        return ConvertApiResult(result);
    }

    (void)memcpy_s(dlpFileAccess, sizeof(DLP_FileAccess), &info.dlpFileAccess, sizeof(DLP_FileAccess));
    (void)memcpy_s(flag, sizeof(uint32_t), &info.flags, sizeof(uint32_t));
    return ConvertApiResult(result);
}

DLP_ErrCode OH_DLP_GetOriginalFileName(const char *fileName, char **originalFileName)
{
    *originalFileName = nullptr;
    if (fileName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid parameter.");
        return ERR_OH_INVALID_PARAMETER;
    }

    uint32_t suffixLen = strlen(DLP_FILE_SUFFIX);
    uint32_t fileNameLen = strlen(fileName);
    if (fileNameLen <= suffixLen || fileNameLen > MAX_FILE_NAME_LEN) {
        DLP_LOG_ERROR(LABEL, "file name len is error.");
        return ERR_OH_INVALID_PARAMETER;
    }

    if (strncmp(fileName + fileNameLen - suffixLen, DLP_FILE_SUFFIX, suffixLen) != 0) {
        DLP_LOG_ERROR(LABEL, "Not a dlp file.");
        return ERR_OH_INVALID_PARAMETER;
    }

    *originalFileName = static_cast<char *>(malloc(fileNameLen - suffixLen + 1));
    if (*originalFileName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Malloc *originalFileName error.");
        return ERR_OH_OUT_OF_MEMORY;
    }

    (void)memcpy_s(*originalFileName, fileNameLen - suffixLen, fileName, fileNameLen - suffixLen);
    (*originalFileName)[fileNameLen - suffixLen] = 0;
    return ERR_OH_SUCCESS;
}

DLP_ErrCode OH_DLP_IsInSandbox(bool *isInSandbox)
{
    if (isInSandbox == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid parameter.");
        return ERR_OH_INVALID_PARAMETER;
    }
    int32_t result = DlpPermissionKit::IsInDlpSandbox(*isInSandbox);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "get isInDlpSandbox error.");
    }
    return ConvertApiResult(result);
}

DLP_ErrCode OH_DLP_SetSandboxAppConfig(const char *configInfo)
{
    if (configInfo == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid parameter.");
        return ERR_OH_INVALID_PARAMETER;
    }
    std::string strConfigInfo(configInfo);
    int32_t result = DlpPermissionKit::SetSandboxAppConfig(strConfigInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set sandboxAppConfig error.");
    }
    return ConvertApiResult(result);
}

DLP_ErrCode OH_DLP_GetSandboxAppConfig(char **configInfo)
{
    *configInfo = nullptr;
    std::string strConfigInfo = "";
    int32_t result = DlpPermissionKit::GetSandboxAppConfig(strConfigInfo);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "get sandboxAppConfig error.");
        return ConvertApiResult(result);
    }

    *configInfo = static_cast<char *>(malloc(strConfigInfo.size() + 1));
    if (*configInfo == nullptr) {
        DLP_LOG_ERROR(LABEL, "Malloc *configInfo error.");
        return ERR_OH_OUT_OF_MEMORY;
    }
    (void)memcpy_s(*configInfo, strConfigInfo.size() + 1, strConfigInfo.c_str(), strConfigInfo.size() + 1);
    return ERR_OH_SUCCESS;
}

DLP_ErrCode OH_DLP_CleanSandboxAppConfig()
{
    int32_t result = DlpPermissionKit::CleanSandboxAppConfig();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "clean sandboxAppConfig error.");
    }
    return ConvertApiResult(result);
}