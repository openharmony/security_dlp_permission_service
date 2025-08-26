/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_feature_info.h"

#include "account_adapt.h"
#include "alg_common_type.h"
#include "alg_manager.h"
#include "alg_utils.h"
#include "dlp_common_func.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFeatureInfo" };
static const char *DLP_FEATURE_INFO_FILE_KEY_ALIAS = "DLP_FEATURE_INFO_FILE_KEY_ALIAS";
static const std::string MDM_ENABLE_VALUE = "status";
static const uint32_t ENABLE_VALUE_FALSE = 0;
static const uint32_t ENABLE_VALUE_TRUE = 1;
static const char *FEATURE_INFO_DATA_FILE_PATH = "/data/service/el1/public/dlp_permission_service/dlp_feature_info.txt";
}
DlpFeatureInfo::DlpFeatureInfo() {}

DlpFeatureInfo::~DlpFeatureInfo() {}

static int32_t AssembleFeatureInfoPath(char **filePath)
{
    uint32_t filePathSize = HcStrlen(FEATURE_INFO_DATA_FILE_PATH);
    *filePath = static_cast<char *>(HcMalloc(filePathSize + 1, 0));
    if (*filePath == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate memory for feature info file path failed");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (memcpy_s(*filePath, filePathSize + 1, FEATURE_INFO_DATA_FILE_PATH, filePathSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "memcpy_s error");
        DLP_FREE_PTR(filePath);
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFeatureInfo::SaveDlpFeatureInfoToFile(const unordered_json &dlpFeatureJson)
{
    auto result = dlpFeatureJson.find(MDM_ENABLE_VALUE);
    if (result == dlpFeatureJson.end() || !result->is_number()) {
        DLP_LOG_ERROR(LABEL, "status not found or not number type");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint32_t status = result->get<uint32_t>();
    if (status != ENABLE_VALUE_FALSE && status != ENABLE_VALUE_TRUE) {
        DLP_LOG_ERROR(LABEL, "status is neither 0 nor 1");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        DLP_LOG_ERROR(LABEL, "get userID failed");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    BlobData keyAliasBlob = { HcStrlen(DLP_FEATURE_INFO_FILE_KEY_ALIAS),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(DLP_FEATURE_INFO_FILE_KEY_ALIAS)) };
    AlgKeyInfo keyInfo = { .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = userId, .keyAlias = keyAliasBlob };
    int32_t res = DLP_SERVICE_ERROR_VALUE_INVALID;
    if (!AlgIsKeyExist(&keyInfo)) {
        res = AlgGenerateMacKey(&keyInfo);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Generate HMAC key failed!");
            return DLP_ERROR_GENERATE_KEY_FAILED;
        }
    }

    char *filePath = nullptr;
    res = AssembleFeatureInfoPath(&filePath);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Failed to assemble FeatureInfoPath! res is %{public}d", res);
        return res;
    }

    std::string jsonString = dlpFeatureJson.dump();
    BlobData fileDataBlob = { HcStrlen(jsonString.c_str()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(jsonString.c_str())) };
    HMACSrcParams hmacSrcParams = { .osAccountId = keyInfo.osAccountId, .protectionLevel = PROTECT_LEVEL_DE,
        .SrcDataBlob = &fileDataBlob };
    res = WriteHMACAndBufToFile(&hmacSrcParams, DLP_FEATURE_INFO_FILE_KEY_ALIAS, filePath);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "WriteHMACAndBufToFile failed, error code: %{public}d.", res);
        DLP_FREE_PTR(filePath);
        return res;
    }

    DLP_LOG_INFO(LABEL, "DlpFeatureInfo saved!");
    DLP_FREE_PTR(filePath);
    return res;
}

int32_t DlpFeatureInfo::GetDlpFeatureInfoFromJson(std::string jsonString, uint32_t &dlpFeature)
{
    auto jsonObj = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_WARN(LABEL, "JsonObj is discarded");
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    auto result = jsonObj.find(MDM_ENABLE_VALUE);
    if (result != jsonObj.end() && result->is_number()) {
        dlpFeature = result->get<uint32_t>();
    }
    return DLP_OK;
}

int32_t DlpFeatureInfo::GetDlpFeatureInfoFromFile(const char *filePath, uint32_t &dlpFeature)
{
    if (filePath == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetDlpFeatureInfoFromFile filePath Invalid input params");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        DLP_LOG_ERROR(LABEL, "get userID failed");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint8_t *fileBuffer = nullptr;
    uint32_t fileSize = 0;
    int32_t ret = ReadBufFromFile(&fileBuffer, &fileSize, filePath);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "ReadBufFromFile fail, ret is %{public}d!", ret);
        return ret;
    }
    uint8_t *featureInfoStrBuf = nullptr;
    uint32_t featureInfoStrBufLen = 0;

    BlobData fileBlob = { fileSize, fileBuffer };
    HMACSrcParams hmacSrcParams = { .osAccountId = userId, .protectionLevel = PROTECT_LEVEL_DE,
        .SrcDataBlob = &fileBlob };
    ret = CompareHMACValue(&hmacSrcParams, &featureInfoStrBuf, &featureInfoStrBufLen, DLP_FEATURE_INFO_FILE_KEY_ALIAS);
    DLP_FREE_PTR(fileBuffer);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Compare feature info file HmacValue failed, ret is %{public}d!", ret);
        return ret;
    }
    char *featureInfoStr = static_cast<char *>(HcMalloc(featureInfoStrBufLen + 1, 0));
    if (featureInfoStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "featureInfoStr is null!");
        DLP_FREE_PTR(featureInfoStrBuf);
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (memcpy_s(featureInfoStr, featureInfoStrBufLen + 1, featureInfoStrBuf, featureInfoStrBufLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Copy featureInfoStrBuf fail, memcpy_s fail");
        DLP_FREE_PTR(featureInfoStrBuf);
        DLP_FREE_PTR(featureInfoStr);
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DLP_FREE_PTR(featureInfoStrBuf);
    std::string jsonString(featureInfoStr);
    DLP_FREE_PTR(featureInfoStr);
    return GetDlpFeatureInfoFromJson(jsonString, dlpFeature);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS