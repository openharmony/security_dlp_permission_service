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

#include "dlp_common_func.h"

#include "account_adapt.h"
#include "alg_common_type.h"
#include "alg_manager.h"
#include "alg_utils.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCommonFunc" };
}

int32_t GetHMACValue(const HMACSrcParams *hmacSrcParams,
    uint8_t **hmacValue, uint32_t *hmacValueSize, const BlobData *aliasBlob)
{
    if (hmacSrcParams == nullptr || !IsBlobDataValid(hmacSrcParams->SrcDataBlob) ||
        hmacValue == nullptr || hmacValueSize == nullptr || aliasBlob == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetHMACValue params error!");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    BlobData outDataBlob = { .dataSize = 0, .value = nullptr };

    AlgKeyInfo keyInfo = { .protectionLevel = hmacSrcParams->protectionLevel,
        .osAccountId = hmacSrcParams->osAccountId, .keyAlias = *aliasBlob };
    if (!AlgIsKeyExist(&keyInfo)) {
        if (AlgGenerateMacKey(&keyInfo) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Generate HMAC key failed!");
            return DLP_ERROR_GENERATE_KEY_FAILED;
        }
    }
    int32_t ret = AlgHmac(&keyInfo, hmacSrcParams->SrcDataBlob, &outDataBlob);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Do HMAC failed, errCode: %{public}d.", ret);
        return ret;
    }

    *hmacValue = outDataBlob.value;
    *hmacValueSize = outDataBlob.dataSize;
    return ret;
}

int32_t WriteHMACAndBufToFile(const HMACSrcParams *hmacSrcParams, const char *keyAlias, const char *filePath)
{
    if (hmacSrcParams == nullptr || !IsBlobDataValid(hmacSrcParams->SrcDataBlob) ||
        keyAlias == nullptr || filePath == nullptr) {
        DLP_LOG_ERROR(LABEL, "Input params is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint8_t *hmacValue = nullptr;
    uint32_t hmacValueSize = 0;
    uint32_t keyAliasLen = HcStrlen(keyAlias);
    if (keyAliasLen == 0) {
        DLP_LOG_ERROR(LABEL, "KeyAlias length is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    BlobData keyAliasBlob = { keyAliasLen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(keyAlias)) };
    int32_t res = GetHMACValue(hmacSrcParams, &hmacValue, &hmacValueSize, &keyAliasBlob);
    if (res != DLP_OK) {
        return res;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (ParcelWrite(&parcel, &hmacValueSize, sizeof(hmacValueSize)) != HC_TRUE ||
        ParcelWrite(&parcel, hmacValue, hmacValueSize) != HC_TRUE ||
        ParcelWrite(&parcel, hmacSrcParams->SrcDataBlob->value, hmacSrcParams->SrcDataBlob->dataSize) != HC_TRUE) {
        DLP_LOG_ERROR(LABEL, "parcel write hmac and buffer failed!");
        DeleteParcel(&parcel);
        DLP_FREE_PTR(hmacValue);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    DLP_FREE_PTR(hmacValue);
    uint32_t fileLen = GetParcelDataSize(&parcel);
    const char *fileBuffer = GetParcelData(&parcel);
    if (fileBuffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetParcelData failed!");
        DeleteParcel(&parcel);
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    FileHandle file = { 0 };
    res = HcFileOpen(filePath, MODE_FILE_WRITE, &file, USER_R_W_FILE_PERMISSION);
    if (res != 0) {
        DeleteParcel(&parcel);
        return DLP_ERROR_FILE_NOT_EXIST;
    }
    res = HcFileWrite(file, fileBuffer, fileLen);
    HcFileClose(file);
    DeleteParcel(&parcel);
    if (res < 0 || static_cast<uint32_t>(res) != fileLen) {
        DLP_LOG_ERROR(LABEL, "HcFileWrite buffer failed!");
        return DLP_ERROR_FILE_SIZE;
    }
    return DLP_OK;
}

int32_t ReadBufFromFile(uint8_t **fileBuffer, uint32_t *fileSize, const char *filePath)
{
    if (fileBuffer == nullptr || fileSize == nullptr || filePath == nullptr) {
        DLP_LOG_ERROR(LABEL, "Input params is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    FileHandle file = { 0 };
    if (HcFileOpen(filePath, MODE_FILE_READ, &file, USER_R_W_FILE_PERMISSION) != 0) {
        DLP_LOG_ERROR(LABEL, "Open file failed (maybe file not exist)");
        return DLP_ERROR_FILE_NOT_EXIST;
    }
    int32_t len = HcFileSize(file);
    if (len <= 0 || len > MAX_POLICY_DATA_LEN) {
        DLP_LOG_ERROR(LABEL, "Invalid server file size: %{public}d", len);
        HcFileClose(file);
        return DLP_ERROR_FILE_SIZE;
    }
    *fileBuffer = static_cast<uint8_t *>(HcMalloc(len, 0));
    if (*fileBuffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate file buffer failed!");
        HcFileClose(file);
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t readSize = HcFileRead(file, *fileBuffer, len);
    HcFileClose(file);
    if (readSize != len) {
        DLP_LOG_ERROR(LABEL, "Read file path failed");
        DLP_FREE_PTR(*fileBuffer);
        return DLP_ERROR_FILE_READ;
    }
    *fileSize = static_cast<uint32_t>(len);
    return DLP_OK;
}

static int32_t AllocHMACValue(HcParcel *parcel, uint8_t **hmacValue1, uint32_t *hmacLen1)
{
    if (ParcelRead(parcel, hmacLen1, sizeof(uint32_t)) != HC_TRUE) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (*hmacLen1 == 0 || *hmacLen1 > MAX_POLICY_DATA_LEN) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    *hmacValue1 = static_cast<uint8_t *>(HcMalloc(*hmacLen1, 0));
    if (*hmacValue1 == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate hmacValue1 failed!");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (ParcelRead(parcel, *hmacValue1, *hmacLen1) != HC_TRUE) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    return DLP_OK;
}

static int32_t PrepareData(const HMACSrcParams *hmacSrcParams, uint8_t **buffer, uint32_t *bufLen,
    uint8_t **hmacValue1, uint32_t *hmacLen1)
{
    if (hmacSrcParams == nullptr || buffer == nullptr || bufLen == nullptr ||
        hmacValue1 == nullptr || hmacLen1 == nullptr) {
        DLP_LOG_ERROR(LABEL, "Input params is invalid in PrepareData.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    HcParcel parcel = CreateParcel(0, 0);
    int32_t ret = DLP_SERVICE_ERROR_VALUE_INVALID;
    do {
        if (ParcelWrite(&parcel, hmacSrcParams->SrcDataBlob->value, hmacSrcParams->SrcDataBlob->dataSize) != HC_TRUE) {
            DLP_LOG_ERROR(LABEL, "parcel write hmac params failed.");
            break;
        }

        if (AllocHMACValue(&parcel, hmacValue1, hmacLen1) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "allocate HMAC value failed.");
            break;
        }

        uint32_t bufSize = GetParcelDataSize(&parcel);
        *buffer = static_cast<uint8_t *>(HcMalloc(bufSize, 0));
        if (*buffer == nullptr) {
            DLP_LOG_ERROR(LABEL, "Allocate buffer memory failed.");
            break;
        }

        if (ParcelRead(&parcel, *buffer, bufSize) != HC_TRUE) {
            DLP_LOG_ERROR(LABEL, "parcel read data failed.");
            DLP_FREE_PTR(*buffer);
            break;
        }

        *bufLen = bufSize;
        ret = DLP_OK;
    } while (0);

    DeleteParcel(&parcel);
    return ret;
}

int32_t CompareHMACValue(const HMACSrcParams *hmacSrcParams, uint8_t **buffer, uint32_t *bufLen, const char *keyAlias)
{
    if (hmacSrcParams == nullptr || !IsBlobDataValid(hmacSrcParams->SrcDataBlob) ||
        buffer == nullptr || bufLen == nullptr || keyAlias == nullptr) {
        DLP_LOG_ERROR(LABEL, "Input params is invalid.");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    uint8_t *hmacValue1 = nullptr;
    uint32_t hmacLen1 = 0;
    int32_t ret = DLP_SERVICE_ERROR_VALUE_INVALID;
    do {
        ret = PrepareData(hmacSrcParams, buffer, bufLen, &hmacValue1, &hmacLen1);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "failed to prepare data in CompareHMACValue.");
            break;
        }
        uint8_t *hmacValue2 = nullptr;
        uint32_t hmacLen2 = 0;
        uint32_t keyAliasLen = HcStrlen(keyAlias);
        BlobData keyAliasBlob = { keyAliasLen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(keyAlias)) };
        BlobData bufferBlob = { *bufLen, static_cast<uint8_t *>(*buffer) };
        HMACSrcParams hmacBuffParams = { .osAccountId = hmacSrcParams->osAccountId,
            .protectionLevel = hmacSrcParams->protectionLevel, .SrcDataBlob = &bufferBlob };
        if (GetHMACValue(&hmacBuffParams, &hmacValue2, &hmacLen2, &keyAliasBlob) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "failed to get HMAC value in CompareHMACValue.");
            DLP_FREE_PTR(*buffer);
            break;
        }
        if (hmacLen1 == hmacLen2 && memcmp(hmacValue1, hmacValue2, hmacLen1) == 0) {
            ret = DLP_OK;
        } else {
            DLP_LOG_ERROR(LABEL, "HMAC values do not match.");
            DLP_FREE_PTR(*buffer);
            ret = DLP_ERROR_HMAC_FAILED;
        }
        DLP_FREE_PTR(hmacValue2);
    } while (0);
    DLP_FREE_PTR(hmacValue1);
    return ret;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS