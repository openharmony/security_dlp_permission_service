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

#include "huks_adapt_manager.h"

#include "hks_api.h"
#include "hks_param.h"
#include "securec.h"

#include "alg_utils.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "HuksAdaptManager" };
}
static const uint32_t HMAC_KEY_SIZE_256 = 256;

static bool CheckHMACParams(const AlgKeyInfo *keyInfo, const BlobData *data, const BlobData *outData)
{
    if (keyInfo == nullptr || !IsBlobDataValid(&(keyInfo->keyAlias))) {
        DLP_LOG_ERROR(LABEL, "Mac keyInfo is invalid!");
        return false;
    }
    if (!IsBlobDataValid(data) || data->dataSize > MAX_DATABASE_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "Mac data is invalid!");
        return false;
    }
    if (outData == nullptr) {
        DLP_LOG_ERROR(LABEL, "Mac outData is invalid!");
        return false;
    }
    return true;
}

static int32_t ConstructParamSet(struct HksParamSet **outParamSet, struct HksParam *params,
    uint32_t paramcount)
{
    int32_t res = HksInitParamSet(outParamSet);
    if (res != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksInitParamSet failed, error code: %{public}d.", res);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    res = HksAddParams(*outParamSet, params, paramcount);
    if (res != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksAddParams failed, error code: %{public}d.", res);
        HksFreeParamSet(outParamSet);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    res = HksBuildParamSet(outParamSet);
    if (res != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksBuildParamSet failed, error code: %{public}d.", res);
        HksFreeParamSet(outParamSet);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

static int32_t MallocAndCheckBlobData(struct HksBlob *blob, uint32_t blobSize)
{
    blob->data = static_cast<uint8_t *>(HcMalloc(blobSize, 0));
    if (blob->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate blob data memory failed!");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t LessThanMaxSeg(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob tmpOutData = { MAX_OUTDATA_SIZE, nullptr };
    if (MallocAndCheckBlobData(&tmpOutData, tmpOutData.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    int32_t ret = HksUpdate(handle, paramSet, inData, &tmpOutData);
    HcFree(tmpOutData.data);
    if (ret != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksUpdate Failed, error code: %{public}d.", ret);
        return HKS_FAILURE;
    }
    struct HksBlob tmpInData = { 0, nullptr };
    if (MallocAndCheckBlobData(&tmpInData, MAX_UPDATE_SIZE) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksFinish(handle, paramSet, &tmpInData, outData);
    HcFree(tmpInData.data);
    if (ret != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksFinish Failed, error code: %{public}d.", ret);
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t HksShardingUpdateAndFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    inDataSeg.size = MAX_UPDATE_SIZE;
    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = { MAX_OUTDATA_SIZE, nullptr };

    if (inData->size <= MAX_UPDATE_SIZE) {
        return LessThanMaxSeg(handle, paramSet, inData, outData);
    }

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
            if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
                return HKS_FAILURE;
            }
        } else {
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            break;
        }
        if (HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg) != HKS_SUCCESS) {
            DLP_LOG_ERROR(LABEL, "HksUpdate Failed.");
            DLP_FREE_PTR(outDataSeg.data);
            return HKS_FAILURE;
        }
        DLP_FREE_PTR(outDataSeg.data);
        if (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr) {
            return HKS_FAILURE;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }
    if (HksFinish(handle, paramSet, &inDataSeg, outData) != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "Finish stage failed.");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t HksHMACThreeStages(const BlobData *keyAlias, struct HksParamSet *hmacParamSet,
    const BlobData *data, BlobData *outData)
{
    uint8_t handle[SIZE_OF_UINT64] = { 0 };
    struct HksBlob handleHMAC = { SIZE_OF_UINT64, handle };
    int32_t ret = HksInit(reinterpret_cast<const struct HksBlob *>(keyAlias), hmacParamSet, &handleHMAC, nullptr);
    if (ret != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksInit failed, error code: %{public}d.", ret);
        return ret;
    }

    ret = HksShardingUpdateAndFinish(&handleHMAC, hmacParamSet,
        reinterpret_cast<const struct HksBlob *>(data), reinterpret_cast<struct HksBlob *>(outData));
    if (ret != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "Update and finish stage failed, error code: %{public}d.", ret);
        HksAbort(&handleHMAC, hmacParamSet);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

bool IsHuksMgrKeyExist(const AlgKeyInfo *keyInfo)
{
    if (keyInfo == nullptr || !IsBlobDataValid(&(keyInfo->keyAlias))) {
        DLP_LOG_ERROR(LABEL, "keyInfo is invalid!");
        return false;
    }
    struct HksParamSet *paramSet = nullptr;
    struct HksParam deHmacParams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = keyInfo->osAccountId },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t res = ConstructParamSet(&paramSet, deHmacParams, sizeof(deHmacParams) / sizeof(deHmacParams[0]));
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "construct param set failed!");
        return false;
    }
    res = HksKeyExist(reinterpret_cast<const struct HksBlob *>(&(keyInfo->keyAlias)), paramSet);
    HksFreeParamSet(&paramSet);
    if (res != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "Key is not exist, error code: %{public}d.", res);
        return false;
    }
    return true;
}

int32_t HuksGenerateMacKey(const AlgKeyInfo *keyInfo)
{
    if (keyInfo == nullptr || !IsBlobDataValid(&(keyInfo->keyAlias))) {
        DLP_LOG_ERROR(LABEL, "keyInfo is invalid!");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    struct HksParamSet *paramSet = nullptr;
    struct HksParam deGenParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE_256 },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = keyInfo->osAccountId },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t ret = ConstructParamSet(&paramSet, deGenParams, sizeof(deGenParams) / sizeof(deGenParams[0]));
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Construct MacKey ParamSet failed!");
        return DLP_ERROR_CONSTRUCT_PARAMS_FAILED;
    }
    ret = HksGenerateKey(reinterpret_cast<const struct HksBlob *>(&(keyInfo->keyAlias)), paramSet, nullptr);
    HksFreeParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "HksGenerateKey for mac key failed, error code: %{public}d.", ret);
        return DLP_ERROR_GENERATE_KEY_FAILED;
    }
    return DLP_OK;
}

int32_t HuksGenerateHmac(const AlgKeyInfo *keyInfo, const BlobData *data, BlobData *outData)
{
    if (!CheckHMACParams(keyInfo, data, outData)) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    outData->value = static_cast<uint8_t *>(HcMalloc(HASH_SIZE_SHA_256, 0));
    if (outData->value == nullptr) {
        DLP_LOG_ERROR(LABEL, "Allocate outData memory failed");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    outData->dataSize = HASH_SIZE_SHA_256;

    struct HksParamSet *hmacParamSet = nullptr;
    struct HksParam deHmacParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = keyInfo->osAccountId },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t res = ConstructParamSet(&hmacParamSet, deHmacParams, sizeof(deHmacParams) / sizeof(deHmacParams[0]));
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "construct hmac param set failed!");
        FreeBlobData(outData);
        return DLP_ERROR_CONSTRUCT_PARAMS_FAILED;
    }
    res = HksHMACThreeStages(&(keyInfo->keyAlias), hmacParamSet, data, outData);
    HksFreeParamSet(&hmacParamSet);
    if (res != DLP_OK) {
        FreeBlobData(outData);
        res = DLP_ERROR_HMAC_FAILED;
    }
    return res;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS