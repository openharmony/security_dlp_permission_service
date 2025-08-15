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

#ifndef DLP_COMMON_FUNC_H
#define DLP_COMMON_FUNC_H

#include "alg_common_type.h"
#include "alg_utils.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

int32_t GetHMACValue(const HMACSrcParams *hmacSrcParams,
    uint8_t **hmacValue, uint32_t *hmacValueSize, const BlobData *aliasBlob);

int32_t WriteHMACAndBufToFile(const HMACSrcParams *hmacSrcParams, const char *keyAlias, const char *filePath);

int32_t ReadBufFromFile(uint8_t **fileBuffer, uint32_t *fileSize, const char *filePath);

int32_t CompareHMACValue(const HMACSrcParams *hmacSrcParams, uint8_t **buffer, uint32_t *bufLen, const char *keyAlias);

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_COMMON_FUNC_H