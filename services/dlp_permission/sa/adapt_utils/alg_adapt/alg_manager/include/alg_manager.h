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

#ifndef ALG_MANAGER_H
#define ALG_MANAGER_H

#include "alg_common_type.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

bool AlgIsKeyExist(const AlgKeyInfo *keyInfo);
int32_t AlgGenerateMacKey(const AlgKeyInfo *keyInfo);
int32_t AlgHmac(const AlgKeyInfo *keyInfo, const BlobData *data, BlobData *outData);

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // ALG_MANAGER_H