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

#ifndef NAPI_DLP_TRANSPARENT_ENC_H
#define NAPI_DLP_TRANSPARENT_ENC_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

typedef enum {
    DLP_SUCCESS = 0x00000000,
    DLP_ERR_INVALID_PARAMS = 0x00000002,
    DLP_ERR_NOT_ENTERPRISE_WORKSPACE = 0x0000D004,
    DLP_ERR_USERID_INCONSISTENT = 0x0000D007,
    DLP_ERR_CHECK_PERFMISSION = 0x00002009,
    DLP_ERR_FILE_INVALID = 0x0000D00B,
} DLP_ErrorCode;

napi_value InitDlpTransparentEncFunction(napi_env env, napi_value exports);

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif /*  NAPI_DLP_TRANSPARENT_ENC_H */