/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef INTERFACES_KITS_NAPI_DLP_PERMISSION_TOOLS_INCLUDE_NAPI_H
#define INTERFACES_KITS_NAPI_DLP_PERMISSION_TOOLS_INCLUDE_NAPI_H

#include "dlp_permission_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "parcel.h"
#include "permission_policy.h"
#include "napi_common.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class NapiDlpPermissionTools {
public:
    static bool CheckPermission(napi_env env, const std::string &permission);
    static napi_value BindingJsWithNative(napi_env env, napi_value *argv, size_t argc);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif /*  INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H */