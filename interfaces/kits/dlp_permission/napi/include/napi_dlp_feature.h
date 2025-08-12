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

#ifndef NAPI_DLP_FEATURE_H
#define NAPI_DLP_FEATURE_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class NapiDlpFeature {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static void InitFunction(napi_env env, napi_value exports);

    static void SetDlpFeatureExecute(napi_env env, void* data);
    static void SetDlpFeatureComplete(napi_env env, napi_status status, void* data);
    static napi_value SetDlpFeature(napi_env env, napi_callback_info cbInfo);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  NAPI_DLP_FEATURE_H */