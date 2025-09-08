/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025
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

#ifndef NAPI_IDENTIFY_SENSITIVE_CONTENT_H
#define NAPI_IDENTIFY_SENSITIVE_CONTENT_H

#include "napi/native_api.h"
#include "napi/native_common.h"


namespace OHOS::Security::DIA {

class NapiIdentifySensitiveContent {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value ScanFile(napi_env env, napi_callback_info info);
};
} // namespace OHOS::Security::DIA
#endif // NAPI_IDENTIFY_SENSITIVE_CONTENT_H