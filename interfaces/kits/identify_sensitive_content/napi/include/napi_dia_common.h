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

#ifndef NAPI_DIA_COMMON_H
#define NAPI_DIA_COMMON_H

#include <string>
#include "dia_fi_defines.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS::Security::DIA {

constexpr size_t ARG_SIZE_TWO = 2;

constexpr size_t PARAM_ZERO = 0;
constexpr size_t PARAM_ONE = 1;

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env napiEnv);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status = napi_invalid_arg;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
    napi_ref callbackRef = nullptr;    // callback handle
    napi_async_work work = nullptr;    // work handle
};

napi_value GenerateBusinessError(napi_env env, int32_t diaErrCode, const std::string &diaErrMsg);
bool NapiParseString(napi_env env, std::string &param, napi_value args);
void DIANapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg);

#ifdef FILE_IDENTIFY_ENABLE
struct ScanFileAsyncContext : CommonAsyncContext {
    explicit ScanFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string filePath;
    std::vector<Policy> policies;
    std::vector<MatchResult> matchResultList;
};
bool NapiParsePolicyArray(napi_env env, std::vector<Policy> &policies, napi_value args);
void DIANapiThrow(napi_env env, int32_t nativeErrCode);
napi_value NapiComposeMatchResultArray(napi_env env, const std::vector<MatchResult> &matchResultList);
#endif
}
#endif