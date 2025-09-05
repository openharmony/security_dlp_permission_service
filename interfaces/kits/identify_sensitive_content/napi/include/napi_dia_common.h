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

#ifndef NAPI_DIA_COMMON_H
#define NAPI_DIA_COMMON_H

#include <string>
#include "napi/native_api.h"
#ifdef FILE_IDENTIFY_ENABLE
#include "dia_fi_defines.h"
#endif

namespace OHOS::Security::DIA{

#define NAPI_RETVAL_NOTHING

#define GET_AND_THROW_LAST_ERROR(env)                                                                   \
    do {                                                                                                \
        const napi_extended_error_info* errorInfo = nullptr;                                            \
        napi_get_last_error_info((env), &errorInfo);                                                    \
        bool isPending = false;                                                                         \
        napi_is_exception_pending((env), &isPending);                                                   \
        if (!isPending && errorInfo != nullptr) {                                                       \
            const char* errorMessage =                                                                  \
                errorInfo->error_message != nullptr ? errorInfo->error_message : "empty error message"; \
            napi_throw_error((env), nullptr, errorMessage);                                             \
        }                                                                                               \
    } while (0)

#define NAPI_ASSERT_BASE(env, assertion, message, retVal)                                    \
    do {                                                                                     \
        if (!(assertion)) {                                                                  \
            napi_throw_error((env), nullptr, "assertion (" #assertion ") failed: " message); \
            return retVal;                                                                   \
        }                                                                                    \
    } while (0)

#define NAPI_ASSERT(env, assertion, message) NAPI_ASSERT_BASE(env, assertion, message, nullptr)

#define NAPI_ASSERT_RETURN_VOID(env, assertion, message) NAPI_ASSERT_BASE(env, assertion, message, NAPI_RETVAL_NOTHING)

#define NAPI_CALL_BASE(env, theCall, retVal) \
    do {                                     \
        if ((theCall) != napi_ok) {          \
            GET_AND_THROW_LAST_ERROR((env)); \
            return retVal;                   \
        }                                    \
    } while (0)

#define NAPI_CALL(env, theCall) NAPI_CALL_BASE(env, theCall, nullptr)

#define NAPI_CALL_RETURN_VOID(env, theCall) NAPI_CALL_BASE(env, theCall, NAPI_RETVAL_NOTHING)

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
struct ScanFileAsyncContext : CommonAsyncContext{
    explicit ScanFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string filePath;
    std::vector<Policy> policies;
    std::vector<MatchResult> matchResultList;
};
bool NapiParsePolicyArray(napi_env env, std::vector<Policy> &policies, napi_value args);
void DIANapiThrow(napi_env env, int32_t nativeErrCode);
napi_value NapiComposeMarchResultArray(napi_env env, const std::vector<MatchResult> &matchResultList);
#endif
}
#endif