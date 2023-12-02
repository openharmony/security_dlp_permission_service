/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ERROR_MSG_H
#define INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ERROR_MSG_H

#include <string>

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum JsErrorCode : int32_t {
    ERR_JS_SUCCESS = 0,
    ERR_JS_PERMISSION_DENIED = 201,
    ERR_JS_NOT_SYSTEM_APP = 202,
    ERR_JS_PARAMETER_ERROR = 401,
    ERR_JS_CAPABILITY_NOT_SUPPORTED = 801,
    ERR_JS_INVALID_PARAMETER = 19100001,
    ERR_JS_BEGIN_CREDENTIAL_FAIL = 19100002,
    ERR_JS_CREDENTIAL_TIMEOUT = 19100003,
    ERR_JS_CREDENTIAL_SERVICE_ERROR = 19100004,
    ERR_JS_CREDENTIAL_SERVER_ERROR = 19100005,
    ERR_JS_API_ONLY_FOR_SANDBOX_ERROR = 19100006,
    ERR_JS_API_NOT_FOR_SANDBOX_ERROR = 19100007,
    ERR_JS_NOT_DLP_FILE = 19100008,
    ERR_JS_OPERATE_DLP_FILE_FAIL = 19100009,
    ERR_JS_DLP_FILE_READ_ONLY = 19100010,
    ERR_JS_SYSTEM_SERVICE_EXCEPTION = 19100011,
    ERR_JS_OUT_OF_MEMORY = 19100012,
    ERR_JS_USER_NO_PERMISSION = 19100013,
    ERR_JS_ACCOUNT_NOT_LOGIN = 19100014,
    ERR_JS_SYSTEM_NEED_TO_BE_UPGRADED = 19100015,
    ERR_JS_URI_NOT_EXIST = 19100016,
    ERR_JS_PARAM_DISPLAY_NAME_NOT_EXIST = 19100017,
    ERR_JS_APPLICATION_NOT_AUTHORIZED = 19100018,
    ERR_JS_DLP_FILE_EXPIRE_TIME = 19100019,
    ERR_JS_DLP_CREDENTIAL_NO_INTERNET_ERROR = 19100020,
};

std::string GetJsErrMsg(int32_t errNo);
int32_t NativeCodeToJsCode(int32_t nativeErrCode);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ERROR_MSG_H */
