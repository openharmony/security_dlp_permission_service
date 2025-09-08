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

#ifndef NAPI_DIA_ERROR_MSG_H
#define NAPI_DIA_ERROR_MSG_H

#include <string>

namespace OHOS::Security::DIA {
enum DIAErrorCode : int32_t {
    ERR_DIA_JS_SUCCESS = 0,
    ERR_DIA_JS_PERMISSION_DENIED = 201,
    ERR_DIA_JS_PARAMETER_ERROR = 401,
    ERR_DIA_JS_CAPABILITY_NOT_SUPPORTED = 801,
    ERR_DIA_JS_INVALID_PARAMETER = 19110001,
    ERR_DIA_JS_TIME_OUT = 19110002,
    ERR_DIA_JS_FILE_NOT_SUPPORTED = 19110003,
    ERR_DIA_JS_SYSTEM_SERVICE_EXCEPTION = 19110004,
};

std::string GetDIAJsErrMsg(int32_t errNo);
#ifdef FILE_IDENTIFY_ENABLE
int32_t NativeCodeToDIAJsCode(int32_t nativeErrCode);
#endif
}  // namespace OHOS::Security::DIA
#endif /*  NAPI_DIA_ERROR_MSG_H */
