/*
 * Copyright (c) Huawei Device Co., Ltd. 2025-2025
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

#include <unordered_map>
#include "napi_dia_error_msg.h"
#include "dia_fi_defines.h"

namespace OHOS::Security::DIA {

static const std::unordered_map<int32_t, std::string> DIA_JS_ERROR_MSG_MAP = {
    //  error + message
    { ERR_DIA_JS_SUCCESS, "success" },
    { ERR_DIA_JS_PERMISSION_DENIED, "Permission denied." },
    { ERR_DIA_JS_PARAMETER_ERROR, "Parameter type error, please check parameter type." },
    { ERR_DIA_JS_CAPABILITY_NOT_SUPPORTED, "Capability is not supported." },
    { ERR_DIA_JS_INVALID_PARAMETER, "Parameter error" },
    { ERR_DIA_JS_TIME_OUT, "Sensitive file content identification timed out." },
    { ERR_DIA_JS_FILE_NOT_SUPPORTED, "The file is not supported." },
    { ERR_DIA_JS_SYSTEM_SERVICE_EXCEPTION, "A system error has occurred." },
};

std::string GetDIAJsErrMsg(int32_t diaErrCode)
{
    auto iter = DIA_JS_ERROR_MSG_MAP.find(diaErrCode);
    if (iter != DIA_JS_ERROR_MSG_MAP.end()) {
        return iter->second;
    }
    std::string msg = "unkown error, please reboot your device and try again, error=" + std::to_string(diaErrCode);
    return msg;
}

#ifdef FILE_IDENTIFY_ENABLE
static const std::unordered_map<int32_t, int32_t> NATIVE_CODE_TO_DIA_JS_CODE_MAP = {
    // ERR_DIA_JS_SUCCESS
    { DIA_SUCCESS, ERR_DIA_JS_SUCCESS },
    { DIA_ERR_FI_NOT_SENSITIVE_FILE, ERR_DIA_JS_SUCCESS },

    // ERR_DIA_JS_PERMISSION_DENIED
    { DIA_ERR_PERMISSION_DENIED, ERR_DIA_JS_PERMISSION_DENIED },

    // ERR_DIA_JS_INVALID_PARAMETER
    { DIA_ERR_DATA_ILLEGAL, ERR_DIA_JS_INVALID_PARAMETER },
    { DIA_ERR_INVALID_PARAM, ERR_DIA_JS_INVALID_PARAMETER },
    { DIA_ERR_FI_POLICY_ERROR, ERR_DIA_JS_INVALID_PARAMETER },

    // ERR_DIA_JS_TIME_OUT
    { DIA_ERR_FI_TIME_OUT, ERR_DIA_JS_TIME_OUT },

    // ERR_DIA_JS_FILE_NOT_SUPPORTED
    { DIA_ERR_FI_INVALID_FILE, ERR_DIA_JS_FILE_NOT_SUPPORTED },
    { DIA_ERR_FI_READ_FILE, ERR_DIA_JS_FILE_NOT_SUPPORTED },
    { DIA_ERR_FI_FILE_NO_PERMISSION, ERR_DIA_JS_FILE_NOT_SUPPORTED },
    { DIA_ERR_IH_TEXTIDENTIFY, ERR_DIA_JS_FILE_NOT_SUPPORTED },
};

int32_t NativeCodeToDIAJsCode(int32_t nativeErrCode)
{
    auto iter = NATIVE_CODE_TO_DIA_JS_CODE_MAP.find(nativeErrCode);
    if (iter != NATIVE_CODE_TO_DIA_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return ERR_DIA_JS_SYSTEM_SERVICE_EXCEPTION;
}
#endif
}  // namespace OHOS::Security::DIA
