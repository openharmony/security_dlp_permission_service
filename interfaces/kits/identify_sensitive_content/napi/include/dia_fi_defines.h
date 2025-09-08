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

#ifndef DIA_FI_DEFINES_H
#define DIA_FI_DEFINES_H

#include <string>
#include <vector>

namespace OHOS::Security::DIA {

struct MatchResult {
    std::string sensitiveLabel;
    std::string matchContent;
    unsigned matchNumber;
};

struct Policy {
    std::string sensitiveLabel;
    std::vector<std::string> keywords;
    std::string regex;
};

struct DIA_String {
    char *data;
    unsigned dataLength;
};
struct MatchResultC {
    DIA_String sensitiveLabel;
    DIA_String matchContent;
    unsigned matchNumber;
};

struct PolicyC {
    DIA_String sensitiveLabel;
    DIA_String *keywords;
    DIA_String regex;
    unsigned keywordsLength;
};

enum DIAErrCode {
    DIA_SUCCESS = 0,
    DIA_FAILURE = 1,
    DIA_ERR_CONFIG_SIPRAM = 1000,
    DIA_ERR_CONFIG_CALLBACK = 1001,
    DIA_ERR_DATA_ILLEGAL = 1002,
    DIA_ERR_INVALID_PARAM = 1003,
    DIA_ERR_PERMISSION_DENIED = 1004,
    DIA_ERR_MALLOC = 1005,
    DIA_ERR_NULL_PTR = 1006,
    DIA_ERR_SERVICE_STOP = 1007,

    DIA_ERR_IH_TEXTIDENTIFY = 1105,

    DIA_ERR_FI_TIME_OUT = 1200,
    DIA_ERR_FI_INVALID_FILE = 1201,
    DIA_ERR_FI_READ_FILE = 1202,
    DIA_ERR_FI_POLICY_ERROR = 1203,
    DIA_ERR_FI_NOT_SENSITIVE_FILE = 1204,
    DIA_ERR_FI_FILE_NO_PERMISSION = 1205,
};

}  // namespace OHOS::Security::DIA
#endif /*  DIA_FI_DEFINES_H */