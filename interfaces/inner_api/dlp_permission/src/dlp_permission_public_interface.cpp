/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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


#include "dlp_permission_public_interface.h"
#include "dlp_permission.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Json = nlohmann::json;
const std::string DLP_CONTACT_ACCOUNT = "contactAccount";
const std::string DLP_VERSION = "dlp_version";
const std::string DLP_VERSION_LOW_CAMEL_CASE = "dlpVersion";
const std::string DLP_OFFLINE_FLAG = "offlineAccess";
const std::string DLP_EXTRA_INFO = "extra_info";
const std::string DLP_EXTRA_INFO_LOW_CAMEL_CASE = "extraInfo";
const std::string DLP_HMAC_VALUE = "hmacValue";
static bool checkParams(GenerateInfoParams& params, const nlohmann::json& jsonObj,
                        const std::string& versionKey, const std::string& infoKey)
{
    auto iter = jsonObj.find(versionKey);
    if (iter == jsonObj.end() || !iter->is_number_integer()) {
        return false;
    }
    iter = jsonObj.find(infoKey);
    if (iter != jsonObj.end() && iter->is_array() &&
        !iter->empty() && iter->at(0).is_string()) {
        return true;
    }
    return false;
}

int32_t GenerateDlpGeneralInfo(const GenerateInfoParams& params, std::string& generalInfo)
{
    nlohmann::json dlp_general_info;

#ifdef DLP_FILE_VERSION_INNER
    uint32_t version = params.version;
#else
    uint32_t version = CURRENT_VERSION;
#endif

    dlp_general_info[DLP_VERSION_LOW_CAMEL_CASE] = version;
    dlp_general_info[DLP_OFFLINE_FLAG] = params.offlineAccessFlag;
    if (params.contactAccount.empty()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    dlp_general_info[DLP_CONTACT_ACCOUNT] = params.contactAccount;
    dlp_general_info[DLP_EXTRA_INFO_LOW_CAMEL_CASE] = params.extraInfo;
    if (params.extraInfo.empty()) {
        dlp_general_info[DLP_EXTRA_INFO_LOW_CAMEL_CASE] = {"kia_info", "cert_info", "enc_data"};
    }
    if (version >= HMAC_VERSION) {
        dlp_general_info[DLP_HMAC_VALUE] = params.hmacVal;
    }
    generalInfo = dlp_general_info.dump();
    return DLP_OK;
}

int32_t ParseDlpGeneralInfo(const std::string& generalInfo, GenerateInfoParams& params)
{
    if (generalInfo.empty()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto jsonObj = nlohmann::json::parse(generalInfo, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (checkParams(params, jsonObj, DLP_VERSION, DLP_EXTRA_INFO)) {
        params.version = jsonObj.at(DLP_VERSION).get<uint32_t>();
        params.extraInfo = jsonObj.at(DLP_EXTRA_INFO).get<std::vector<std::string>>();
    } else if (checkParams(params, jsonObj, DLP_VERSION_LOW_CAMEL_CASE, DLP_EXTRA_INFO_LOW_CAMEL_CASE)) {
        params.version = jsonObj.at(DLP_VERSION_LOW_CAMEL_CASE).get<uint32_t>();
        params.extraInfo = jsonObj.at(DLP_EXTRA_INFO_LOW_CAMEL_CASE).get<std::vector<std::string>>();
    } else {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    auto iter = jsonObj.find(DLP_OFFLINE_FLAG);
    if (iter != jsonObj.end() && iter->is_boolean()) {
        params.offlineAccessFlag = iter->get<bool>();
    } else {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    iter = jsonObj.find(DLP_CONTACT_ACCOUNT);
    if (iter != jsonObj.end() && iter->is_string()) {
        params.contactAccount = iter->get<std::string>();
        if (params.contactAccount == "") {
            return DLP_PARSE_ERROR_VALUE_INVALID;
        }
    }
    iter = jsonObj.find(DLP_HMAC_VALUE);
    if (iter != jsonObj.end() && iter->is_string()) {
        params.hmacVal = iter->get<std::string>();
    } else if (params.version >= HMAC_VERSION) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS