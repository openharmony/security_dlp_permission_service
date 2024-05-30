/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mock_utils.h"
#include "dlp_permission_log.h"
#include "hex_string.h"
#include "nlohmann/json.hpp"

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "MockUtil" };
static const std::string POLICY_CERT = "policyCert";
static const std::string TEXT_CERT = "plaintextPolicy";
}
using unordered_json = nlohmann::ordered_json;

bool ModifyParseData(uint8_t** data, uint32_t* dataLen, uint8_t* dataIn, uint32_t dataInLen)
{
    uint32_t encDataHexLen = dataInLen * OHOS::Security::DlpPermission::BYTE_TO_HEX_OPER_LENGTH + 1;
    char* encDataHex = new (std::nothrow) char[encDataHexLen];
    if (encDataHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail.");
        return false;
    }
    int32_t res = OHOS::Security::DlpPermission::ByteToHexString(dataIn, dataInLen, encDataHex, encDataHexLen);
    if (res != 0) {
        delete[] encDataHex;
        return false;
    }
    std::string txtStr = encDataHex;
    unordered_json json;
    json[TEXT_CERT] = txtStr;
    json[POLICY_CERT] = unordered_json::parse(dataIn, dataIn + dataInLen + 1, nullptr, false);
    std::string certStr = json.dump();
    delete[] encDataHex;
    *data = (uint8_t *)strdup(const_cast<char *>(certStr.c_str()));
    *dataLen = certStr.length();
    return true;
}