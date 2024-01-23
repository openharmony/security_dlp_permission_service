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

#include "dlp_permission_kit.h"
#include <string>
#include <thread>
#include <vector>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKit"};
}  // namespace

int32_t DlpPermissionKit::GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert)
{
    unordered_json jsonObj;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeDlpPermission(policy, jsonObj);
    if (res != DLP_OK) {
        return res;
    }
    std::string certStr = jsonObj.dump();
    cert = std::vector<uint8_t>(certStr.begin(), certStr.end());
    return DLP_OK;
}

int32_t DlpPermissionKit::ParseDlpCertificate(sptr<CertParcel>& certParcel, PermissionPolicy& policy,
    const std::string& appId, const bool& offlineAccess)
{
    std::string encJsonStr(certParcel->cert.begin(), certParcel->cert.end());
    auto jsonObj = nlohmann::json::parse(encJsonStr, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    certParcel->offlineCert = certParcel->cert;
    return DlpPermissionSerializer::GetInstance().DeserializeDlpPermission(jsonObj, policy);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
