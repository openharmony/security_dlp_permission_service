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

#ifndef DLP_PERMISSION_PUBLIC_INTERFACE_H
#define DLP_PERMISSION_PUBLIC_INTERFACE_H

#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const uint32_t CURRENT_VERSION = 3;
static const uint32_t HMAC_VERSION = 3;

struct GenerateInfoParams {
    uint32_t version;
    bool offlineAccessFlag;
    std::string contactAccount;
    std::vector<std::string> extraInfo;
    std::string hmacVal;
};

int32_t GenerateDlpGeneralInfo(const GenerateInfoParams& params, std::string& generalInfo);
int32_t ParseDlpGeneralInfo(const std::string& generalInfo, GenerateInfoParams& params);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif // DLP_PERMISSION_PUBLIC_INTERFACE_H