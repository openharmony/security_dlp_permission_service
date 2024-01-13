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

#ifndef DLP_CREDENTIAL_H
#define DLP_CREDENTIAL_H

#include <string>
#include <vector>
#include "cert_parcel.h"
#include "i_dlp_permission_callback.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpCredential {
public:
    DlpCredential();
    ~DlpCredential() {};
    static DlpCredential& GetInstance();
    int32_t GenerateDlpCertificate(
        const std::string& policy, const std::string& accountInfo, DlpAccountType accountType,
        sptr<IDlpPermissionCallback>& callback);
    int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, sptr<IDlpPermissionCallback>& callback,
        const std::string& appId, const bool& offlineAccess);
    int32_t SetMDMPolicy(const std::vector<std::string>& appIdList);
    int32_t GetMDMPolicy(std::vector<std::string>& appIdList);
    int32_t RemoveMDMPolicy();
    int32_t CheckMdmPermission(const std::string& bundleName, int32_t userId);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_CREDENTIAL_H
