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

#ifndef DLP_PERMISSION_ASYNC_PROXY_H
#define DLP_PERMISSION_ASYNC_PROXY_H

#include <string>
#include <vector>
#include "dlp_permission.h"
#include "idlp_permission_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionAsyncProxy : public IRemoteProxy<IDlpPermissionCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DlpPermissionAsyncProxy);
    explicit DlpPermissionAsyncProxy(const sptr<IRemoteObject>& object) : IRemoteProxy<IDlpPermissionCallback>(object)
    {}
    ~DlpPermissionAsyncProxy() override = default;

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override;
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override;

private:
    static inline BrokerDelegator<DlpPermissionAsyncProxy> delegator_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_ASYNC_PROXY_H
