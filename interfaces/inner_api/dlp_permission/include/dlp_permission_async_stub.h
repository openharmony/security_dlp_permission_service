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

#ifndef DLP_PERMISSION_ASYNC_STUB_H
#define DLP_PERMISSION_ASYNC_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>
#include "dlp_permission_kit.h"
#include "idlp_permission_callback.h"
#include "dlp_permission_callback.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionAsyncStub : public IRemoteStub<IDlpPermissionCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DlpPermissionAsyncStub);
    explicit DlpPermissionAsyncStub(const std::shared_ptr<GenerateDlpCertificateCallback>& impl);
    explicit DlpPermissionAsyncStub(const std::shared_ptr<ParseDlpCertificateCallback>& impl);
    explicit DlpPermissionAsyncStub(const std::shared_ptr<GetWaterMarkCallback>& impl);
    ~DlpPermissionAsyncStub() override = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override;
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override;
    void OnGetDlpWaterMark(int32_t result, const GeneralInfo& info) override;

private:
    int32_t OnGenerateDlpCertificateStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnParseDlpCertificateStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnGetDlpWaterMarkStub(MessageParcel& data, MessageParcel& reply);

    std::shared_ptr<GenerateDlpCertificateCallback> generateDlpCertificateCallback_ {nullptr};
    std::shared_ptr<ParseDlpCertificateCallback> parseDlpCertificateCallback_ {nullptr};
    std::shared_ptr<GetWaterMarkCallback> getWaterMarkCallback_ {nullptr};
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // DLP_PERMISSION_ASYNC_STUB_H
