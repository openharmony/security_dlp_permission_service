/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DLP_PERMISSION_STUB_H
#define DLP_PERMISSION_STUB_H

#include <map>
#include "i_dlp_permission_service.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionStub : public IRemoteStub<IDlpPermissionService> {
public:
    DlpPermissionStub();
    virtual ~DlpPermissionStub();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t GenerateDlpCertificateInner(MessageParcel& data, MessageParcel& reply);
    int32_t ParseDlpCertificateInner(MessageParcel& data, MessageParcel& reply);
    int32_t InstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply);
    int32_t UninstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetSandboxExternalAuthorizationInner(MessageParcel& data, MessageParcel& reply);

    int32_t QueryDlpFileCopyableByTokenIdInner(MessageParcel& data, MessageParcel& reply);
    int32_t QueryDlpFileAccessInner(MessageParcel& data, MessageParcel& reply);
    int32_t IsInDlpSandboxInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDlpSupportFileTypeInner(MessageParcel& data, MessageParcel& reply);
    int32_t RegisterDlpSandboxChangeCallbackInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegisterDlpSandboxChangeCallbackInner(MessageParcel &data, MessageParcel &reply);
    int32_t RegisterOpenDlpFileCallbackInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegisterOpenDlpFileCallbackInner(MessageParcel &data, MessageParcel &reply);

    int32_t GetDlpGatheringPolicyInner(MessageParcel& data, MessageParcel& reply);
    int32_t SetRetentionStateInner(MessageParcel& data, MessageParcel& reply);
    int32_t CancelRetentionStateInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetRetentionSandboxListInner(MessageParcel& data, MessageParcel& reply);
    int32_t ClearUnreservedSandboxInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDLPFileVisitRecordInner(MessageParcel& data, MessageParcel& reply);

    using RequestFuncType = int32_t (DlpPermissionStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_STUB_H
