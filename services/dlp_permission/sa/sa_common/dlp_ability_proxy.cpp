/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_ability_proxy.h"
#include "dlp_ability_stub.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpAbilityProxy" };
}

int32_t DlpAbilityProxy::CheckRemoteAndSendRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &opt)
{
    sptr<IRemoteObject> remoteObj = Remote();
    if (remoteObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "remoteObj is nullptr.");
        return DLP_IPC_GETREMOTE_ERROR;
    }
    return remoteObj->SendRequest(code, data, reply, opt);
}

bool DlpAbilityProxy::PackMsg(sptr<IRemoteObject> stubInstance, MessageParcel &data)
{
    bool res = data.WriteInterfaceToken(GetDescriptor());
    res &= data.WriteRemoteObject(stubInstance);
    return res;
}

int32_t DlpAbilityProxy::HandleGetWaterMark(sptr<IRemoteObject> stubInstance)
{
    MessageParcel data;
    if (!PackMsg(stubInstance, data)) {
        DLP_LOG_ERROR(LABEL, "Pack data to msg failed.");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    MessageParcel reply;
    MessageOption opt(MessageOption::TF_SYNC);
    int32_t res = CheckRemoteAndSendRequest(static_cast<uint32_t>
        (DlpPermAbilityInterfaceCode::CMD_SEND_GET_WATERMARK), data, reply, opt);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "send HandleGetWaterMark request failed with errCode %{public}d", res);
        return DLP_IPC_SEND_REQUEST_ERROR;
    }
    int32_t replyCode = reply.ReadInt32();
    if (FAILED(replyCode)) {
        DLP_LOG_ERROR(LABEL, "HandleGetWaterMark failed in ability with errCode %{public}d", replyCode);
        return replyCode;
    }

    if (reply.ReadInterfaceToken() != IDlpAbilityCallback::GetDescriptor()) {
        return DLP_ABILITY_CONNECT_ERROR;
    }
    int32_t watermarkFd = -1;
    int32_t watermarkStatus = reply.ReadInt32();  //todo 判断异常情况
    if (watermarkStatus != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "recv watermark error with %{public}d", watermarkStatus);
        return watermarkFd;
    }
    watermarkFd = reply.ReadFileDescriptor();
    DLP_LOG_INFO(LABEL, "recv watermarkFd %{public}d", watermarkFd);
    return watermarkFd;
    
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS