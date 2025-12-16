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

#include "dlp_ability_stub.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpAbilityStub" };
}

sptr<DlpAbilityStub> DlpAbilityStub::singleton_ = nullptr;
std::mutex DlpAbilityStub::mutex_;

DlpAbilityStub::DlpAbilityStub(ReceiveDataCallback callback)
{
    callback_ = callback;
}

sptr<DlpAbilityStub> DlpAbilityStub::GetInstance(ReceiveDataCallback callback)
{
    if (singleton_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (singleton_ == nullptr) {
            singleton_ = new (std::nothrow) DlpAbilityStub(callback);
            DLP_LOG_INFO(LABEL, "Create DlpAbilityStub instance.");
        }
    }
    return singleton_;
}

void DlpAbilityStub::OnResult(uint64_t reqId, int32_t userId, std::string &jsonRes)
{
    (void)reqId;
    (void)userId;
    (void)jsonRes;
    return;
}

int32_t DlpAbilityStub::OnRemoteRequest(uint32_t errCode, MessageParcel &data,
    MessageParcel &reply, MessageOption &opt)
{
    (void)errCode;
    (void)opt;
    if (GetDescriptor() != data.ReadInterfaceToken()) {
        DLP_LOG_ERROR(LABEL, "RemoteRequest failed with dismatch descriptor.");
        return DLP_IPC_DISMATCH_DESCRIPTOR;
    }
    return DLP_OK; // getwatermark同步调用
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS