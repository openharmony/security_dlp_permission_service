/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "dlp_ability_stub.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
bool g_forceStubNull = false;
}

sptr<DlpAbilityStub> DlpAbilityStub::singleton_ = nullptr;
std::mutex DlpAbilityStub::mutex_;

namespace TestMock {
void ResetDlpAbilityStubMockState()
{
    g_forceStubNull = false;
}

void SetDlpAbilityStubForceNull(bool forceNull)
{
    g_forceStubNull = forceNull;
}
} // namespace TestMock

DlpAbilityStub::DlpAbilityStub(ReceiveDataCallback callback)
{
    callback_ = callback;
}

sptr<DlpAbilityStub> DlpAbilityStub::GetInstance(ReceiveDataCallback callback)
{
    if (g_forceStubNull) {
        return nullptr;
    }
    if (singleton_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (singleton_ == nullptr) {
            singleton_ = new (std::nothrow) DlpAbilityStub(callback);
        }
    }
    return singleton_;
}

void DlpAbilityStub::OnResult(uint64_t reqId, int32_t userId, std::string &jsonRes)
{
    (void)reqId;
    (void)userId;
    (void)jsonRes;
}

int32_t DlpAbilityStub::OnRemoteRequest(uint32_t errCode, MessageParcel &data,
    MessageParcel &reply, MessageOption &opt)
{
    (void)errCode;
    (void)data;
    (void)reply;
    (void)opt;
    return 0;
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS