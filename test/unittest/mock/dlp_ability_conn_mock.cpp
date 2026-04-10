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

#include "dlp_ability_conn.h"
#include "dlp_permission.h"

#include <atomic>

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
std::atomic_bool g_forceConnected { false };
std::atomic_bool g_forceProxyNull { false };
}

namespace TestMock {
void ResetDlpAbilityConnMockState()
{
    g_forceConnected.store(false);
    g_forceProxyNull.store(false);
}

void SetDlpAbilityConnForceConnected(bool forceConnected)
{
    g_forceConnected.store(forceConnected);
}

void SetDlpAbilityConnForceProxyNull(bool forceProxyNull)
{
    g_forceProxyNull.store(forceProxyNull);
}
} // namespace TestMock

DlpAbilityConnection::DlpAbilityConnection(ConnectCallback connectCallback, DisconnectCallback disconnectCallback)
{
    connectCallback_ = connectCallback;
    disconnectCallback_ = disconnectCallback;
}

DlpAbilityConnection::~DlpAbilityConnection()
{
    connectCallback_ = nullptr;
    disconnectCallback_ = nullptr;
}

sptr<IRemoteObject> DlpAbilityConnection::GetProxy()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (g_forceProxyNull.load()) {
        return nullptr;
    }
    return remoteObj_;
}

void DlpAbilityConnection::ClearProxy()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    remoteObj_ = nullptr;
}

void DlpAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObj, int res)
{
    (void)element;
    (void)res;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    remoteObj_ = remoteObj;
    if (connectCallback_ != nullptr) {
        connectCallback_(remoteObj_);
    }
}

void DlpAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int res)
{
    (void)element;
    (void)res;
    if (disconnectCallback_ != nullptr && isDestroyFlag_ == false) {
        disconnectCallback_(DLP_HAP_DISCONN_ERROR, 0, nullptr, 0);
    }
    ClearProxy();
}

bool DlpAbilityConnection::IsConnected()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (g_forceConnected.load()) {
        return true;
    }
    return remoteObj_ != nullptr;
}

void DlpAbilityConnection::SetIsDestroyFlag(bool flag)
{
    isDestroyFlag_ = flag;
}

} // namespace DlpPermission
} // namespace Security
} // namespace OHOS