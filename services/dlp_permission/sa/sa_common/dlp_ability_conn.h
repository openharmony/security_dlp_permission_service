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

#ifndef DLP_ABILITY_CONN_H
#define DLP_ABILITY_CONN_H

#include <mutex>
#include <functional>
#include <iremote_stub.h>
#include <iremote_object.h>
#include <ability_connect_callback_stub.h>
#include "dlp_ability_stub.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;

class DlpAbilityConnection : public AAFwk::AbilityConnectionStub {
public:
    using ConnectCallback = std::function<void(sptr<IRemoteObject>)>;
    using DisconnectCallback = ReceiveDataCallback;

    DlpAbilityConnection() = default;
    explicit DlpAbilityConnection(ConnectCallback connectCallback,
        DisconnectCallback disconnectCallback);
    ~DlpAbilityConnection();
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObj, int res) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int res) override;
    bool IsConnected();
    sptr<IRemoteObject> GetProxy();
    void ClearProxy();
    void SetIsDestroyFlag(bool flag);

private:
    std::recursive_mutex mutex_;
    bool isDestroyFlag_{false};
    ConnectCallback connectCallback_{nullptr};
    DisconnectCallback disconnectCallback_{nullptr};
    sptr<IRemoteObject> remoteObj_{nullptr};
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif