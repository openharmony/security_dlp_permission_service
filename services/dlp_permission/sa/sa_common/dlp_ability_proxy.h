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

#ifndef DLP_ABILITY_PROXY_H
#define DLP_ABILITY_PROXY_H

#include <iremote_stub.h>
#include <iremote_proxy.h>
#include <iremote_broker.h>
#include <iremote_object.h>

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;

enum class DlpPermAbilityInterfaceCode {
    CMD_SEND_GET_WATERMARK = 101,
};

class IDlpAbility : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DlpPermStub");
    virtual int32_t HandleGetWaterMark(sptr<IRemoteObject> remoteObj) = 0;
};

class DlpAbilityProxy : public IRemoteProxy<IDlpAbility> {
public:
    explicit DlpAbilityProxy(const sptr<IRemoteObject> &remoteObj) :
        IRemoteProxy<IDlpAbility>(remoteObj) {}
    virtual ~DlpAbilityProxy() {}
    int32_t HandleGetWaterMark(sptr<IRemoteObject> stubInstance) override;

private:
    bool PackMsg(sptr<IRemoteObject> stubInstance, MessageParcel &msg);
    int32_t CheckRemoteAndSendRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &opt);
    static inline BrokerDelegator<DlpAbilityProxy> delegator_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif