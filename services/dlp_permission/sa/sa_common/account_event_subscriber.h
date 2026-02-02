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

#ifndef DLP_ACCOUNT_EVENT_SUBSCRIBER_H
#define DLP_ACCOUNT_EVENT_SUBSCRIBER_H

#include "common_event_subscriber.h"
#include "account_status_listener.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class AccountEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    AccountEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo, AccountListenerCallback &callback);
    virtual ~AccountEventSubscriber();
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    void HandleRegisterCloudAccount();
    void HandleUnregisterCloudAccount();
    AccountListenerCallback callback_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif