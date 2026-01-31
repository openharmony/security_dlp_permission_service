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

#include "account_event_subscriber.h"
#include "common_event_support.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionService" };
}
AccountEventSubscriber::AccountEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo, AccountListenerCallback &callback)
    : EventFwk::CommonEventSubscriber(subscribeInfo), callback_(callback)
{}

AccountEventSubscriber::~AccountEventSubscriber()
{
    callback_.registerAccount = nullptr;
    callback_.unregisterAccount = nullptr;
}

void AccountEventSubscriber::HandleRegisterCloudAccount(const EventFwk::CommonEventData &data)
{
    DLP_LOG_ERROR(LABEL, "HandleRegisterCloudAccount Start.");
    callback_.registerAccount();
}

void AccountEventSubscriber::HandleUnregisterCloudAccount(const EventFwk::CommonEventData &data)
{
    DLP_LOG_ERROR(LABEL, "HandleUnregisterCloudAccount Start.");
    callback_.unregisterAccount();
}

void AccountEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN) {
        HandleRegisterCloudAccount(data);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT ||
               action == EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF) {
        HandleUnregisterCloudAccount(data);
    }
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS