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

#include "account_status_listener.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "dlp_permission_log.h"
#include "account_event_subscriber.h"
#include "alg_utils.h"

using namespace OHOS::Security::DlpPermission;
using OHOS::EventFwk::CommonEventManager;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountStatusListener"};
}

static std::shared_ptr<AccountEventSubscriber> g_eventSubscriber = nullptr;

int32_t RegisterAccountEventMonitor(AccountListenerCallback *callback)
{
    if (g_eventSubscriber != nullptr) {
        return DLP_SUCCESS;
    }

    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid callback");
        return DLP_ERROR;
    }

    using OHOS::EventFwk::CommonEventSubscribeInfo;
    using OHOS::EventFwk::CommonEventSupport;
    using OHOS::EventFwk::MatchingSkills;

    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    g_eventSubscriber = std::make_shared<AccountEventSubscriber>(subscribeInfo, *callback);
    if (!CommonEventManager::SubscribeCommonEvent(g_eventSubscriber)) {
        DLP_LOG_ERROR(LABEL, "SubscribeCommonEvent failed.");
        g_eventSubscriber = nullptr;
        return DLP_ERROR;
    }
    return DLP_SUCCESS;
}

void UnRegisterAccountMonitor(void)
{
    if (g_eventSubscriber != nullptr) {
        if (!CommonEventManager::UnSubscribeCommonEvent(g_eventSubscriber)) {
            DLP_LOG_ERROR(LABEL, "Unregister account common event listener failed");
        }
        g_eventSubscriber = nullptr;
    }
}