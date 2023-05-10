/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_uninstall_observer.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "retention_file_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppUninstallObserver" };
}

AppUninstallObserver::AppUninstallObserver(const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : CommonEventSubscriber(subscribeInfo)
{}

void AppUninstallObserver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
        std::string bundleName = data.GetWant().GetBundle();
        DLP_LOG_INFO(LABEL, "action %{public}s %{public}s is uninstall", action.c_str(), bundleName.c_str());
        if (RetentionFileManager::GetInstance().HasRetentionSandboxInfo(bundleName)) {
            RetentionFileManager::GetInstance().RemoveRetentionState(bundleName, -1);
        }
    }
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS