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

#ifndef DLP_APP_UNINSTALL_OBSERVER_OBSERVER_H
#define DLP_APP_UNINSTALL_OBSERVER_OBSERVER_H

#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "sandbox_config_kv_data_storage.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class AppUninstallObserver : public EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<AppUninstallObserver> {
public:
    explicit AppUninstallObserver(const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    virtual ~AppUninstallObserver() {};
    virtual void OnReceiveEvent(const EventFwk::CommonEventData& data);
};

class DlpEventSubSubscriber {
public:
    DlpEventSubSubscriber();
private:
    std::shared_ptr<AppUninstallObserver> subscriber_ = nullptr;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS


#endif // DLP_APP_UNINSTALL_OBSERVER_OBSERVER_H
