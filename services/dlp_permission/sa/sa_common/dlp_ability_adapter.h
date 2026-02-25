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

#ifndef DLP_ABILITY_ADAPTER_H
#define DLP_ABILITY_ADAPTER_H

#include <mutex>
#include <functional>
#include <iremote_object.h>
#include "dlp_permission_service.h"
#include "dlp_ability_conn.h"
#include "dlp_ability_stub.h"


namespace OHOS {
namespace Security {
namespace DlpPermission {

class DlpAbilityAdapter {
public:
    explicit DlpAbilityAdapter(ReceiveDataCallback &callback);
    int32_t HandleGetWaterMark(int32_t userId, WaterMarkInfo &waterMarkInfo, std::condition_variable &waterMarkInfoCv);
    void SetIsDestroyFlag(bool flag);
    ~DlpAbilityAdapter();

private:
    int32_t ConnectPermServiceAbility(int32_t userId,
        std::function<void(OHOS::sptr<OHOS::IRemoteObject>)> connectCallback);
    void DisconnectPermServiceAbility();
    std::recursive_mutex mutex_;
    OHOS::sptr<DlpAbilityConnection> abilityConnection_;
    ReceiveDataCallback callback_{nullptr};
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif