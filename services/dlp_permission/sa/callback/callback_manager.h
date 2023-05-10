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

#ifndef DLP_PERMISSION_CALLBACK_MANAGER_H
#define DLP_PERMISSION_CALLBACK_MANAGER_H

#include <mutex>
#include <map>

#include "dlp_permission_sandbox_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct CallbackRecord {
    CallbackRecord() : callbackObject_(nullptr) {}
    CallbackRecord(sptr<IRemoteObject> callback) : callbackObject_(callback) {}

    sptr<IRemoteObject> callbackObject_;
    uint32_t pid;
};

class CallbackManager {
public:
    virtual ~CallbackManager();
    CallbackManager();
    static CallbackManager &GetInstance();

    int32_t AddCallback(uint32_t pid, const sptr<IRemoteObject> &callback);
    int32_t RemoveCallback(const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(uint32_t pid, bool &result);
    void ExecuteCallbackAsync(const DlpSandboxInfo &dlpSandboxInfo);

private:
    std::mutex mutex_;
    std::map<uint32_t, CallbackRecord> callbackInfoMap_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_PERMISSION_CALLBACK_MANAGER_H