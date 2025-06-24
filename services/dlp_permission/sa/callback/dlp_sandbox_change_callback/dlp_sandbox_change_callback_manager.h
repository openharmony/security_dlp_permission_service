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

#include "dlp_sandbox_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct DlpSandboxChangeCallbackRecord {
    DlpSandboxChangeCallbackRecord() : callbackObject_(nullptr) {}
    explicit DlpSandboxChangeCallbackRecord(sptr<IRemoteObject> callback) : callbackObject_(callback) {}

    sptr<IRemoteObject> callbackObject_;
    int32_t pid = 0;
};

class DlpSandboxChangeCallbackManager {
public:
    virtual ~DlpSandboxChangeCallbackManager();
    
    static DlpSandboxChangeCallbackManager &GetInstance();

    int32_t AddCallback(int32_t pid, const sptr<IRemoteObject> &callback);
    int32_t RemoveCallback(const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(int32_t pid, bool &result);
    void ExecuteCallbackAsync(const DlpSandboxInfo &dlpSandboxInfo);

private:
    DlpSandboxChangeCallbackManager();
    DISALLOW_COPY_AND_MOVE(DlpSandboxChangeCallbackManager);
    std::mutex mutex_;
    std::map<int32_t, DlpSandboxChangeCallbackRecord> callbackInfoMap_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_PERMISSION_CALLBACK_MANAGER_H
