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

#ifndef OPEN_DLP_FILE_CALLBACK_MANAGER_H
#define OPEN_DLP_FILE_CALLBACK_MANAGER_H

#include <mutex>
#include <map>
#include <vector>
#include <string_view>

#include "dlp_sandbox_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct OpenDlpFileCallbackRecord {
    OpenDlpFileCallbackRecord() : callbackObject(nullptr) {}
    explicit OpenDlpFileCallbackRecord(sptr<IRemoteObject> callback) : callbackObject(callback) {}

    sptr<IRemoteObject> callbackObject;
    int32_t userId = 0;
    std::string bundleName = "";
};

class OpenDlpFileCallbackManager {
public:
    virtual ~OpenDlpFileCallbackManager();
    OpenDlpFileCallbackManager();
    static OpenDlpFileCallbackManager &GetInstance();

    int32_t AddCallback(
        int32_t pid, int32_t userId, const std::string& bundleName, const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(const sptr<IRemoteObject>& callback);
    int32_t RemoveCallback(int32_t pid, const sptr<IRemoteObject> &callback);
    void ExecuteCallbackAsync(const DlpSandboxInfo &dlpSandboxInfo);
    bool IsCallbackEmpty();

private:
    bool OnOpenDlpFile(const sptr<IRemoteObject> &subscribeRecordPtr, const DlpSandboxInfo &dlpSandboxInfo);
    std::mutex mutex_;
    std::map<int32_t, std::vector<OpenDlpFileCallbackRecord>> openDlpFileCallbackMap_;
    sptr<IRemoteObject::DeathRecipient> callbackDeathRecipient_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // OPEN_DLP_FILE_CALLBACK_MANAGER_H
