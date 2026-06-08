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

#ifndef DLP_TRANSPARENT_ENC_MANAGER_H
#define DLP_TRANSPARENT_ENC_MANAGER_H

#include <string>
#include <vector>
#include <mutex>

#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class DlpTransparentEncManager {
public:
    static DlpTransparentEncManager &GetInstance();
    int32_t SetControlledAppLists(const std::vector<std::string> &appLists, int32_t userId, bool userIdSet);
    int32_t GetControlledAppLists(std::vector<std::string> &appLists);

private:
    DlpTransparentEncManager() = default;
    ~DlpTransparentEncManager();
    DISALLOW_COPY_AND_MOVE(DlpTransparentEncManager);
    int32_t LoadDlpCredentialService();
    void *credentialServiceHandle_ = nullptr;

    typedef int32_t (*SetControlledAppLists_Func)(int32_t userid, bool userIdSet, const char *const *appLists,
                                                  uint32_t appListsLen);
    typedef int32_t (*GetControlledAppLists_Func)(char ***appLists, uint32_t *appListsLen);
    typedef int32_t (*FreeControlledAppLists_Func)(char ***appLists, uint32_t *appListsLen);
    SetControlledAppLists_Func setControlledAppListsFunc_ = nullptr;
    GetControlledAppLists_Func getControlledAppListsFunc_ = nullptr;
    FreeControlledAppLists_Func freeControlledAppListsFunc_ = nullptr;
    std::mutex mutex_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif /*  DLP_TRANSPARENT_ENC_MANAGER_H */