/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlp_fuse_helper.h"

#include "fuse_daemon.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
std::recursive_mutex g_instanceMutex;
} // namespace

DlpLinkManager &DlpFuseHelper::GetDlpLinkManagerInstance()
{
    static DlpLinkManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new DlpLinkManager();
            FuseDaemon::InitFuseFs();
        }
    }
    return *instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS