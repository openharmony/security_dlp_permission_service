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

#include "dlp_transparent_enc_mock.h"
#include <cstdlib>
#include <cstring>

namespace OHOS {
namespace Security {
namespace DlpPermission {

DlpTransparentEncMock &DlpTransparentEncMock::GetInstance()
{
    static DlpTransparentEncMock instance;
    return instance;
}

int32_t DlpTransparentEncMock::SetControlledAppLists(int32_t userid, const std::vector<std::string> &appLists)
{
    controlledAppLists_ = appLists;
    return mockResult_;
}

int32_t DlpTransparentEncMock::GetControlledAppLists(std::vector<std::string> &appLists)
{
    appLists = controlledAppLists_;
    return mockResult_;
}

void DlpTransparentEncMock::SetMockResult(int32_t result)
{
    mockResult_ = result;
}

extern "C" {
int32_t DLP_SetControlledAppLists(int32_t userid, const char *const *appLists, uint32_t appListsLen)
{
    if (appLists == nullptr || appListsLen == 0) {
        return -1;
    }
    std::vector<std::string> appListVec;
    for (uint32_t i = 0; i < appListsLen; i++) {
        if (appLists[i] != nullptr) {
            appListVec.push_back(std::string(appLists[i]));
        }
    }
    return DlpTransparentEncMock::GetInstance().SetControlledAppLists(userid, appListVec);
}

int32_t DLP_GetControlledAppLists(char ***appLists, uint32_t *appListsLen)
{
    if (appLists == nullptr || appListsLen == nullptr) {
        return -1;
    }

    std::vector<std::string> appListVec;
    int32_t ret = DlpTransparentEncMock::GetInstance().GetControlledAppLists(appListVec);
    if (ret != 0) {
        return ret;
    }

    if (appListVec.empty()) {
        *appLists = nullptr;
        *appListsLen = 0;
        return 0;
    }

    *appLists = (char **)malloc(sizeof(char *) * appListVec.size());
    if (*appLists == nullptr) {
        return -1;
    }
    
    for (size_t i = 0; i < appListVec.size(); i++) {
        (*appLists)[i] = strdup(appListVec[i].c_str());
        if ((*appLists)[i] == nullptr) {
            for (size_t j = 0; j < i; j++) {
                free((*appLists)[j]);
            }
            free(*appLists);
            *appLists = nullptr;
            return -1;
        }
    }
    *appListsLen = static_cast<uint32_t>(appListVec.size());

    return 0;
}

int32_t DLP_FreeControlledAppLists(char ***appLists, uint32_t *appListsLen)
{
    if (appLists == nullptr || appListsLen == nullptr || *appLists == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < *appListsLen; i++) {
        if ((*appLists)[i] != nullptr) {
            free((*appLists)[i]);
            (*appLists)[i] = nullptr;
        }
    }

    free(*appLists);
    *appLists = nullptr;
    *appListsLen = 0;

    return 0;
}
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS