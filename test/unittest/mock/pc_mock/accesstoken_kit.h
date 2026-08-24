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

#ifndef ACCESSTOKEN_KIT_H
#define ACCESSTOKEN_KIT_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace TestMock {
int GetMockVerifyAccessTokenResultForPerm(const std::string &permission);
uint32_t GetMockNativeTokenId();
}  // namespace TestMock
}  // namespace DlpPermission

namespace AccessToken {

using AccessTokenID = uint32_t;

enum PermissionState : int32_t {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
};

class AccessTokenKit {
public:
    static int VerifyAccessToken(AccessTokenID tokenID, const std::string &permission)
    {
        return DlpPermission::TestMock::GetMockVerifyAccessTokenResultForPerm(permission);
    }
    static AccessTokenID GetNativeTokenId(const std::string &processName)
    {
        return DlpPermission::TestMock::GetMockNativeTokenId();
    }
};

}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // ACCESSTOKEN_KIT_H
