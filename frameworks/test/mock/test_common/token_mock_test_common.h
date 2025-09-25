/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TOKEN_MOCK_TEST_COMMON_H
#define TOKEN_MOCK_TEST_COMMON_H

#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};

class MockHapToken {
public:
    explicit MockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~MockHapToken();
    uint32_t GetMockToken();
private:
    uint64_t selfToken_;
    uint32_t mockToken_;
};

class DlpPermissionTestCommon {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;
    static void SetTestEvironment(uint64_t shellTokenId);
    static void ResetTestEvironment();
    static uint64_t GetShellTokenId();

    static AccessToken::AccessTokenIDEx AllocTestHapToken(const AccessToken::HapInfoParams& hapInfo,
        AccessToken::HapPolicyParams& hapPolicy);
    static int32_t DeleteTestHapToken(AccessToken::AccessTokenID tokenID);
    static AccessToken::AccessTokenID GetNativeTokenIdFromProcess(const std::string& process);
    static AccessToken::AccessTokenIDEx GetHapTokenIdFromBundle(
        int32_t userID, const std::string& bundleName, int32_t instIndex);
    static int32_t GrantPermissionByTest(AccessToken::AccessTokenID tokenID,
        const std::string& permission, uint32_t flag);
    static int32_t RevokePermissionByTest(AccessToken::AccessTokenID tokenID,
        const std::string& permission, uint32_t flag);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // TOKEN_MOCK_TEST_COMMON_H
