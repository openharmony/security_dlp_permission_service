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

#ifndef TEST_UNITTEST_MOCK_EXTENSION_MANAGER_CLIENT_H
#define TEST_UNITTEST_MOCK_EXTENSION_MANAGER_CLIENT_H

#include <cstdint>
#include "want.h"

namespace OHOS {
namespace AAFwk {

class ExtensionManagerClient {
public:
    static ExtensionManagerClient &GetInstance()
    {
        static ExtensionManagerClient instance;
        return instance;
    }

    template<typename T>
    int32_t ConnectServiceExtensionAbility(const AAFwk::Want &want,
        const OHOS::sptr<T> &abilityConnection, int32_t userId)
    {
        (void)want;
        (void)abilityConnection;
        (void)userId;
        return connectResult_;
    }

    template<typename T>
    int32_t DisconnectAbility(const OHOS::sptr<T> &abilityConnection)
    {
        (void)abilityConnection;
        return disconnectResult_;
    }

    static void SetConnectResult(int32_t result)
    {
        connectResult_ = result;
    }

    static void SetDisconnectResult(int32_t result)
    {
        disconnectResult_ = result;
    }

    static void ResetMockState()
    {
        connectResult_ = 0;
        disconnectResult_ = 0;
    }

private:
    ExtensionManagerClient() = default;
    ~ExtensionManagerClient() = default;

    inline static int32_t connectResult_ = 0;
    inline static int32_t disconnectResult_ = 0;
};

} // namespace AAFwk
} // namespace OHOS

#endif