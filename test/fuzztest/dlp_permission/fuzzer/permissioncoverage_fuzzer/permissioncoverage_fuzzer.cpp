/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "permissioncoverage_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>

#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"
#include "dlp_permission_service_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "iremote_stub.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "dlp_permission_service.cpp"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
    const uint32_t BUFFER_LENGTH = 64;
}

namespace OHOS {
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string appId = fdp.ConsumeBytesAsString(size);
    AppExecFwk::ApplicationInfo applicationInfo;
    GetApplicationInfo(appId, applicationInfo);
    const AAFwk::Want want;
    CheckAllowAbilityList(want);
    ClearKvStorage();
}

bool PermissionCoverageFuzzer(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::PermissionCoverageFuzzer(data, size);
    return 0;
}
