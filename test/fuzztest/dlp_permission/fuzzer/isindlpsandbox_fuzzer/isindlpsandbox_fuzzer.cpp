/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "isindlpsandbox_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "mock_sandbox_init.h"
#include "securec.h"

constexpr uint8_t STATUS_NUM = 2;

using namespace OHOS::Security::DlpPermission;
namespace OHOS {
static pthread_once_t g_callOnce = PTHREAD_ONCE_INIT;

static void FuzzTest(const uint8_t* data, size_t size)
{
    bool inSandbox = data[0] % STATUS_NUM;
    DlpPermissionKit::IsInDlpSandbox(inSandbox);
}

bool IsInDlpSandboxFuzzTest(const uint8_t* data, size_t size)
{
    pthread_once(&g_callOnce, InitTokenId);
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::IsInDlpSandboxFuzzTest(data, size);
    return 0;
}
