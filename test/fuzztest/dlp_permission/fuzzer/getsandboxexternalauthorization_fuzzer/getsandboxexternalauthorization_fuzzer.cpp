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

#include "getsandboxexternalauthorization_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "mock_sandbox_init.h"
#include "securec.h"

using namespace OHOS::Security::DlpPermission;
namespace OHOS {
static pthread_once_t g_callOnce = PTHREAD_ONCE_INIT;

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    uint32_t offsize = 0;
    int sandboxUid = *(reinterpret_cast<const int32_t *>(data + offsize));
    offsize += sizeof(int32_t);
    SandBoxExternalAuthorType authType = *(reinterpret_cast<const SandBoxExternalAuthorType *>(data + offsize));
    offsize += sizeof(int32_t);
    std::string bundleName(reinterpret_cast<const char*>(data + offsize), size - offsize);
    AAFwk::Want want;
    want.SetBundle(bundleName);
    DlpPermissionKit::GetSandboxExternalAuthorization(sandboxUid, want, authType);
}

bool GetSandboxExternalAuthorizationFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::GetSandboxExternalAuthorizationFuzzTest(data, size);
    return 0;
}
