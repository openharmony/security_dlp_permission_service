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

#include "installdlpsandbox_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const int32_t TWO = 2;
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    uint32_t offsize = 0;
    int32_t userId = *(reinterpret_cast<const int32_t *>(data + offsize));
    offsize += sizeof(int32_t);
    DLPFileAccess dlpFileAccess = *(reinterpret_cast<const DLPFileAccess *>(data + offsize));
    uint32_t length = (size - offsize) / TWO;
    std::string bundleName(reinterpret_cast<const char*>(data + offsize), length);
    std::string uri(reinterpret_cast<const char*>(data + offsize + length), length);
    SandboxInfo sandboxInfo;
    DlpPermissionKit::InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
}

bool InstallDlpSandboxFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::InstallDlpSandboxFuzzTest(data, size);
    return 0;
}
