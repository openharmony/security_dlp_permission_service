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

#include "setenterpriseinfosproxy_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace {
static constexpr int32_t DLP_PERMISSION_SERVICE_SA_ID = 3521;
constexpr int32_t SA_LOAD_TIME = 4 * 1000;
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
static const size_t MIN_INT32_COUNT = 3;
}

namespace OHOS {
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) * MIN_INT32_COUNT)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string uri = fdp.ConsumeBytesAsString(size / 3);
    std::string fileId = fdp.ConsumeBytesAsString(size / 3);
    DLPFileAccess dlpFileAccess = static_cast<DLPFileAccess>(fdp.ConsumeIntegral<int32_t>());
    std::string classificationLabel = fdp.ConsumeBytesAsString(size / 3);
    std::string appIdentifier = fdp.ConsumeRemainingBytesAsString();
    DlpPermissionClient::GetInstance().SetEnterpriseInfos(uri, fileId, dlpFileAccess,
        classificationLabel, appIdentifier);
}

bool SetEnterpriseInfosProxyFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SetEnterpriseInfosProxyFuzzTest(data, size);
    return 0;
}
