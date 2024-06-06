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

#include "parsecert_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "cert_parcel.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const int32_t APPID_LENGTH = 30;
const int32_t TWO = 2;
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t) + sizeof(char) * APPID_LENGTH)) {
        return;
    }
    uint32_t offsize = 0;
    bool flag = *(reinterpret_cast<const int32_t *>(data + offsize)) % TWO == 0;
    offsize += sizeof(int32_t);
    std::string appId(reinterpret_cast<const char*>(data + offsize), APPID_LENGTH);
    offsize += sizeof(char) * APPID_LENGTH;
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::vector<uint8_t> cert((data + offsize), data + size);
    certParcel->cert = cert;
    PermissionPolicy policy;
    DlpPermissionKit::ParseDlpCertificate(certParcel, policy, appId, flag);
}

bool ParseCertFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    return 0;
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
