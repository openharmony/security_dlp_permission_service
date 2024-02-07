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

#include "generatecert_fuzzer.h"
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static std::string Uint8ArrayToString(const uint8_t* buff, size_t size)
{
    std::string str = "";
    for (size_t i = 0; i < size; i++) {
        str += (33 + buff[i] % (126 - 33));  // Visible Character Range 33 - 126
    }
    return str;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount_ = Uint8ArrayToString(data, size);
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    encPolicy.SetAeskey(data, size);
    encPolicy.SetIv(data, size);
    const uint8_t* userNum = reinterpret_cast<const uint8_t*>(data);
    for (int user = 0; user < *userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = Uint8ArrayToString(data, size);
        const uint8_t* temp1 = reinterpret_cast<const uint8_t*>(data);
        perminfo.authPerm = static_cast<DLPFileAccess>(1 + *temp1 % 3);  // perm type 1 to 3
        const uint8_t* temp2 = reinterpret_cast<const uint8_t*>(data);
        perminfo.permExpiryTime = curTime + *temp2 % 200;               // time range 0 to 200
        perminfo.authAccountType = DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    std::vector<uint8_t> cert;
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, cert);
}

bool GenerateCertFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0);  // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
