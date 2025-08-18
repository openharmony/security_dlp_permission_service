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

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
} // namespace

namespace OHOS {
const int32_t KEY_LEN = 16;
constexpr int32_t DATA_LENGTH = KEY_LEN * 6;
const int32_t USER_COUNT = 3;
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
    if ((data == nullptr) || (size <= sizeof(uint32_t) * DATA_LENGTH)) {
        return;
    }
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount_ = Uint8ArrayToString(data, KEY_LEN);
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    uint32_t offset = KEY_LEN;
    encPolicy.SetAeskey(data + offset, KEY_LEN);
    offset += KEY_LEN;
    encPolicy.SetIv(data + offset, KEY_LEN);
    for (int user = 0; user < USER_COUNT; ++user) {
        AuthUserInfo perminfo;
        offset += KEY_LEN;
        perminfo.authAccount = Uint8ArrayToString(data + offset, KEY_LEN);
        const uint8_t* temp1 = reinterpret_cast<const uint8_t*>(data + offset);
        perminfo.authPerm = static_cast<DLPFileAccess>(1 + *temp1 % 3);  // perm type 1 to 3
        const uint8_t* temp2 = reinterpret_cast<const uint8_t*>(data + offset + 1);
        perminfo.permExpiryTime = curTime + *temp2 % 200;               // time range 0 to 200
        perminfo.authAccountType = DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    std::vector<uint8_t> cert;
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, cert);
}

bool GenerateCertFuzzTest(const uint8_t* data, size_t size)
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
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
