/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "generatecertstub_fuzzer.h"
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "GenerateCertFuzzTest" };
const uint32_t KEY_LEN = 16;
const uint64_t DEFAULT_TIME = 3711509424L;
const int32_t UINT8_MAX_SIZE = 256;
const int32_t FIFTY = 50;
constexpr int32_t DATA_LENGTH = KEY_LEN * 4;
const uint8_t ARRAY_CHAR_SIZE = 62;
const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static int GetRandNum()
{
    unsigned int rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

static void GenerateRandStr(uint32_t len, const uint8_t *data, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = data[i] % ARRAY_CHAR_SIZE;
        res.push_back(CHAR_ARRAY[index]);
    }
}

static void InitPolicy(const uint8_t* data, size_t size, PermissionPolicy &encPolicy)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string acount;
    GenerateRandStr(KEY_LEN, data, acount);
    encPolicy.ownerAccount_ = acount;
    encPolicy.ownerAccountId_ = acount;
    encPolicy.ownerAccountType_ = DlpAccountType::DOMAIN_ACCOUNT;
    encPolicy.expireTime_ = DEFAULT_TIME;
    uint8_t* aeskey = const_cast<uint8_t*>(data + KEY_LEN);
    uint8_t* iv = const_cast<uint8_t*>(data + KEY_LEN + KEY_LEN);
    uint8_t* mac = const_cast<uint8_t*>(data + KEY_LEN + KEY_LEN + KEY_LEN);
    encPolicy.SetAeskey(aeskey, KEY_LEN);
    encPolicy.SetIv(iv, KEY_LEN);
    encPolicy.SetHmacKey(mac, KEY_LEN);
    int userNum = GetRandNum() % FIFTY;
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = acount;
        perminfo.authPerm = static_cast<DLPFileAccess>(1 + GetRandNum() % 3); // perm type 1 to 3
        perminfo.permExpiryTime = curTime + GetRandNum() % 200;              // time range 0 to 200
        perminfo.authAccountType = DlpAccountType::DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t) * DATA_LENGTH)) {
        return;
    }
    PermissionPolicy encPolicy;
    InitPolicy(data, size, encPolicy);
    DlpPolicyParcel parcel;
    parcel.policyParams_.CopyPermissionPolicy(encPolicy);
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionStub::GetDescriptor())) {
        return;
    }
    if (!datas.WriteParcelable(&parcel)) {
        return;
    }
    std::shared_ptr<GenerateDlpCertificateCallback> callback = std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (!datas.WriteRemoteObject(asyncStub->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GENERATE_DLP_CERTIFICATE);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
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
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
