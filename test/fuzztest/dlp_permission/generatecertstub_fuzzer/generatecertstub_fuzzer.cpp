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
const std::string DEFAULT_NAME = "testName";
const int32_t UINT8_MAX_SIZE = 256;
const int32_t FIFTY = 50;
static int GetRandNum()
{
    unsigned int rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

static void FreeUint8Buffer(uint8_t** buff, const uint32_t& buffLen)
{
    if (*buff != nullptr) {
        memset_s(*buff, buffLen, 0, buffLen);
        delete[] *buff;
        *buff = nullptr;
    }
}

static void InitPolicy(PermissionPolicy &encPolicy)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    encPolicy.ownerAccount_ = DEFAULT_NAME;
    encPolicy.ownerAccountId_ = DEFAULT_NAME;
    encPolicy.ownerAccountType_ = DlpAccountType::DOMAIN_ACCOUNT;
    encPolicy.expireTime_ = DEFAULT_TIME;
    uint8_t* aeskey = new (std::nothrow) uint8_t[KEY_LEN];
    if (aeskey == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for aes key fail.");
        return;
    }
    uint8_t* iv = new (std::nothrow) uint8_t[KEY_LEN];
    if (iv == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for iv key fail.");
        FreeUint8Buffer(&aeskey, KEY_LEN);
        return;
    }
    uint8_t* mac = new (std::nothrow) uint8_t[KEY_LEN];
    if (mac == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for iv key fail.");
        FreeUint8Buffer(&aeskey, KEY_LEN);
        FreeUint8Buffer(&iv, KEY_LEN);
        return;
    }
    for (int i = 0; i < KEY_LEN; i++) {
        aeskey[i] = GetRandNum() % UINT8_MAX_SIZE;
        iv[i] = GetRandNum() % UINT8_MAX_SIZE;
        mac[i] = GetRandNum() % UINT8_MAX_SIZE;
    }
    encPolicy.SetAeskey(aeskey, KEY_LEN);
    encPolicy.SetIv(iv, KEY_LEN);
    encPolicy.SetHmacKey(mac, KEY_LEN);
    int userNum = GetRandNum() % FIFTY;
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = DEFAULT_NAME;
        perminfo.authPerm = static_cast<DLPFileAccess>(1 + GetRandNum() % 3); // perm type 1 to 3
        perminfo.permExpiryTime = curTime + GetRandNum() % 200;              // time range 0 to 200
        perminfo.authAccountType = DlpAccountType::DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    FreeUint8Buffer(&aeskey, KEY_LEN);
    FreeUint8Buffer(&iv, KEY_LEN);
    FreeUint8Buffer(&mac, KEY_LEN);
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    PermissionPolicy encPolicy;
    InitPolicy(encPolicy);
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
    service->OnRemoteRequest(code, datas, reply, option);
}

bool GenerateCertFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
