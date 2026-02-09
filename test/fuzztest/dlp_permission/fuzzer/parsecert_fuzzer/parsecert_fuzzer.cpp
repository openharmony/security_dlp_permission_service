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
#include <fuzzer/FuzzedDataProvider.h>
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
#define LABEL LABEL_POLICY
#include "cert_parcel.cpp"
#undef LABEL
#define LABEL LABEL_CERT
#include "permission_policy.cpp"
#undef LABEL

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
} // namespace

namespace OHOS {
const int32_t APPID_LENGTH = 30;
const int32_t TWO = 2;
const uint32_t STRING_LENGTH = 10;

static void CallCertParcel1(FuzzedDataProvider& fdp)
{
    CertParcel* parcel = new (std::nothrow) CertParcel();
    Parcel data;
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel == nullptr) {
        parcel = new (std::nothrow) CertParcel();
    }

    data.WriteInt32(fdp.ConsumeIntegral<int>());
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel == nullptr) {
        parcel = new (std::nothrow) CertParcel();
    }

    data.WriteInt32(fdp.ConsumeIntegral<int>());
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel == nullptr) {
        parcel = new (std::nothrow) CertParcel();
    }

    data.WriteInt32(fdp.ConsumeIntegral<int>());
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel == nullptr) {
        parcel = new (std::nothrow) CertParcel();
    }

    data.WriteInt32(fdp.ConsumeIntegral<int>());
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel == nullptr) {
        parcel = new (std::nothrow) CertParcel();
    }

    data.WriteInt32(fdp.ConsumeIntegral<int>());
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data.WriteInt32(fdp.ConsumeIntegral<int>());
    parcel = UnmarshallingProperty(data, parcel);
    if (parcel != nullptr) {
        delete parcel;
    }
}

static void CallCertParcel2(FuzzedDataProvider& fdp)
{
    CertParcel* parcel = new (std::nothrow) CertParcel();
    Parcel data1;
    (void)parcel->Unmarshalling(data1);

    data1.WriteBool(fdp.ConsumeBool());
    (void)parcel->Unmarshalling(data1);

    data1.WriteBool(fdp.ConsumeBool());
    data1.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    (void)parcel->Unmarshalling(data1);

    data1.WriteBool(fdp.ConsumeBool());
    data1.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data1.WriteUInt8Vector(std::vector<uint8_t>{0, 1, 2});
    (void)parcel->Unmarshalling(data1);

    data1.WriteBool(fdp.ConsumeBool());
    data1.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data1.WriteUInt8Vector(std::vector<uint8_t>{0, 1, 2});
    data1.WriteUInt8Vector(std::vector<uint8_t>{0, 1, 2});
    (void)parcel->Unmarshalling(data1);

    data1.WriteBool(fdp.ConsumeBool());
    data1.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    data1.WriteUInt8Vector(std::vector<uint8_t>{0, 1, 2});
    data1.WriteUInt8Vector(std::vector<uint8_t>{0, 1, 2});
    data1.WriteBool(fdp.ConsumeBool());
    (void)parcel->Unmarshalling(data1);
    if (parcel != nullptr) {
        delete parcel;
    }
}

static void CallPermissionPolicy1(FuzzedDataProvider& fdp)
{
    uint8_t buff = 0;
    (void)CheckAesParam(&buff, 0);

    std::vector<AuthUserInfo> authUsers;
    for (uint32_t i = 0; i < MAX_ACCOUNT_NUM; i++) {
        AuthUserInfo authUser;
        authUsers.push_back(authUser);
    }
    (void)CheckAuthUserInfoList(authUsers);

    uint32_t buffLen;
    FreeUint8Buffer(nullptr, buffLen);

    PermissionPolicy permissionPolicy;
    (void)permissionPolicy.IsValid();

    uint32_t keyLen;
    SetKey(nullptr, 0, nullptr, keyLen);
    uint8_t originalKey;
    uint8_t* key;
    SetKey(nullptr, 0, nullptr, keyLen);
    SetKey(nullptr, 0, &key, keyLen);
    SetKey(&originalKey, 0, &key, keyLen);

    PermissionPolicy srcPolicy;
    permissionPolicy.CopyPolicyHmac(srcPolicy);
    permissionPolicy.CopyPermissionPolicy(srcPolicy);

    permissionPolicy.expireTime_ = fdp.ConsumeIntegral<uint64_t>();
    (void)permissionPolicy.CheckActionUponExpiry();

    DlpAccountType accountType = static_cast<DlpAccountType>(fdp.ConsumeIntegral<uint32_t>() + STRING_LENGTH);
    CheckAccountType(accountType);
}

static void CallPermissionPolicy2(FuzzedDataProvider& fdp)
{
    SandboxInfo sandboxInfo;
    Parcel out;
    sandboxInfo.Marshalling(out);
    sandboxInfo.Unmarshalling(out);
    out.WriteInt32(0);
    sandboxInfo.Unmarshalling(out);
    out.WriteInt32(0);
    out.WriteInt32(0);
    sandboxInfo.Unmarshalling(out);

    FileInfo fileInfo;
    Parcel in;
    fileInfo.Unmarshalling(in);
    in.WriteBool(fdp.ConsumeBool());
    fileInfo.Unmarshalling(in);
    in.WriteBool(fdp.ConsumeBool());
    in.WriteBool(fdp.ConsumeBool());
    fileInfo.Unmarshalling(in);
    in.WriteBool(fdp.ConsumeBool());
    in.WriteBool(fdp.ConsumeBool());
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    fileInfo.Unmarshalling(in);
    in.WriteBool(fdp.ConsumeBool());
    in.WriteBool(fdp.ConsumeBool());
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    fileInfo.Unmarshalling(in);
    in.WriteBool(fdp.ConsumeBool());
    in.WriteBool(fdp.ConsumeBool());
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    in.WriteString(fdp.ConsumeBytesAsString(STRING_LENGTH));
    fileInfo.Unmarshalling(in);
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t) + sizeof(char) * APPID_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    CallCertParcel1(fdp);
    CallPermissionPolicy1(fdp);
    CallCertParcel2(fdp);
    CallPermissionPolicy2(fdp);
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
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
