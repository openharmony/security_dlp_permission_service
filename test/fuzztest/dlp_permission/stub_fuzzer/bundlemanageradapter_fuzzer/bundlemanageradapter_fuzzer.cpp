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

#include "bundlemanageradapter_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include "account_adapt.h"
#include "cert_parcel.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_async_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_parcel.h"
#include "dlp_credential.h"
#include "dlp_credential.cpp"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "accesstoken_kit.h"
#include "idlp_permission_service.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using unordered_json = nlohmann::ordered_json;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
static const int32_t DATA_MIN_LEN = 8;
} // namespace

namespace OHOS {
    const std::string ENC_DATA_LEN = "encDataLen";
    const std::string ENC_DATA = "encData";
    const std::string ENC_ACCOUNT_TYPE = "accountType";
    static const uint8_t TWO = 2;
    static const uint8_t FOUR = 4;
    static const uint8_t EIGHT = 8;
    static const uint8_t BUFFER_LENGTH = 32;
    static const uint8_t CONST_SIZE = 100;
    static const std::string POLICY_PLAINTTEXT =
    "7b22706f6c696379223a7b224b4941223a22222c226f776e65724163636f756e744e616d65223a226f686f73416e6f6e796d6f75734e616d6"
    "5222c226f776e65724163636f756e744964223a226f686f73416e6f6e796d6f75734e616d65222c2276657273696f6e223a312c2265787069"
    "726554696d65223a302c226e6565644f6e6c696e65223a312c226163636f756e74223a7b22716c7479733332636e35574d4b493534223a7b2"
    "27269676874223a7b2272656164223a747275652c2265646974223a66616c73652c2266756c6c4374726c223a66616c73657d7d2c22377236"
    "4c4f4b3548396c444758577078223a7b227269676874223a7b2272656164223a747275652c2265646974223a66616c73652c2266756c6c437"
    "4726c223a66616c73657d7d7d7d2c2266696c65223a7b2266696c656b6579223a224532433037304238373531444435334142363930453337"
    "3938464134364142314138314135393145414132354439333141303032323938363431384230343034222c2266696c656b65794c656e223a3"
    "3322c226976223a224245303230323430393136434436394538333842463631383038333238333346222c2269764c656e223a31362c22686d"
    "61634b6579223a223146393533374535343432444339374546394442344634413133374543304239343539463445314545303846364644344"
    "4304245414141444336424539414644222c22686d61634b65794c656e223a33322c22646c7056657273696f6e223a337d7d";

static void CheckHapPermissionFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    BundleManagerAdapter::GetInstance().CheckHapPermission(fdp.ConsumeBytesAsString(size / TWO),
        fdp.ConsumeBytesAsString(size / TWO));
}

static void GetBundleInfoFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }
    AppExecFwk::BundleInfo bundleInfo;

    FuzzedDataProvider fdp(data, size);
    BundleManagerAdapter::GetInstance().GetBundleInfo(fdp.ConsumeBytesAsString(size - EIGHT),
        fdp.ConsumeIntegral<int32_t>(), bundleInfo, fdp.ConsumeIntegral<int32_t>());
}

static void GetApplicationInfoFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }
    AppExecFwk::ApplicationInfo applicationInfo;

    FuzzedDataProvider fdp(data, size);
    BundleManagerAdapter::GetInstance().GetApplicationInfo(fdp.ConsumeBytesAsString(size - EIGHT),
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), applicationInfo);
}

static void GetBundleInfoV9FUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }
    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::BundleFlag flag = AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES;

    FuzzedDataProvider fdp(data, size);
    BundleManagerAdapter::GetInstance().GetBundleInfoV9(fdp.ConsumeBytesAsString(size - FOUR),
        flag, bundleInfo, fdp.ConsumeIntegral<int32_t>());
}

class DlpPermissionAsyncStubTests : public IRemoteStub<IDlpPermissionCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DlpPermissionAsyncStubTests);
    DlpPermissionAsyncStubTests() = default;
    ~DlpPermissionAsyncStubTests() override = default;

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override {};
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override {};
    void OnGetDlpWaterMark(int32_t result, const GeneralInfo& info) override {};
};

static void ParseDlpCertificateFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    sptr<IDlpPermissionCallback> stub = new (std::nothrow) DlpPermissionAsyncStubTests();
    std::string policy;
    std::string account;
    DlpAccountType accountType = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    AppExecFwk::ApplicationInfo applicationInfo;
    int res = DlpCredential::GetInstance().GenerateDlpCertificate(policy, account, accountType, stub);

    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::string appId = "test_appId_passed";
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true, applicationInfo);

    unordered_json encDataJson = {
        {ENC_DATA_LEN, POLICY_PLAINTTEXT.length()},
        {ENC_DATA, POLICY_PLAINTTEXT},
        {ENC_ACCOUNT_TYPE, accountType},
    };
    std::string s2 = encDataJson.dump();
    std::vector<uint8_t> cert2(s2.begin(), s2.end());
    certParcel->cert = cert2;
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true, applicationInfo);
}

static void CheckMdmPermissionFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> appList;
    appList.push_back(fdp.ConsumeBytesAsString(size / TWO - TWO));
    DlpCredential::GetInstance().CheckMdmPermission(fdp.ConsumeBytesAsString(size / TWO - TWO),
        fdp.ConsumeIntegral<int32_t>());
    DlpCredential::GetInstance().RemoveMDMPolicy();
    DlpCredential::GetInstance().SetMDMPolicy(appList);
    DlpCredential::GetInstance().GetMDMPolicy(appList);
    OHOS::Security::DlpPermission::RemovePresetDLPPolicy(appList);
    OHOS::Security::DlpPermission::PresetDLPPolicy(appList, appList);
}

static void ParseFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> appList;
    appList.push_back(fdp.ConsumeBytesAsString(size));

    uint32_t policy  = 0;
    uint32_t policyLen = 1;

    OHOS::Security::DlpPermission::ParseUint8TypedArrayToStringVector(reinterpret_cast<uint8_t *>(&policy),
        (&policyLen), appList);

    uint8_t *policy1 = new (std::nothrow) uint8_t[CONST_SIZE];
    OHOS::Security::DlpPermission::ParseStringVectorToUint8TypedArray(appList, policy1, CONST_SIZE);
    delete [] policy1;
}

static void IsError(const uint8_t* data, size_t size)
{
    if (data == nullptr || (size < BUFFER_LENGTH)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t errorCode = fdp.ConsumeIntegral<int32_t>();
    IsDlpCredentialHuksError(errorCode);
    IsEnterpriseError(errorCode);
    IsDlpCredentialIpcError(errorCode);
    IsDlpCredentialServerError(errorCode);
    IsNoPermissionError(errorCode);
    IsNoInternetError(errorCode);
    ConvertCredentialError(errorCode);
}

static void GetCallbackMap(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < DATA_MIN_LEN) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint64_t requestId = fdp.ConsumeIntegral<uint64_t>();
    int32_t errorCode = fdp.ConsumeIntegral<int32_t>();
    RequestInfo info;
    DLP_EncPolicyData outParams;
    DLP_PackPolicyParams packPolicy;
    DLP_RestorePolicyData outParamsRes;
    GetCallbackFromRequestMap(requestId, info);
    InsertCallbackToRequestMap(requestId, info);
    GetCallbackFromRequestMap(requestId, info);
    DlpPackPolicyCallback(requestId, errorCode, &outParams);
    unordered_json plainPolicyJson;
    std::vector<uint8_t> cert;
    DlpAccountType ownerAccountType = DlpAccountType::CLOUD_ACCOUNT;
    GetNewCert(plainPolicyJson, cert, ownerAccountType);
    FreeBuffer(nullptr, 0);
    RequestInfo requestInfo;
    PermissionPolicy policyInfo;
    CheckDebugPermission(requestInfo, policyInfo);
    DlpRestorePolicyCallback(requestId, errorCode, &outParamsRes);
    FreeDlpPackPolicyParams(packPolicy);
    std::string account;
    std::string contactAccount;
    bool isOwner;
    GetLocalAccountName(account, contactAccount, &isOwner);
    GetDomainAccountName(account, contactAccount, &isOwner);
    AccountInfo accountCfg;
    std::string appId = "appId";
    GetEnterpriseAccountName(accountCfg, appId, &isOwner);
}

bool BundleManagerAdapterFuzzTest(const uint8_t* data, size_t size)
{
    CheckHapPermissionFUZZ(data, size);
    GetBundleInfoFUZZ(data, size);
    GetApplicationInfoFUZZ(data, size);
    GetBundleInfoV9FUZZ(data, size);
    ParseDlpCertificateFUZZ(data, size);
    CheckMdmPermissionFUZZ(data, size);
    ParseFUZZ(data, size);
    IsError(data, size);
    GetCallbackMap(data, size);
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
    OHOS::BundleManagerAdapterFuzzTest(data, size);
    return 0;
}
