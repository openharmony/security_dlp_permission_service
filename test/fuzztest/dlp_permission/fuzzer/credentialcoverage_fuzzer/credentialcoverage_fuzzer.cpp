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

#include "credentialcoverage_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"
#include "dlp_permission_service_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "iremote_stub.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "dlp_credential.cpp"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace {
const uint32_t BUFFER_LENGTH = 64;
const uint32_t TWO = 2;
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
}

namespace OHOS {

class GenerateDlpCertificateFuzzerTest : public IRemoteStub<IDlpPermissionCallback> {
public:
    GenerateDlpCertificateFuzzerTest() {}
    ~GenerateDlpCertificateFuzzerTest() override {}

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override {};
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override {};
};

static DlpAccountType GenerateDlpAccountType(int32_t data)
{
    int8_t typeNum = data % (sizeof(DlpAccountType) / sizeof(INVALID_ACCOUNT));
    if (typeNum == 0) {
        return DlpAccountType::INVALID_ACCOUNT;
    } else if (typeNum == 1) {
        return DlpAccountType::CLOUD_ACCOUNT;
    } else if (typeNum == TWO) {
        return DlpAccountType::DOMAIN_ACCOUNT;
    } else {
        return DlpAccountType::APPLICATION_ACCOUNT;
    }
}

static std::string GenerateRandAppProvisionType(int32_t data)
{
    int8_t typeNum = data % TWO;
    if (typeNum == 0) {
        return AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG;
    } else {
        return AppExecFwk::Constants::APP_PROVISION_TYPE_RELEASE;
    }
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    PermissionPolicy policyInfo;
    int errorCode = fdp.ConsumeIntegral<int>();
    DLP_RestorePolicyData outParams;
    outParams.data = nullptr;
    sptr<GenerateDlpCertificateFuzzerTest> callback = new (std::nothrow) GenerateDlpCertificateFuzzerTest();
    if (callback == nullptr) {
        return;
    }
#ifndef SUPPORT_DLP_CREDENTIAL
#define SUPPORT_DLP_CREDENTIAL
#endif
    unordered_json plainPolicyJson;
    std::vector<uint8_t> cert;
    DlpAccountType ownerAccountType = GenerateDlpAccountType(fdp.ConsumeIntegral<int32_t>());
    GetNewCert(plainPolicyJson, cert, ownerAccountType);
    plainPolicyJson[POLICY_CERT] = fdp.ConsumeBytesAsString(size);
    GetNewCert(plainPolicyJson, cert, ownerAccountType);

    DlpAccountType accountType = GenerateDlpAccountType(fdp.ConsumeIntegral<int32_t>());
    DlpRestorePolicyCallbackCheck(callback, accountType, errorCode, &outParams, policyInfo);

    unordered_json jsonObj;
    SetPermissionPolicy(&outParams, callback, policyInfo, jsonObj);

    RequestInfo requestInfo;
    requestInfo.appProvisionType = GenerateRandAppProvisionType(fdp.ConsumeIntegral<int32_t>());
    CheckDebugPermission(requestInfo, policyInfo);

    uint64_t requestId = fdp.ConsumeIntegral<uint64_t>();
    DlpRestorePolicyCallback(requestId, errorCode, &outParams);

    std::string account;
    std::string contactAccount = fdp.ConsumeBytesAsString(size);
    bool isOwner;
    GetDomainAccountName(account, contactAccount, &isOwner);

    std::vector<uint8_t> offlineCert;
    DLP_EncPolicyData encpolicy;
    std::string accountStr = fdp.ConsumeBytesAsString(size);
    encpolicy.receiverAccountInfo.accountIdLen = accountStr.length();
    encpolicy.receiverAccountInfo.accountId = reinterpret_cast<uint8_t*>(strdup(accountStr.c_str()));
    isOwner = fdp.ConsumeIntegral<int32_t>() % TWO;
    AdapterData(offlineCert, isOwner, jsonObj, encpolicy);
}

static void FuzzTestCert(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    unordered_json jsonObj;
    jsonObj["policyCert"] = "123456789";
    std::vector<uint8_t> cert;
    DlpAccountType ownerAccountType = GenerateDlpAccountType(fdp.ConsumeIntegral<int32_t>());
    GetNewCert(jsonObj, cert, ownerAccountType);
}

bool CredentialCoverageFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    FuzzTestCert(data, size);
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
    OHOS::CredentialCoverageFuzzTest(data, size);
    return 0;
}
