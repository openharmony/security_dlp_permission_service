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


#include "dlp_credential_test.h"
#include <string>
#include <thread>
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
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "securec.h"

#include "dlp_credential.cpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using unordered_json = nlohmann::ordered_json;
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string ENC_ACCOUNT_TYPE = "accountType";
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
const uint32_t ERROR_CODE_NUM = 12;
constexpr size_t MAX_MALLOC_SIZE = 1024 * 1024 * 1024; // bigger may over rss litmit
const uint32_t MALLOC_SIZE = 10;
const uint8_t MALLOC_VAL = 0;
const int32_t DLP_CREDENTIAL_SERVER_ERROR_TEST = 0x00004000;

static void *HcMalloc(uint32_t size, char val)
{
    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return nullptr;
    }
    void *addr = malloc(size);
    if (addr != nullptr) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

static void HcFree(void *addr)
{
    if (addr != nullptr) {
        free(addr);
    }
}

void DlpCredentialTest::SetUpTestCase() {}

void DlpCredentialTest::TearDownTestCase() {}

void DlpCredentialTest::SetUp() {}

void DlpCredentialTest::TearDown() {}

class DlpTestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.test");
    DlpTestRemoteObj() = default;
    virtual ~DlpTestRemoteObj() noexcept = default;
};

/**
 * @tc.name: DlpCredentialTest001
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest001, TestSize.Level1)
{
    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    auto proxy = std::make_shared<DlpPermissionAsyncProxy>(callback->AsObject());

    std::vector<uint8_t> cert;
    proxy->OnGenerateDlpCertificate(0, cert);
    EXPECT_EQ(true, (cert.size() == 0));
    proxy->OnGenerateDlpCertificate(-1, cert);
    EXPECT_EQ(true, (cert.size() == 0));

    PermissionPolicy policy;
    proxy->OnParseDlpCertificate(0, policy, cert);
    EXPECT_EQ(true, (cert.size() == 0));
    proxy->OnParseDlpCertificate(-1, policy, cert);
    EXPECT_EQ(true, (cert.size() == 0));
}

class DlpPermissionAsyncStubTest : public IRemoteStub<IDlpPermissionCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DlpPermissionAsyncStubTest);
    DlpPermissionAsyncStubTest() = default;
    ~DlpPermissionAsyncStubTest() override = default;

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override {};
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override {};
    void OnGetDlpWaterMark(int32_t result, const GeneralInfo& info) override {};
};

/**
 * @tc.name: DlpCredentialTest001
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest002, TestSize.Level1)
{
    sptr<IDlpPermissionCallback> stub = new (std::nothrow) DlpPermissionAsyncStubTest();
    std::string policy;
    std::string account;
    DlpAccountType accountType = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    AppExecFwk::ApplicationInfo applicationInfo;
    int res = DlpCredential::GetInstance().GenerateDlpCertificate(policy, account, accountType, stub);
    EXPECT_EQ(DLP_CREDENTIAL_ERROR_COMMON_ERROR, res);
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::string appId = "test_appId_passed";
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true, applicationInfo);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, res);
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

/**
 * @tc.name: DlpCredentialTest003
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest003, TestSize.Level1)
{
    sptr<IDlpPermissionCallback> stub = new (std::nothrow) DlpPermissionAsyncStubTest();
    std::string policy;
    std::string account;
    DlpAccountType accountType = OHOS::Security::DlpPermission::DOMAIN_ACCOUNT;
    AppExecFwk::ApplicationInfo applicationInfo;
    int res = DlpCredential::GetInstance().GenerateDlpCertificate(policy, account, accountType, stub);
    EXPECT_EQ(DLP_CREDENTIAL_ERROR_COMMON_ERROR, res);
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::string appId = "test_appId_passed";
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true, applicationInfo);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, res);
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

/**
 * @tc.name: SetMDMPolicy001
 * @tc.desc: SetMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, SetMDMPolicy001, TestSize.Level1)
{
    std::vector<std::string> appIdList1 = {};
    std::vector<std::string> appIdList2 = {"wechat", "taobao", "dlp_manager"};

    int32_t ret = DlpCredential::GetInstance().SetMDMPolicy(appIdList1);
    if (ret == DLP_SERVICE_ERROR_VALUE_INVALID) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    } else {
        ASSERT_EQ(DLP_OK, ret);
    }

    ret = DlpCredential::GetInstance().SetMDMPolicy(appIdList2);
    if (ret == DLP_SERVICE_ERROR_VALUE_INVALID) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    } else {
        ASSERT_EQ(DLP_OK, ret);
    }
}

/**
 * @tc.name: GetMDMPolicy001
 * @tc.desc: GetMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, GetMDMPolicy001, TestSize.Level1)
{
    std::vector<std::string> appIdList1 = {};
    std::vector<std::string> appIdList2 = {"wechat", "taobao", "dlp_manager"};

    int32_t ret = DlpCredential::GetInstance().GetMDMPolicy(appIdList1);
    ASSERT_EQ(DLP_OK, ret);

    ret = DlpCredential::GetInstance().GetMDMPolicy(appIdList2);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: RemoveMDMPolicy001
 * @tc.desc: RemoveMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, RemoveMDMPolicy001, TestSize.Level1)
{
    std::vector<std::string> appIdList1 = {"wechat", "taobao", "dlp_manager"};
    int32_t ret = DlpCredential::GetInstance().SetMDMPolicy(appIdList1);
    if (ret == DLP_SERVICE_ERROR_VALUE_INVALID) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    } else {
        ASSERT_EQ(DLP_OK, ret);
    }
    ret = DlpCredential::GetInstance().RemoveMDMPolicy();
    if (ret == DLP_SERVICE_ERROR_VALUE_INVALID) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    } else {
        ASSERT_EQ(DLP_OK, ret);
    }
}

/**
 * @tc.name: CheckMdmPermission001
 * @tc.desc: CheckMdmPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, CheckMdmPermission001, TestSize.Level1)
{
    int32_t ret = DlpCredential::GetInstance().CheckMdmPermission("testBundle", 101);
    ASSERT_EQ(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: SetEnterprisePolicy001
 * @tc.desc: SetEnterprisePolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, SetEnterprisePolicy001, TestSize.Level1)
{
    std::string policy = "policy";
    int32_t ret = DlpCredential::GetInstance().SetEnterprisePolicy(policy);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DlpCredentialTest004
 * @tc.desc: ConvertCredentialError test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest004, TestSize.Level1)
{
    int32_t errorCode[ERROR_CODE_NUM] = { DLP_SUCCESS, DLP_ERR_ENTERPRISE_MIN, DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED, 
        DLP_ERR_APPID_NOT_AUTHORIZED, DLP_ERR_CALLBACK_TIME_OUT, DLP_ERR_ACCOUNT_NOT_LOG_IN,
        DLP_ERR_CONNECTION_ALLOWED_OPEN_COUNT_INVALID, DLP_ERR_CONNECTION_TIME_OUT,
        DLP_ERR_CONNECTION_VIP_RIGHT_EXPIRED, DLP_ERR_GENERATE_KEY_FAILED, DLP_ERR_IPC_INTERNAL_FAILED,
        DLP_CREDENTIAL_SERVER_ERROR_TEST};

    int32_t retCode[ERROR_CODE_NUM] = { DLP_OK, DLP_ERR_ENTERPRISE_MIN, DLP_CREDENTIAL_ERROR_TIME_EXPIRED,
        DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED, DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR,
        DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR, DLP_CREDENTIAL_ERROR_ALLOWED_OPEN_COUNT_INVALID,
        DLP_CREDENTIAL_ERROR_NO_INTERNET, DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR, DLP_CREDENTIAL_ERROR_HUKS_ERROR,
        DLP_CREDENTIAL_ERROR_IPC_ERROR, DLP_CREDENTIAL_ERROR_SERVER_ERROR};

    for (uint32_t i = 0; i < ERROR_CODE_NUM; i++) {
        EXPECT_EQ(retCode[i], ConvertCredentialError(errorCode[i]));
    }
}

/**
 * @tc.name: DlpCredentialTest005
 * @tc.desc: CallbackRequestMap test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest005, TestSize.Level1)
{
    uint64_t requestId = MAX_REQUEST_NUM;
    uint64_t invalidRequestId = 114514;
    RequestInfo info;
    sptr<IDlpPermissionCallback> stub = new (std::nothrow) DlpPermissionAsyncStubTest();
    info.callback = stub;

    EXPECT_EQ(false, GetCallbackFromRequestMap(invalidRequestId, info));
    DlpPackPolicyCallback(invalidRequestId, DLP_CREDENTIAL_ERROR_COMMON_ERROR, nullptr);
    EXPECT_EQ(DLP_OK, InsertCallbackToRequestMap(requestId, info));
    EXPECT_EQ(DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE, InsertCallbackToRequestMap(requestId, info));
    for (uint64_t i = 0; i < MAX_REQUEST_NUM; i++) {
        EXPECT_EQ(DLP_OK, InsertCallbackToRequestMap(i, info));
    }
    EXPECT_EQ(DLP_SERVICE_ERROR_CREDENTIAL_BUSY, QueryRequestIdle());

    DlpPackPolicyCallback(requestId--, DLP_OK, nullptr);
    DLP_EncPolicyData params;
    DlpPackPolicyCallback(requestId--, DLP_OK, &params);
    params.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    DlpPackPolicyCallback(requestId--, DLP_OK, &params);
    params.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    DlpPackPolicyCallback(requestId--, DLP_OK, &params);
    HcFree(params.data);
    HcFree(params.featureName);

    DlpAccountType accountType = INVALID_ACCOUNT;
    PermissionPolicy policyInfo;
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        DlpRestorePolicyCallbackCheck(nullptr, accountType, DLP_OK, nullptr, policyInfo));
    delete info.callback;
    info.callback = nullptr;
    g_requestMap.clear();
}

/**
 * @tc.name: DlpCredentialTest006
 * @tc.desc: FreeBuffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest006, TestSize.Level1)
{
    uint32_t buffLen = MALLOC_SIZE;
    char *buff = nullptr;
    FreeBuffer(nullptr, buffLen);
    FreeBuffer(&buff, buffLen);

    buff = (char *)HcMalloc(buffLen, MALLOC_VAL);
    FreeBuffer(&buff, buffLen);
    EXPECT_EQ(nullptr, buff);
}

/**
 * @tc.name: DlpCredentialTest007
 * @tc.desc: FreeDlpPackPolicyParams test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest007, TestSize.Level1)
{
    DLP_PackPolicyParams packPolicy;
    FreeDlpPackPolicyParams(packPolicy);

    packPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDlpPackPolicyParams(packPolicy);
    EXPECT_EQ(nullptr, packPolicy.featureName);

    packPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    packPolicy.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDlpPackPolicyParams(packPolicy);
    EXPECT_EQ(nullptr, packPolicy.featureName);
    EXPECT_EQ(nullptr, packPolicy.data);

    packPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    packPolicy.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    packPolicy.senderAccountInfo.accountId = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDlpPackPolicyParams(packPolicy);
    EXPECT_EQ(nullptr, packPolicy.featureName);
    EXPECT_EQ(nullptr, packPolicy.data);
    EXPECT_EQ(nullptr, packPolicy.senderAccountInfo.accountId);
}

/**
 * @tc.name: DlpCredentialTest008
 * @tc.desc: GetEnterpriseAccountName test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest008, TestSize.Level1)
{
    AccountInfo info;
    std::string appId = "appId";
    bool isOwner = false;
    EXPECT_EQ(DLP_OK, GetEnterpriseAccountName(info, appId, &isOwner));
    HcFree(info.accountId);
}

/**
 * @tc.name: DlpCredentialTest009
 * @tc.desc: RemovePresetDLPPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest009, TestSize.Level1)
{
    std::vector<std::string> appIdList;
    EXPECT_EQ(DLP_OK, RemovePresetDLPPolicy(appIdList));
    std::string appId = "appId";
    appIdList.push_back(appId);
    EXPECT_EQ(DLP_OK, RemovePresetDLPPolicy(appIdList));
}

/**
 * @tc.name: DlpCredentialTest010
 * @tc.desc: FreeDLPEncPolicyData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialTest, DlpCredentialTest010, TestSize.Level1)
{
    DLP_EncPolicyData encPolicy;
    FreeDLPEncPolicyData(encPolicy);

    encPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDLPEncPolicyData(encPolicy);
    EXPECT_EQ(nullptr, encPolicy.featureName);

    encPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDLPEncPolicyData(encPolicy);
    EXPECT_EQ(nullptr, encPolicy.featureName);
    EXPECT_EQ(nullptr, encPolicy.data);

    encPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.options.extraInfo = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDLPEncPolicyData(encPolicy);
    EXPECT_EQ(nullptr, encPolicy.featureName);
    EXPECT_EQ(nullptr, encPolicy.data);
    EXPECT_EQ(nullptr, encPolicy.options.extraInfo);

    encPolicy.featureName = (char *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.data = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.options.extraInfo = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    encPolicy.receiverAccountInfo.accountId = (uint8_t *)HcMalloc(MALLOC_SIZE, MALLOC_VAL);
    FreeDLPEncPolicyData(encPolicy);
    EXPECT_EQ(nullptr, encPolicy.featureName);
    EXPECT_EQ(nullptr, encPolicy.data);
    EXPECT_EQ(nullptr, encPolicy.options.extraInfo);
    EXPECT_EQ(nullptr, encPolicy.receiverAccountInfo.accountId);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
