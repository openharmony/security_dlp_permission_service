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
#include "dlp_credential.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "securec.h"

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

    int res = DlpCredential::GetInstance().GenerateDlpCertificate(policy, account, accountType, stub);
    EXPECT_EQ(DLP_CREDENTIAL_ERROR_COMMON_ERROR, res);
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::string appId = "test_appId_passed";
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, res);
    unordered_json encDataJson = {
        {ENC_DATA_LEN, POLICY_PLAINTTEXT.length()},
        {ENC_DATA, POLICY_PLAINTTEXT},
        {ENC_ACCOUNT_TYPE, accountType},
    };
    std::string s2 = encDataJson.dump();
    std::vector<uint8_t> cert2(s2.begin(), s2.end());
    certParcel->cert = cert2;
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true);
    EXPECT_EQ(DLP_OK, res);
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
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
