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
#include "permission_policy.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

static const std::string POLICY_PLAINTTEXT = "{\"policy\":{\"KIA\":\"KIA\",\"ownerAccountName\":\"accountIdA\","
                                              "\"ownerAccountId\":\"accountIdA\",\"version\":1,\"account\":{"
                                              "\"accountIdB\":{\"expireTime\":0,\"needOnline\":0,\"right\":{"
                                              "\"read\":\"true\",\"edit\":\"true\",\"fullCtrl\": \"true\"}}}},"
                                              "\"file\":{\"filekey\":\"31A02CFB2B89ABAD49F84957A69CBB5C54A5952"
                                              "7B0B46F9BCF653A6406BCDBE9\",\"filekeyLen\":32,\"iv\":"
                                              "\"3D9E014D7464C4A2414808CC842D92822998D878CDB669DBD63B990459D07E14\","
                                              "\"ivLen\":32}}";

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
    std::string s2(POLICY_PLAINTTEXT);
    std::vector<uint8_t> cert2(s2.begin(), s2.end());
    certParcel->cert = cert2;
    res = DlpCredential::GetInstance().ParseDlpCertificate(certParcel, stub, appId, true);
    EXPECT_EQ(DLP_CREDENTIAL_ERROR_COMMON_ERROR, res);
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
